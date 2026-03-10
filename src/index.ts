
import { sendEmail } from './smtp';
import { generateIdenticon } from './identicon';
import { uploadImage, deleteImage, listAllKeys, getPublicUrl, getKeyFromUrl, S3Env } from './s3';
import * as OTPAuth from 'otpauth';
import { Security, UserPayload } from './security';

interface DBUser {
    id: number;
    email: string;
    username: string;
    password: string;
    verified: number;
    role?: string;
    avatar_url?: string;
    totp_secret?: string;
    totp_enabled?: number;
    email_notifications?: number;
    reset_token?: string;
    reset_token_expires?: number;
    pending_email?: string;
    verification_token?: string;
    email_change_token?: string;
    bio?: string;
    location?: string;
    website?: string;
    github_url?: string;
    twitter_url?: string;
    linkedin_url?: string;
    skills?: string;
    dashboard_sections?: string;
    created_at?: string;
}

interface PostAuthorInfo {
    title: string;
    author_id: number;
    email: string;
    email_notifications: number;
    username: string;
}

interface DBUserEmail { email: string; }
interface DBUserTotp { totp_secret: string; }
interface DBCount { count: number; }
interface DBSetting { value: string; }

// Utility to extract image URLs from Markdown content
function extractImageUrls(content: string): string[] {
	if (!content) return [];
	const urls: string[] = [];
	const regex = /!\[.*?\]\((.*?)\)/g;
	let match;
	while ((match = regex.exec(content)) !== null) {
		urls.push(match[1]);
	}
	return urls;
}

// --- PBKDF2 password hashing (replaces plain SHA-256) ---
const PBKDF2_ITERATIONS = 100_000;
const SALT_LENGTH = 16; // bytes

async function hashPassword(password: string): Promise<string> {
	const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
	const keyMaterial = await crypto.subtle.importKey(
		'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']
	);
	const derived = await crypto.subtle.deriveBits(
		{ name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
		keyMaterial, 256
	);
	const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
	const hashHex = Array.from(new Uint8Array(derived)).map(b => b.toString(16).padStart(2, '0')).join('');
	return `pbkdf2:${PBKDF2_ITERATIONS}:${saltHex}:${hashHex}`;
}

async function verifyPassword(password: string, stored: string): Promise<boolean> {
	if (stored.startsWith('pbkdf2:')) {
		// New PBKDF2 format: pbkdf2:<iterations>:<salt_hex>:<hash_hex>
		const [, iters, saltHex, hashHex] = stored.split(':');
		const salt = new Uint8Array(saltHex.match(/.{2}/g)!.map(h => parseInt(h, 16)));
		const keyMaterial = await crypto.subtle.importKey(
			'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']
		);
		const derived = await crypto.subtle.deriveBits(
			{ name: 'PBKDF2', salt, iterations: Number(iters), hash: 'SHA-256' },
			keyMaterial, 256
		);
		const computedHex = Array.from(new Uint8Array(derived)).map(b => b.toString(16).padStart(2, '0')).join('');
		return computedHex === hashHex;
	}
	// Legacy SHA-256 fallback (no salt, plain hex)
	const legacy = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password));
	const legacyHex = Array.from(new Uint8Array(legacy)).map(b => b.toString(16).padStart(2, '0')).join('');
	return legacyHex === stored;
}

// Rehash legacy password to PBKDF2 (call after successful legacy verify)
async function rehashIfLegacy(stored: string, password: string, userId: number, db: any): Promise<void> {
	if (!stored.startsWith('pbkdf2:')) {
		const newHash = await hashPassword(password);
		await db.prepare('UPDATE users SET password = ? WHERE id = ?').bind(newHash, userId).run();
		console.log(`[Security] Migrated user ${userId} password to PBKDF2`);
	}
}

function generateToken(): string {
	return crypto.randomUUID();
}

function hasControlCharacters(str: string): boolean {
	return /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(str);
}

function isVisuallyEmpty(str: string): boolean {
	if (!str) return true;
	const stripped = str.replace(/[\s\u200B-\u200F\uFEFF\u2028\u2029\u180E\u3164\u115F\u1160\x00-\x1F\x7F]+/g, '');
	return stripped.length === 0;
}

function hasInvisibleCharacters(str: string): boolean {
	return /[\u200B-\u200F\uFEFF\u2028\u2029\u180E\u3164\u115F\u1160]/.test(str);
}

function hasRestrictedKeywords(username: string): boolean {
	const restricted = ['administrator', 'admin', 'sudo', 'test'];
	return restricted.some(keyword => username.toLowerCase().includes(keyword.toLowerCase()));
}

// --- Rate Limiter (in-memory, per-isolate) ---
const rateLimitMap = new Map<string, { count: number; resetAt: number }>();

function isRateLimited(key: string, maxRequests: number, windowMs: number): boolean {
	const now = Date.now();
	const entry = rateLimitMap.get(key);
	if (!entry || now > entry.resetAt) {
		rateLimitMap.set(key, { count: 1, resetAt: now + windowMs });
		return false;
	}
	entry.count++;
	if (entry.count > maxRequests) return true;
	return false;
}

// Cleanup stale entries periodically (max 1000 keys)
function cleanupRateLimit() {
	if (rateLimitMap.size > 1000) {
		const now = Date.now();
		for (const [key, val] of rateLimitMap) {
			if (now > val.resetAt) rateLimitMap.delete(key);
		}
	}
}

async function verifyTurnstile(token: string, ip: string, secretKey: string): Promise<boolean> {
	const formData = new FormData();
	formData.append('secret', secretKey);
	formData.append('response', token);
	formData.append('remoteip', ip);

	const url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
	const result = await fetch(url, {
		body: formData,
		method: 'POST',
	});

	const outcome = await result.json() as any;
	return outcome.success;
}

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const url = new URL(request.url);
		const method = request.method;

		// Helper function to get base URL
		const getBaseUrl = () => {
			// Priority: 1. Env var 2. X-Original-URL header (from Pages Functions) 3. Request origin
			if (env.BASE_URL) {
				console.log(`✅ Using BASE_URL from env: ${env.BASE_URL}`);
				return env.BASE_URL;
			}
			
			const xOriginalUrl = request.headers.get('X-Original-URL');
			if (xOriginalUrl) {
				console.log(`✅ Using X-Original-URL from Pages Functions: ${xOriginalUrl}`);
				return xOriginalUrl;
			}
			
			console.warn(`⚠️ BASE_URL not configured and no X-Original-URL header, falling back to request origin: ${url.origin}`);
			return url.origin;
		};

		// CORS headers helper
		// CORS — dynamiczny origin z env.ALLOWED_ORIGIN (może być lista oddzielona przecinkami)
		const requestOrigin = request.headers.get('Origin') || '';
		const allowedOrigins = ((env as any).ALLOWED_ORIGIN || '').split(',').map((o: string) => o.trim());
		const originAllowed = allowedOrigins.includes(requestOrigin) || allowedOrigins.includes('*');
		const corsOrigin = originAllowed ? requestOrigin : (allowedOrigins[0] || '*');
		const corsHeaders = {
			'Access-Control-Allow-Origin': corsOrigin,
			'Access-Control-Allow-Methods': 'GET, HEAD, POST, OPTIONS, DELETE, PUT',
			'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Timestamp, X-Nonce',
			'Access-Control-Allow-Credentials': 'true',
			'Vary': 'Origin',
		};

		// Handle OPTIONS (CORS preflight)
		if (method === 'OPTIONS') {
			return new Response(null, {
				headers: corsHeaders,
			});
		}

		// Helper to return JSON response with CORS
		const jsonResponse = (data: any, status = 200) => {
			return Response.json(data, {
				status,
				headers: corsHeaders,
			});
		};

		// --- Rate limiting for auth endpoints ---
		const clientIp = request.headers.get('CF-Connecting-IP') || '0.0.0.0';
		cleanupRateLimit();

		const rateLimitedPaths = ['/api/login', '/api/register', '/api/auth/forgot-password', '/api/auth/reset-password', '/api/test-email'];
		if (method === 'POST' && rateLimitedPaths.includes(url.pathname)) {
			const rlKey = `${clientIp}:${url.pathname}`;
			// 10 requests per 60 seconds per IP per endpoint
			if (isRateLimited(rlKey, 10, 60_000)) {
				return jsonResponse({ error: 'Zbyt wiele żądań. Spróbuj ponownie za chwilę.' }, 429);
			}
		}

		// Serve R2 objects through Worker when using bucket binding
		if (url.pathname.startsWith('/r2/') && (method === 'GET' || method === 'HEAD')) {
			const bucket = (env as any).BUCKET as R2Bucket | undefined;
			if (!bucket) return new Response('R2 bucket not configured', { status: 404 });
			const key = decodeURIComponent(url.pathname.slice('/r2/'.length));
			if (!key) return new Response('Not Found', { status: 404 });
			const object = await bucket.get(key);
			if (!object) return new Response('Not Found', { status: 404 });
			const headers = new Headers();
			object.writeHttpMetadata(headers);
			if (object.httpEtag) headers.set('etag', object.httpEtag);
			headers.set('Cache-Control', 'public, max-age=3600');
			return new Response(method === 'HEAD' ? null : object.body, { headers });
		}

		// Ensure the database schema exists before anything else.
		const ensureSchema = async () => {
			try {
				await env.jimbo77_community_db.prepare('SELECT 1 FROM posts LIMIT 1').first();
				return;
			} catch (err: any) {
				console.warn('Database schema missing, initializing', err);
			}

			// using prepare().run() instead of exec ensures each statement is committed
			const stmts = [
				`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  username TEXT NOT NULL,
  password TEXT NOT NULL,
  role TEXT DEFAULT 'user',
  verified INTEGER DEFAULT 0,
  verification_token TEXT,
  totp_secret TEXT,
  totp_enabled INTEGER DEFAULT 0,
  reset_token TEXT,
  reset_token_expires INTEGER,
  pending_email TEXT,
  email_change_token TEXT,
  avatar_url TEXT,
  nickname TEXT,
  email_notifications INTEGER DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);`,
				`CREATE TABLE IF NOT EXISTS categories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);`,
				`CREATE TABLE IF NOT EXISTS posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  author_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  category_id INTEGER,
  is_pinned INTEGER DEFAULT 0,
  view_count INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (author_id) REFERENCES users(id),
  FOREIGN KEY (category_id) REFERENCES categories(id)
);`,
				`CREATE TABLE IF NOT EXISTS comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id INTEGER NOT NULL,
  parent_id INTEGER,
  author_id INTEGER NOT NULL,
  content TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (post_id) REFERENCES posts(id),
  FOREIGN KEY (parent_id) REFERENCES comments(id),
  FOREIGN KEY (author_id) REFERENCES users(id)
);`,
				`CREATE TABLE IF NOT EXISTS likes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(post_id, user_id),
  FOREIGN KEY (post_id) REFERENCES posts(id),
  FOREIGN KEY (user_id) REFERENCES users(id)
);`,
				`CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT
);`,
				`CREATE TABLE IF NOT EXISTS nonces (
  nonce TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
);`,
				`CREATE TABLE IF NOT EXISTS sessions (
  jti TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);`,
				`CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  action TEXT NOT NULL,
  resource_type TEXT,
  resource_id TEXT,
  details TEXT,
  ip_address TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);`,
				`INSERT OR IGNORE INTO settings (key, value) VALUES ('turnstile_enabled', '0');`,
				`INSERT OR IGNORE INTO users (email, username, password, role, verified, nickname) VALUES 
('admin@adysec.com', 'Admin', 'e86f78a8a3caf0b60d8e74e5942aa6d86dc150cd3c03338aef25b7d2d7e3acc7', 'admin', 1, 'System Admin');`
			];
			for (const stmt of stmts) {
				try {
					await env.jimbo77_community_db.prepare(stmt).run();
				} catch (e) {
					console.error('Error running schema statement', e, stmt);
				}
			}
			// verify posts table exists now
			try {
				await env.jimbo77_community_db.prepare('SELECT 1 FROM posts LIMIT 1').first();
			} catch (e) {
				console.error('Failed to verify posts table after init', e);
			}
		};

		// perform initialization before security setup
		await ensureSchema();

		let security: Security;
		try {
			security = new Security(env);
		} catch (e) {
			console.error('Security initialization failed:', e);
			return Response.json(
				{ error: 'Server misconfigured' },
				{ status: 500, headers: corsHeaders }
			);
		}

		// authentication helper - throws on failure
		const authenticate = async (req: Request) => {
			const authHeader = req.headers.get('Authorization');
			if (!authHeader || !authHeader.startsWith('Bearer ')) {
				throw new Error('Unauthorized');
			}
			const token = authHeader.split(' ')[1];
			const payload = await security.verifyToken(token);
			if (!payload) {
				throw new Error('Unauthorized');
			}
			return payload;
		};

		// Helper to handle errors
		const handleError = (e: any) => {
			const errString = String(e);
			if (errString.includes('Unauthorized') || errString.includes('Invalid Token')) {
				return jsonResponse({ error: 'Brak autoryzacji' }, 401);
			}
			return jsonResponse({ error: errString }, 500);
		};


        const publicPaths = [
            '/api/config', '/api/login', '/api/register', '/api/verify', 
            '/api/auth/forgot-password', '/api/auth/reset-password', '/api/verify-email-change',
             // Static/Public GETs
            '/api/posts', '/api/categories', '/api/stats'
        ];
        
        // Relax check for public GETs that don't need nonce
        const isPublicGet = method === 'GET' && (
            publicPaths.includes(url.pathname) || 
            url.pathname.match(/^\/api\/posts\/\d+$/) || 
            url.pathname.match(/^\/api\/posts\/\d+\/comments$/)
        );

        // However, user specifically asked for "Replay protection for sensitive operations".
        // We will apply strict checks for mutation methods (POST, PUT, DELETE)
        if (['POST', 'PUT', 'DELETE'].includes(method)) {
             const validation = await security.validateRequest(request);
             if (!validation.valid) {
                 return jsonResponse({ error: validation.error || 'Security check failed' }, 400);
             }
        }

		// GET /api/config
		if (url.pathname === '/api/config' && method === 'GET') {
			try {
				const [setting, userCount] = await Promise.all([
					env.jimbo77_community_db.prepare("SELECT value FROM settings WHERE key = 'turnstile_enabled'").first<DBSetting>(),
					env.jimbo77_community_db.prepare('SELECT COUNT(*) as count FROM users').first('count')
				]);
				
				// Turnstile aktywny tylko gdy włączony w bazie danych ORAZ oba klucze env są skonfigurowane
				const dbEnabled = setting ? setting.value === '1' : false;
				const siteKey = (env as any).TURNSTILE_SITE_KEY || '';
				const secretKey = (env as any).TURNSTILE_SECRET_KEY || '';
				const turnstileFullyConfigured = !!(dbEnabled && siteKey && secretKey);
				
				return jsonResponse({
					turnstile_enabled: turnstileFullyConfigured,
					turnstile_site_key: siteKey,
					user_count: userCount || 0,
					jwt_secret_configured: !!env.JWT_SECRET && String(env.JWT_SECRET).length >= 32
				});
			} catch (e) {
				return handleError(e);
			}
		}

		// GET /api/admin/settings
		if (url.pathname === '/api/admin/settings' && method === 'GET') {
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Brak autoryzacji' }, 403);

				const settings = await env.jimbo77_community_db.prepare("SELECT key, value FROM settings").all();
				const config: any = {
					turnstile_enabled: false,
					notify_on_user_delete: false,
					notify_on_username_change: false,
					notify_on_avatar_change: false,
					notify_on_manual_verify: false
				};
				
				if (settings.results) {
					for (const row of settings.results) {
						config[row.key as string] = row.value === '1';
					}
				}
				
				return jsonResponse(config);
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/admin/settings
		if (url.pathname === '/api/admin/settings' && method === 'POST') {
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Brak autoryzacji' }, 403);

				const body = await request.json() as any;
				const { turnstile_enabled, notify_on_user_delete, notify_on_username_change, notify_on_avatar_change, notify_on_manual_verify } = body;
				
				const stmt = env.jimbo77_community_db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)");
				const batch = [];

				if (turnstile_enabled !== undefined) batch.push(stmt.bind('turnstile_enabled', turnstile_enabled ? '1' : '0'));
				if (notify_on_user_delete !== undefined) batch.push(stmt.bind('notify_on_user_delete', notify_on_user_delete ? '1' : '0'));
				if (notify_on_username_change !== undefined) batch.push(stmt.bind('notify_on_username_change', notify_on_username_change ? '1' : '0'));
				if (notify_on_avatar_change !== undefined) batch.push(stmt.bind('notify_on_avatar_change', notify_on_avatar_change ? '1' : '0'));
				if (notify_on_manual_verify !== undefined) batch.push(stmt.bind('notify_on_manual_verify', notify_on_manual_verify ? '1' : '0'));
				
				if (batch.length > 0) await env.jimbo77_community_db.batch(batch);

				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}
		
		// Helper to check Turnstile if enabled
		const checkTurnstile = async (reqBody: any, ip: string) => {
			const setting = await env.jimbo77_community_db.prepare("SELECT value FROM settings WHERE key = 'turnstile_enabled'").first<DBSetting>();
			// Wymagaj weryfikacji tylko gdy włączone w bazie i oba klucze env skonfigurowane (spójne z frontendem)
			const dbEnabled = setting && setting.value === '1';
			const siteKey = (env as any).TURNSTILE_SITE_KEY;
			const secretKey = (env as any).TURNSTILE_SECRET_KEY;
			const fullyConfigured = dbEnabled && siteKey && secretKey;
			
			if (fullyConfigured) {
				const token = reqBody['cf-turnstile-response'];
				if (!token) return false;
				return await verifyTurnstile(token, ip, secretKey);
			}
			return true;
		};

		// POST /api/upload (Image Upload)
		if (url.pathname === '/api/upload' && method === 'POST') {
			try {
				const user = await authenticate(request);
				
				const formData = await request.formData();
				const file = formData.get('file');
				const userId = user.id.toString(); // Use verified user ID
				const postId = formData.get('post_id') || 'general';
				const type = formData.get('type') || 'post';

				if (!file || !(file instanceof File)) {
					return jsonResponse({ error: 'Nie przesłano pliku' }, 400);
				}

				if (!file.type.startsWith('image/')) {
					return jsonResponse({ error: 'Dozwolone tylko obrazy' }, 400);
				}

// Check file size (2MB = 2 * 1024 * 1024 bytes)
			const MAX_SIZE = 2 * 1024 * 1024;
			if (file.size > MAX_SIZE) {
				return jsonResponse({ error: 'File size too large (Max 2MB)' }, 400);
				}

				const imageKey = await uploadImage(env as unknown as S3Env, file, userId, postId.toString(), type as 'post' | 'avatar');
			const publicBase = (env as any).BUCKET ? `${getBaseUrl()}/r2` : undefined;
			const imageUrl = getPublicUrl(env as unknown as S3Env, imageKey, publicBase);
				return jsonResponse({ success: true, url: imageUrl });
			} catch (e) {
				console.error('Upload error:', e);
				return handleError(e); // 401/403 will be caught here if auth fails
			}
		}

		// --- AUTH ROUTES ---

		// POST /api/login
		if (url.pathname === '/api/login' && method === 'POST') {
			try {
				const body = await request.json() as any;
				
				// Turnstile Check
				const ip = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
				if (!(await checkTurnstile(body, ip))) {
					return jsonResponse({ error: 'Weryfikacja CAPTCHA nie powiodła się' }, 403);
				}

				const { email, password, totp_code } = body;
				if (!email || !password) {
					return jsonResponse({ error: 'Podaj e-mail i hasło' }, 400);
				}

				const user = await env.jimbo77_community_db
					.prepare('SELECT * FROM users WHERE email = ?')
					.bind(email)
					.first<DBUser>();
				if (!user) {
					return jsonResponse({ error: 'Nieprawidłowy e-mail lub hasło' }, 401);
				}

				if (!user.verified) {
					return jsonResponse({ error: 'Najpierw zweryfikuj swój e-mail (sprawdź skrzynkę)' }, 403);
				}

				if (!await verifyPassword(password, user.password)) {
					return jsonResponse({ error: 'Nieprawidłowy e-mail lub hasło' }, 401);
				}

				// Auto-migrate legacy SHA-256 hash to PBKDF2
				ctx.waitUntil(rehashIfLegacy(user.password, password, user.id, env.jimbo77_community_db));

				// TOTP Check
				if (user.totp_enabled) {
					if (!totp_code) {
						return jsonResponse({ error: 'TOTP_REQUIRED' }, 403);
					}
					if (!user.totp_secret) {
						return jsonResponse({ error: 'TOTP nie skonfigurowane — skontaktuj się z adminem' }, 500);
					}

					const totp = new OTPAuth.TOTP({
						algorithm: 'SHA1',
						digits: 6,
						period: 30,
						secret: OTPAuth.Secret.fromBase32(String(user.totp_secret)),
					});

					const delta = totp.validate({ token: totp_code, window: 1 });
					if (delta === null) {
						return jsonResponse({ error: 'Nieprawidłowy kod 2FA' }, 401);
					}
				}

				const { token, jti, expiresAt } = await security.generateToken({
					id: user.id,
					role: user.role || 'user',
					email: user.email
				});

				await env.jimbo77_community_db.prepare('INSERT INTO sessions (jti, user_id, expires_at) VALUES (?, ?, ?)').bind(jti, user.id, expiresAt).run();
				await security.logAudit(user.id, 'LOGIN', 'user', String(user.id), { email }, request);

				return jsonResponse({
					token,
					user: {
						id: user.id,
						email: user.email,
						username: user.username,
						avatar_url: user.avatar_url,
						role: user.role || 'user',
						totp_enabled: !!user.totp_enabled,
						email_notifications: user.email_notifications === 1
					}
				});
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/user/profile
		if (url.pathname === '/api/user/profile' && method === 'POST') {
			try {
				const userPayload = await authenticate(request);
				const body = await request.json() as any;
				const { username, avatar_url, email_notifications, bio, location, website, github_url, twitter_url, linkedin_url, skills, dashboard_sections } = body;
				
				const user_id = userPayload.id;

				if (username) {
					if (username.length > 20) return jsonResponse({ error: 'Nazwa max 20 znaków' }, 400);
					if (isVisuallyEmpty(username)) return jsonResponse({ error: 'Nazwa użytkownika nie może być pusta' }, 400);
					if (hasInvisibleCharacters(username)) return jsonResponse({ error: 'Nazwa zawiera niedozwolone niewidoczne znaki' }, 400);
					if (hasControlCharacters(username)) return jsonResponse({ error: 'Nazwa zawiera niedozwolone znaki sterujące' }, 400);
					if (hasRestrictedKeywords(username)) return jsonResponse({ error: 'Nazwa zawiera zastrzeżone słowa kluczowe' }, 400);
					
					const existingUser = await env.jimbo77_community_db.prepare('SELECT id FROM users WHERE username = ? AND id != ?').bind(username, user_id).first<{id:number}>();
					if (existingUser) {
						return jsonResponse({ error: 'Ta nazwa użytkownika jest już zajęta' }, 409);
					}
				}

				const currentUser = await env.jimbo77_community_db.prepare('SELECT * FROM users WHERE id = ?').bind(user_id).first<DBUser>();
				if (!currentUser) return jsonResponse({ error: 'Użytkownik nie znaleziony' }, 404);

				let newUsername = currentUser.username;
				if (username !== undefined) newUsername = username;

				let newAvatarUrl = currentUser.avatar_url;
				if (avatar_url !== undefined) {
					if (avatar_url === '' || avatar_url === null) {
						newAvatarUrl = await generateIdenticon(String(user_id));
					} else {
						if (avatar_url.length > 500) return jsonResponse({ error: 'Avatar URL za długi (max 500 znaków)' }, 400);
						if (!/^https?:\/\//i.test(avatar_url) && !avatar_url.startsWith('data:image/svg+xml')) return jsonResponse({ error: 'Nieprawidłowy URL avatara (musi zaczynać się od http:// lub https://)' }, 400);
						newAvatarUrl = avatar_url;
					}
				}

				let newEmailNotif = currentUser.email_notifications;
				if (email_notifications !== undefined) newEmailNotif = email_notifications ? 1 : 0;

				// Dashboard profile fields
				const newBio = bio !== undefined ? String(bio).slice(0, 500) : (currentUser.bio || '');
				const newLocation = location !== undefined ? String(location).slice(0, 100) : (currentUser.location || '');
				const newWebsite = website !== undefined ? String(website).slice(0, 200) : (currentUser.website || '');
				const newGithub = github_url !== undefined ? String(github_url).slice(0, 200) : (currentUser.github_url || '');
				const newTwitter = twitter_url !== undefined ? String(twitter_url).slice(0, 200) : (currentUser.twitter_url || '');
				const newLinkedin = linkedin_url !== undefined ? String(linkedin_url).slice(0, 200) : (currentUser.linkedin_url || '');
				const newSkills = skills !== undefined ? String(skills).slice(0, 500) : (currentUser.skills || '');
				const newDashboard = dashboard_sections !== undefined ? String(dashboard_sections).slice(0, 10000) : (currentUser.dashboard_sections || '[]');

				await env.jimbo77_community_db.prepare(
					`UPDATE users SET username = ?, avatar_url = ?, email_notifications = ?,
					 bio = ?, location = ?, website = ?, github_url = ?, twitter_url = ?,
					 linkedin_url = ?, skills = ?, dashboard_sections = ? WHERE id = ?`
				).bind(newUsername, newAvatarUrl, newEmailNotif, newBio, newLocation, newWebsite, newGithub, newTwitter, newLinkedin, newSkills, newDashboard, user_id).run();

				const user = await env.jimbo77_community_db.prepare('SELECT * FROM users WHERE id = ?').bind(user_id).first<DBUser>();
				if (!user) return jsonResponse({ error: 'Użytkownik nie znaleziony' }, 404);
				return jsonResponse({
					success: true,
					user: {
						id: user.id,
						email: user.email,
						username: user.username,
						avatar_url: user.avatar_url,
						role: user.role || 'user',
						totp_enabled: !!user.totp_enabled,
						email_notifications: user.email_notifications === 1,
						bio: user.bio || '',
						location: user.location || '',
						website: user.website || '',
						github_url: user.github_url || '',
						twitter_url: user.twitter_url || '',
						linkedin_url: user.linkedin_url || '',
						skills: user.skills || '',
						dashboard_sections: user.dashboard_sections || '[]'
					}
				});
			} catch (e) {
				return handleError(e);
			}
		}

		// GET /api/users/:username/dashboard — public user dashboard/profile
		const dashboardMatch = url.pathname.match(/^\/api\/users\/([^/]+)\/dashboard$/);
		if (dashboardMatch && method === 'GET') {
			try {
				const targetUsername = decodeURIComponent(dashboardMatch[1]);
				const user = await env.jimbo77_community_db.prepare(
					`SELECT id, username, avatar_url, role, bio, location, website,
					 github_url, twitter_url, linkedin_url, skills, dashboard_sections, created_at
					 FROM users WHERE username = ?`
				).bind(targetUsername).first<DBUser>();
				if (!user) return jsonResponse({ error: 'Użytkownik nie znaleziony' }, 404);

				// Fetch user stats
				const postCount = await env.jimbo77_community_db.prepare('SELECT COUNT(*) as cnt FROM posts WHERE author_id = ?').bind(user.id).first<{cnt:number}>();
				const commentCount = await env.jimbo77_community_db.prepare('SELECT COUNT(*) as cnt FROM comments WHERE author_id = ?').bind(user.id).first<{cnt:number}>();
				const likeCount = await env.jimbo77_community_db.prepare(
					'SELECT COUNT(*) as cnt FROM likes WHERE post_id IN (SELECT id FROM posts WHERE author_id = ?)'
				).bind(user.id).first<{cnt:number}>();

				// Recent posts
				const recentPosts = await env.jimbo77_community_db.prepare(
					`SELECT p.id, p.title, p.created_at, p.view_count,
					 (SELECT COUNT(*) FROM likes WHERE post_id = p.id) as like_count,
					 (SELECT COUNT(*) FROM comments WHERE post_id = p.id) as comment_count
					 FROM posts p WHERE p.author_id = ? ORDER BY p.created_at DESC LIMIT 5`
				).bind(user.id).all();

				return jsonResponse({
					id: user.id,
					username: user.username,
					avatar_url: user.avatar_url || '',
					role: user.role || 'user',
					bio: user.bio || '',
					location: user.location || '',
					website: user.website || '',
					github_url: user.github_url || '',
					twitter_url: user.twitter_url || '',
					linkedin_url: user.linkedin_url || '',
					skills: user.skills || '',
					dashboard_sections: user.dashboard_sections || '[]',
					created_at: user.created_at || '',
					stats: {
						posts: postCount?.cnt || 0,
						comments: commentCount?.cnt || 0,
						likes_received: likeCount?.cnt || 0,
					},
					recent_posts: recentPosts?.results || [],
				});
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/user/delete
		if (url.pathname === '/api/user/delete' && method === 'POST') {
			try {
				const userPayload = await authenticate(request);
				const body = await request.json() as any;
				const { password, totp_code } = body;
				
				if (!password) return jsonResponse({ error: 'Podaj hasło' }, 400);

				const user_id = userPayload.id;

				const user = await env.jimbo77_community_db.prepare('SELECT * FROM users WHERE id = ?').bind(user_id).first<DBUser>();
				if (!user) return jsonResponse({ error: 'Użytkownik nie znaleziony' }, 404);

				// Verify Password (Double check for sensitive delete op)
				if (!await verifyPassword(password, user.password)) {
					return jsonResponse({ error: 'Nieprawidłowe hasło' }, 401);
				}

				// Verify TOTP if enabled
				if (user.totp_enabled) {
					if (!totp_code) return jsonResponse({ error: 'TOTP_REQUIRED' }, 403);
					if (!user.totp_secret) return jsonResponse({ error: 'TOTP not configured' }, 500);
					const totp = new OTPAuth.TOTP({
						algorithm: 'SHA1',
						digits: 6,
						period: 30,
						secret: OTPAuth.Secret.fromBase32(String(user.totp_secret))
					});
					if (totp.validate({ token: totp_code, window: 1 }) === null) {
						return jsonResponse({ error: 'Nieprawidłowy kod 2FA' }, 401);
					}
				}

				// Delete User and Data
				
				// 1. Delete images (Avatar + Post images)
				const posts: any = await env.jimbo77_community_db.prepare('SELECT content FROM posts WHERE author_id = ?').bind(user_id).all();
				const deletionPromises: Promise<any>[] = [];
				
				if (user.avatar_url) {
					deletionPromises.push(deleteImage(env as unknown as S3Env, user.avatar_url, user_id));
				}
				
				if (posts.results) {
					for (const post of posts.results) {
						const imageUrls = extractImageUrls(post.content as string);
						imageUrls.forEach(url => deletionPromises.push(deleteImage(env as unknown as S3Env, url, user_id)));
					}
				}
				
				if (deletionPromises.length > 0) {
					 ctx.waitUntil(Promise.all(deletionPromises).catch(err => console.error('Failed to delete user images', err)));
				}

				// 2. Delete likes/comments ON user's posts (Cascade manually)
				await env.jimbo77_community_db.prepare('DELETE FROM likes WHERE post_id IN (SELECT id FROM posts WHERE author_id = ?)').bind(user_id).run();
				await env.jimbo77_community_db.prepare('DELETE FROM comments WHERE post_id IN (SELECT id FROM posts WHERE author_id = ?)').bind(user_id).run();

				// 3. Delete user's activity
				await env.jimbo77_community_db.prepare('DELETE FROM likes WHERE user_id = ?').bind(user_id).run();
				await env.jimbo77_community_db.prepare('DELETE FROM comments WHERE author_id = ?').bind(user_id).run();
				
				// 4. Delete posts and user
				await env.jimbo77_community_db.prepare('DELETE FROM posts WHERE author_id = ?').bind(user_id).run();
				await env.jimbo77_community_db.prepare('DELETE FROM users WHERE id = ?').bind(user_id).run();
				
				await security.logAudit(userPayload.id, 'DELETE_ACCOUNT', 'user', String(user_id), {}, request);

				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/user/totp/setup
		if (url.pathname === '/api/user/totp/setup' && method === 'POST') {
			try {
				const userPayload = await authenticate(request);
				const user_id = userPayload.id; // Force use of authenticated ID
				
				const secret = new OTPAuth.Secret({ size: 20 });
				const secretBase32 = secret.base32;

				await env.jimbo77_community_db.prepare('UPDATE users SET totp_secret = ?, totp_enabled = 0 WHERE id = ?').bind(secretBase32, user_id).run();

				const user = await env.jimbo77_community_db.prepare('SELECT email FROM users WHERE id = ?').bind(user_id).first<DBUserEmail>();
			if (!user) return jsonResponse({ error: 'Użytkownik nie znaleziony' }, 404);
				
				await security.logAudit(userPayload.id, 'SETUP_TOTP', 'user', String(user_id), {}, request);

				const totp = new OTPAuth.TOTP({
					issuer: 'CloudflareForum',
					label: user.email,
					algorithm: 'SHA1',
					digits: 6,
					period: 30,
					secret: secret
				});

				return jsonResponse({ 
					secret: secretBase32,
					uri: totp.toString() 
				});
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/user/totp/verify
		if (url.pathname === '/api/user/totp/verify' && method === 'POST') {
			try {
				const userPayload = await authenticate(request);
				const body = await request.json() as any;
				const { token } = body;
				const user_id = userPayload.id; // Force use of authenticated ID

				if (!token) return jsonResponse({ error: 'Brak wymaganych parametrów' }, 400);

				const user = await env.jimbo77_community_db.prepare('SELECT totp_secret FROM users WHERE id = ?').bind(user_id).first<DBUserTotp>();
				
				if (!user || !user.totp_secret) return jsonResponse({ error: 'TOTP not setup' }, 400);

				const totp = new OTPAuth.TOTP({
					algorithm: 'SHA1',
					digits: 6,
					period: 30,
					secret: OTPAuth.Secret.fromBase32(user.totp_secret)
				});

				const delta = totp.validate({ token: token, window: 1 });

				if (delta !== null) {
					await env.jimbo77_community_db.prepare('UPDATE users SET totp_enabled = 1 WHERE id = ?').bind(user_id).run();
					await security.logAudit(userPayload.id, 'ENABLE_TOTP', 'user', String(user_id), {}, request);
					return jsonResponse({ success: true });
				} else {
					return jsonResponse({ error: 'Nieprawidłowy kod weryfikacyjny' }, 400);
				}
			} catch (e) {
				return handleError(e);
			}
		}

		// GET /api/user/me — fetch current authenticated user
		if (url.pathname === '/api/user/me' && method === 'GET') {
			try {
				const userPayload = await authenticate(request);
				const user = await env.jimbo77_community_db.prepare(
					'SELECT id, email, username, avatar_url, role, totp_enabled, email_notifications, created_at FROM users WHERE id = ?'
				).bind(userPayload.id).first<DBUser>();
				if (!user) return jsonResponse({ error: 'Użytkownik nie znaleziony' }, 404);

				return jsonResponse({
					id: user.id,
					email: user.email,
					username: user.username,
					avatar_url: user.avatar_url,
					role: user.role || 'user',
					totp_enabled: !!user.totp_enabled,
					email_notifications: (user as any).email_notifications === 1,
					created_at: (user as any).created_at
				});
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/user/change-password — change password while logged in
		if (url.pathname === '/api/user/change-password' && method === 'POST') {
			try {
				const userPayload = await authenticate(request);
				const body = await request.json() as any;
				const { current_password, new_password, totp_code } = body;

				if (!current_password || !new_password) return jsonResponse({ error: 'Podaj obecne i nowe hasło' }, 400);
				if (new_password.length < 8 || new_password.length > 16) return jsonResponse({ error: 'Hasło musi mieć 8–16 znaków' }, 400);

				const user = await env.jimbo77_community_db.prepare('SELECT * FROM users WHERE id = ?').bind(userPayload.id).first<DBUser>();
				if (!user) return jsonResponse({ error: 'Użytkownik nie znaleziony' }, 404);

				// Verify current password
				if (!await verifyPassword(current_password, user.password)) {
					return jsonResponse({ error: 'Nieprawidłowe obecne hasło' }, 401);
				}

				// Verify TOTP if enabled
				if (user.totp_enabled) {
					if (!totp_code) return jsonResponse({ error: 'TOTP_REQUIRED' }, 403);
					if (!user.totp_secret) return jsonResponse({ error: 'TOTP not configured' }, 500);
					const totp = new OTPAuth.TOTP({
						algorithm: 'SHA1', digits: 6, period: 30,
						secret: OTPAuth.Secret.fromBase32(String(user.totp_secret))
					});
					if (totp.validate({ token: totp_code, window: 1 }) === null) {
						return jsonResponse({ error: 'Nieprawidłowy kod 2FA' }, 401);
					}
				}

				const newHash = await hashPassword(new_password);
				await env.jimbo77_community_db.prepare('UPDATE users SET password = ? WHERE id = ?').bind(newHash, userPayload.id).run();

				// Invalidate all other sessions
				await env.jimbo77_community_db.prepare('DELETE FROM sessions WHERE user_id = ? AND jti != ?')
					.bind(userPayload.id, (userPayload as any).jti || '').run();

				await security.logAudit(userPayload.id, 'CHANGE_PASSWORD', 'user', String(userPayload.id), {}, request);
				return jsonResponse({ success: true, message: 'Password changed. Other sessions invalidated.' });
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/user/totp/disable — disable TOTP 2FA
		if (url.pathname === '/api/user/totp/disable' && method === 'POST') {
			try {
				const userPayload = await authenticate(request);
				const body = await request.json() as any;
				const { password, totp_code } = body;

				if (!password || !totp_code) return jsonResponse({ error: 'Podaj hasło i kod 2FA' }, 400);

				const user = await env.jimbo77_community_db.prepare('SELECT * FROM users WHERE id = ?').bind(userPayload.id).first<DBUser>();
				if (!user) return jsonResponse({ error: 'Użytkownik nie znaleziony' }, 404);
				if (!user.totp_enabled) return jsonResponse({ error: 'TOTP is not enabled' }, 400);

				// Verify password
				if (!await verifyPassword(password, user.password)) {
					return jsonResponse({ error: 'Nieprawidłowe hasło' }, 401);
				}

				// Verify current TOTP code
				if (!user.totp_secret) return jsonResponse({ error: 'TOTP not configured' }, 500);
				const totp = new OTPAuth.TOTP({
					algorithm: 'SHA1', digits: 6, period: 30,
					secret: OTPAuth.Secret.fromBase32(String(user.totp_secret))
				});
				if (totp.validate({ token: totp_code, window: 1 }) === null) {
					return jsonResponse({ error: 'Nieprawidłowy kod 2FA' }, 401);
				}

				await env.jimbo77_community_db.prepare('UPDATE users SET totp_enabled = 0, totp_secret = NULL WHERE id = ?').bind(userPayload.id).run();
				await security.logAudit(userPayload.id, 'DISABLE_TOTP', 'user', String(userPayload.id), {}, request);

				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/auth/forgot-password
		if (url.pathname === '/api/auth/forgot-password' && method === 'POST') {
			try {
				const body = await request.json() as any;

				// Turnstile Check
				const ip = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
				if (!(await checkTurnstile(body, ip))) {
					return jsonResponse({ error: 'Turnstile verification failed' }, 403);
				}

				const { email } = body;
				if (!email) return jsonResponse({ error: 'Podaj adres e-mail' }, 400);

				const user = await env.jimbo77_community_db.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
				if (!user) return jsonResponse({ success: true }); // Silent fail

				const token = generateToken();
				const expires = Date.now() + 3600000; // 1 hour

				await env.jimbo77_community_db.prepare('UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?')
					.bind(token, expires, user.id).run();

				const baseUrl = getBaseUrl();
				const resetLink = `${baseUrl}/reset?token=${token}`;
				
				const emailHtml = `
					<h1>Prośba o reset hasła</h1>
					<p>Kliknij poniższy link, aby zresetować hasło:</p>
					<a href="${resetLink}">Resetuj hasło</a>
					<p>Jeśli nie prosiłeś o tę operację, zignoruj tego e-maila.</p>
					<p>Ten link wygaśnie za 1 godzinę.</p>
				`;

				ctx.waitUntil(sendEmail(email, 'Prośba o reset hasła', emailHtml, env).catch(console.error));
				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /auth/reset-password
		if (url.pathname === '/api/auth/reset-password' && method === 'POST') {
			try {
				const body = await request.json() as any;

				// Turnstile Check
				const ip = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
				if (!(await checkTurnstile(body, ip))) {
					return jsonResponse({ error: 'Turnstile verification failed' }, 403);
				}

				const { token, new_password, totp_code } = body;
				if (!token || !new_password) return jsonResponse({ error: 'Brak wymaganych parametrów' }, 400);

				if (new_password.length < 8 || new_password.length > 16) return jsonResponse({ error: 'Password must be 8-16 characters' }, 400);

				// Verify token
				const user = await env.jimbo77_community_db.prepare('SELECT * FROM users WHERE reset_token = ?').bind(token).first<DBUser>();
				if (!user) return jsonResponse({ error: 'Nieprawidłowy lub wygasły token' }, 400);
				if (!user.reset_token_expires || Date.now() > user.reset_token_expires) return jsonResponse({ error: 'Token expired' }, 400);

				// If user has 2FA, require it
				if (user.totp_enabled) {
					if (!totp_code) return jsonResponse({ error: 'TOTP_REQUIRED' }, 403);
					if (!user.totp_secret) return jsonResponse({ error: 'TOTP not configured' }, 500);
					const totp = new OTPAuth.TOTP({
						algorithm: 'SHA1',
						digits: 6,
						period: 30,
						secret: OTPAuth.Secret.fromBase32(String(user.totp_secret))
					});
					if (totp.validate({ token: totp_code, window: 1 }) === null) {
						return jsonResponse({ error: 'Nieprawidłowy kod 2FA' }, 401);
					}
				}

				const passwordHash = await hashPassword(new_password);
				await env.jimbo77_community_db.prepare('UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?')
					.bind(passwordHash, user.id).run();

				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/user/change-email
		if (url.pathname === '/api/user/change-email' && method === 'POST') {
			try {
				const userPayload = await authenticate(request);
				const body = await request.json() as any;
				const { new_email, totp_code } = body; 
				
				if (!new_email) return jsonResponse({ error: 'Podaj nowy adres e-mail' }, 400);
				
				if (new_email.length > 50) return jsonResponse({ error: 'E-mail max 50 znaków' }, 400);
				
				const user_id = userPayload.id;

const user = await env.jimbo77_community_db.prepare('SELECT * FROM users WHERE id = ?').bind(user_id).first<DBUser>();
				if (!user) return jsonResponse({ error: 'Użytkownik nie znaleziony' }, 404);

				// Verify 2FA if enabled
				if (user.totp_enabled) {
					if (!totp_code) return jsonResponse({ error: 'TOTP_REQUIRED' }, 403);
					if (!user.totp_secret) return jsonResponse({ error: 'TOTP not configured' }, 500);
					const totp = new OTPAuth.TOTP({
						algorithm: 'SHA1',
						digits: 6,
						period: 30,
						secret: OTPAuth.Secret.fromBase32(String(user.totp_secret))
					});
					if (totp.validate({ token: totp_code, window: 1 }) === null) {
						return jsonResponse({ error: 'Nieprawidłowy kod 2FA' }, 401);
					}
				}

				// Check if email already exists
				const exists = await env.jimbo77_community_db.prepare('SELECT id FROM users WHERE email = ?').bind(new_email).first();
				if (exists) return jsonResponse({ error: 'Ten e-mail jest już w użyciu' }, 400);

				const token = generateToken();
				await env.jimbo77_community_db.prepare('UPDATE users SET pending_email = ?, email_change_token = ? WHERE id = ?')
					.bind(new_email, token, user.id).run();
				
				await security.logAudit(userPayload.id, 'CHANGE_EMAIL_INIT', 'user', String(user_id), { new_email }, request);

				const baseUrl = getBaseUrl();
				const verifyLink = `${baseUrl}/api/verify-email-change?token=${token}`;
				const emailHtml = `
					<h1>Potwierdź zmianę adresu e-mail</h1>
					<p>Kliknij poniższy link, aby potwierdzić zmianę e-maila na ${new_email}:</p>
					<a href="${verifyLink}">Potwierdź zmianę</a>
				`;

				ctx.waitUntil(sendEmail(new_email, 'Potwierdź zmianę adresu e-mail', emailHtml, env).catch(console.error));
				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}

		// GET /api/verify-email-change
		if (url.pathname === '/api/verify-email-change' && method === 'GET') {
			const token = url.searchParams.get('token');
			if (!token) return new Response('Missing token', { status: 400 });

			try {
const user = await env.jimbo77_community_db.prepare('SELECT * FROM users WHERE email_change_token = ?').bind(token).first<DBUser>();
				if (!user) return new Response('Invalid token', { status: 400 });

				await env.jimbo77_community_db.prepare('UPDATE users SET email = ?, pending_email = NULL, email_change_token = NULL WHERE id = ?')
					.bind(user.pending_email, user.id).run();

				return Response.redirect(`${getBaseUrl()}/?email_changed=true`, 302);
			} catch (e) {
				return new Response('Failed', { status: 500 });
			}
		}

		// POST /api/admin/users/:id/update (Admin direct update)
		if (url.pathname.match(/^\/api\/admin\/users\/\d+\/update$/) && method === 'POST') {
			const id = url.pathname.split('/')[4];
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Brak autoryzacji' }, 403);

				const body = await request.json() as any;
				const { password, email, username, avatar_url } = body;

				if (password && (password.length < 8 || password.length > 16)) return jsonResponse({ error: 'Hasło musi mieć 8–16 znaków' }, 400);

				if (password) {
					const hash = await hashPassword(password);
					await env.jimbo77_community_db.prepare('UPDATE users SET password = ? WHERE id = ?').bind(hash, id).run();
				}
				if (email) {
					if (email.length > 50) return jsonResponse({ error: 'E-mail max 50 znaków' }, 400);
					await env.jimbo77_community_db.prepare('UPDATE users SET email = ? WHERE id = ?').bind(email, id).run();
				}
				if (avatar_url !== undefined) {
					// Allow clearing avatar with empty string or null -> Force Regenerate Default
					if (!avatar_url) {
						// Reset to Default
						const identicon = await generateIdenticon(String(id));
						await env.jimbo77_community_db.prepare('UPDATE users SET avatar_url = ? WHERE id = ?').bind(identicon, id).run();
					} else {
						if (avatar_url.length > 500) return jsonResponse({ error: 'Avatar URL too long (Max 500 chars)' }, 400);
						if (!/^https?:\/\//i.test(avatar_url) && !avatar_url.startsWith('data:image/svg+xml')) return jsonResponse({ error: 'Nieprawidłowy URL avatara' }, 400);
						await env.jimbo77_community_db.prepare('UPDATE users SET avatar_url = ? WHERE id = ?').bind(avatar_url, id).run();
					}

					// Notify Avatar Change
					const notifyAvatar = await env.jimbo77_community_db.prepare("SELECT value FROM settings WHERE key = 'notify_on_avatar_change'").first<DBSetting>();
					if (notifyAvatar && notifyAvatar.value === '1') {
						const user = await env.jimbo77_community_db.prepare('SELECT email, username FROM users WHERE id = ?').bind(id).first<{email:string;username:string}>();
						if (user) {
							const emailHtml = `
								<h1>Avatar został zaktualizowany</h1>
								<p>Twój avatar został zmieniony przez administratora.</p>
							`;
							ctx.waitUntil(sendEmail(user.email, 'Twój avatar został zaktualizowany', emailHtml, env).catch(console.error));
						}
					}
				}
				if (username) {
					if (username.length > 20) return jsonResponse({ error: 'Username too long (Max 20 chars)' }, 400);
					if (isVisuallyEmpty(username)) return jsonResponse({ error: 'Username cannot be empty' }, 400);
					if (hasInvisibleCharacters(username)) return jsonResponse({ error: 'Username contains invalid invisible characters' }, 400);
					if (hasControlCharacters(username)) return jsonResponse({ error: 'Username contains invalid control characters' }, 400);
					
					await env.jimbo77_community_db.prepare('UPDATE users SET username = ? WHERE id = ?').bind(username, id).run();

					// Notify user about username change
					const notifyUsername = await env.jimbo77_community_db.prepare("SELECT value FROM settings WHERE key = 'notify_on_username_change'").first<DBSetting>();
					if (notifyUsername && notifyUsername.value === '1') {
						const user = await env.jimbo77_community_db.prepare('SELECT email, username FROM users WHERE id = ?').bind(id).first<{email:string;username:string}>();
						if (user) {
							const emailHtml = `
								<h1>Nazwa użytkownika została zmieniona</h1>
								<p>Twoja nazwa użytkownika została zmieniona przez administratora na <strong>${username}</strong>.</p>
								<p>W razie pytań skontaktuj się z administratorem.</p>
							`;
							ctx.waitUntil(sendEmail(user.email, 'Twoja nazwa użytkownika została zmieniona', emailHtml, env).catch(console.error));
						}
					}
				}
				
				await security.logAudit(userPayload.id, 'ADMIN_UPDATE_USER', 'user', id, { username, email, avatar_url, passwordChanged: !!password }, request);

				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}

		// GET /api/categories
		if (url.pathname === '/api/categories' && method === 'GET') {
			try {
				const { results } = await env.jimbo77_community_db.prepare('SELECT * FROM categories ORDER BY created_at ASC').all();
				return jsonResponse(results);
			} catch (e) {
				return handleError(e);
			}
		}

		// GET /api/stats — public stats for blog sidebar widget
		if (url.pathname === '/api/stats' && method === 'GET') {
			try {
				const [usersRow, postsRow, commentsRow, recentPosts] = await Promise.all([
					env.jimbo77_community_db.prepare('SELECT COUNT(*) as count FROM users WHERE verified = 1').first(),
					env.jimbo77_community_db.prepare('SELECT COUNT(*) as count FROM posts').first(),
					env.jimbo77_community_db.prepare('SELECT COUNT(*) as count FROM comments').first(),
					env.jimbo77_community_db.prepare(
						`SELECT p.id, p.title, p.created_at, u.username as author_name
						 FROM posts p JOIN users u ON p.author_id = u.id
						 ORDER BY p.created_at DESC LIMIT 3`
					).all(),
				]);
				return jsonResponse({
					users: (usersRow as any)?.count ?? 0,
					posts: (postsRow as any)?.count ?? 0,
					comments: (commentsRow as any)?.count ?? 0,
					recent: (recentPosts as any)?.results ?? [],
				});
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/admin/categories
		if (url.pathname === '/api/admin/categories' && method === 'POST') {
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Brak autoryzacji' }, 403);

				const body = await request.json() as any;
				const { name } = body;
				if (!name) return jsonResponse({ error: 'Podaj nazwę' }, 400);
				
				const { success } = await env.jimbo77_community_db.prepare('INSERT INTO categories (name) VALUES (?)').bind(name).run();
				await security.logAudit(userPayload.id, 'CREATE_CATEGORY', 'category', name, {}, request);
				return jsonResponse({ success });
			} catch (e) {
				return handleError(e);
			}
		}

		// PUT /api/admin/categories/:id
		if (url.pathname.match(/^\/api\/admin\/categories\/\d+$/) && method === 'PUT') {
			const id = url.pathname.split('/')[4];
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Brak autoryzacji' }, 403);

				const body = await request.json() as any;
				const { name } = body;
				if (!name) return jsonResponse({ error: 'Podaj nazwę' }, 400);
				
				await env.jimbo77_community_db.prepare('UPDATE categories SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').bind(name, id).run();
				await security.logAudit(userPayload.id, 'UPDATE_CATEGORY', 'category', id, { name }, request);
				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}

		// DELETE /api/admin/categories/:id
		if (url.pathname.match(/^\/api\/admin\/categories\/\d+$/) && method === 'DELETE') {
			const id = url.pathname.split('/')[4];
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Brak autoryzacji' }, 403);

				// Check if there are posts in this category
				const count = await env.jimbo77_community_db.prepare('SELECT COUNT(*) as count FROM posts WHERE category_id = ?').bind(id).first<number>('count');
				if ((count ?? 0) > 0) {
					return jsonResponse({ error: 'Cannot delete category with existing posts' }, 400);
				}
				
				await env.jimbo77_community_db.prepare('DELETE FROM categories WHERE id = ?').bind(id).run();
				await security.logAudit(userPayload.id, 'DELETE_CATEGORY', 'category', id, {}, request);
				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}

		// --- ADMIN ROUTES ---

		// GET /api/admin/stats
		if (url.pathname === '/api/admin/stats' && method === 'GET') {
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Brak autoryzacji' }, 403);

				const [userCount, postCount, commentCount] = await Promise.all([
					env.jimbo77_community_db.prepare('SELECT COUNT(*) as count FROM users').first<number>('count'),
					env.jimbo77_community_db.prepare('SELECT COUNT(*) as count FROM posts').first<number>('count'),
					env.jimbo77_community_db.prepare('SELECT COUNT(*) as count FROM comments').first<number>('count')
				]);
				
				return jsonResponse({
					users: userCount,
					posts: postCount,
					comments: commentCount
				});
			} catch (e) {
				return handleError(e);
			}
		}

		// GET /api/admin/users
		if (url.pathname === '/api/admin/users' && method === 'GET') {
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Brak autoryzacji' }, 403);

				const { results } = await env.jimbo77_community_db.prepare('SELECT id, email, username, role, verified, created_at, avatar_url FROM users ORDER BY created_at DESC').all();
				return jsonResponse(results);
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/admin/users/:id/verify (Manual Verify)
		if (url.pathname.match(/^\/api\/admin\/users\/\d+\/verify$/) && method === 'POST') {
			const id = url.pathname.split('/')[4];
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Brak autoryzacji' }, 403);

				const { success } = await env.jimbo77_community_db.prepare('UPDATE users SET verified = 1, verification_token = NULL WHERE id = ?').bind(id).run();
				await security.logAudit(userPayload.id, 'MANUAL_VERIFY_USER', 'user', id, {}, request);

				// Notification
				const setting = await env.jimbo77_community_db.prepare("SELECT value FROM settings WHERE key = 'notify_on_manual_verify'").first<DBSetting>();
				if (setting && setting.value === '1') {
					const user = await env.jimbo77_community_db.prepare('SELECT email, username FROM users WHERE id = ?').bind(id).first<{email:string;username:string}>();
					if (!user) throw new Error('User unexpectedly missing');
					const emailHtml = `
						<h1>Konto zweryfikowane</h1>
						<p>Twoje konto (nazwa użytkownika: <strong>${user.username}</strong>) zostało ręcznie zweryfikowane przez administratora.</p>
						<p>Możesz się teraz zalogować i korzystać ze wszystkich funkcji.</p>
					`;
					ctx.waitUntil(sendEmail(user.email as string, 'Twoje konto zostało zweryfikowane', emailHtml, env).catch(console.error));
				}

				return jsonResponse({ success });
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/admin/users/:id/resend (Resend Verification Email)
		if (url.pathname.match(/^\/api\/admin\/users\/\d+\/resend$/) && method === 'POST') {
			const id = url.pathname.split('/')[4];
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Brak autoryzacji' }, 403);

				const user = await env.jimbo77_community_db.prepare('SELECT * FROM users WHERE id = ?').bind(id).first<DBUser>();
				if (!user) return jsonResponse({ error: 'Użytkownik nie znaleziony' }, 404);
				if (user.verified) return jsonResponse({ error: 'User already verified' }, 400);

				// Generate new token if needed, or use existing
				let token = user.verification_token;
				if (!token) {
					token = generateToken();
					await env.jimbo77_community_db.prepare('UPDATE users SET verification_token = ? WHERE id = ?').bind(token, id).run();
				}

				const baseUrl = getBaseUrl();
				const verifyLink = `${baseUrl}/api/verify?token=${token}`;
				const emailHtml = `
					<h1>Witaj na forum, ${user.username}!</h1>
					<p>Kliknij poniższy link, aby zweryfikować swój adres e-mail:</p>
					<a href="${verifyLink}">Zweryfikuj e-mail</a>
					<p>Jeśli nie prosiłeś o tę operację, zignoruj tego e-maila.</p>
				`;

				ctx.waitUntil(
					sendEmail(user.email, 'Zweryfikuj swój adres e-mail', emailHtml, env)
						.catch(err => console.error('[Background Email Error]', err))
				);
				
				await security.logAudit(userPayload.id, 'RESEND_VERIFY_EMAIL', 'user', id, {}, request);

				return jsonResponse({ success: true, message: 'E-mail weryfikacyjny został wysłany' });
			} catch (e) {
				return handleError(e);
			}
		}

		// DELETE /api/admin/users/:id
		if (url.pathname.startsWith('/api/admin/users/') && method === 'DELETE') {
			const id = url.pathname.split('/').pop();
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Brak autoryzacji' }, 403);

				// 0. Delete user avatar and post images
				const user = await env.jimbo77_community_db.prepare('SELECT avatar_url FROM users WHERE id = ?').bind(id).first<{avatar_url?: string}>();
				const posts = await env.jimbo77_community_db.prepare('SELECT content FROM posts WHERE author_id = ?').bind(id).all();
				
				const deletionPromises: Promise<any>[] = [];
				if (user && user.avatar_url) {
					deletionPromises.push(deleteImage(env as unknown as S3Env, user.avatar_url, id));
				}
				if (posts.results) {
					for (const post of posts.results) {
						const imageUrls = extractImageUrls(post.content as string);
						imageUrls.forEach(url => deletionPromises.push(deleteImage(env as unknown as S3Env, url, id)));
					}
				}
				if (deletionPromises.length > 0) {
					ctx.waitUntil(Promise.all(deletionPromises).catch(err => console.error('Failed to delete user images', err)));
				}

				// 1. Delete likes and comments ON the user's posts (to avoid orphans)
				await env.jimbo77_community_db.prepare('DELETE FROM likes WHERE post_id IN (SELECT id FROM posts WHERE author_id = ?)').bind(id).run();
				await env.jimbo77_community_db.prepare('DELETE FROM comments WHERE post_id IN (SELECT id FROM posts WHERE author_id = ?)').bind(id).run();

				// 2. Delete the user's own activity (likes and comments they made)
				await env.jimbo77_community_db.prepare('DELETE FROM likes WHERE user_id = ?').bind(id).run();
				await env.jimbo77_community_db.prepare('DELETE FROM comments WHERE author_id = ?').bind(id).run();

				// 3. Delete the user's posts
				await env.jimbo77_community_db.prepare('DELETE FROM posts WHERE author_id = ?').bind(id).run();

				// 4. Finally, delete the user
				const userToDelete = await env.jimbo77_community_db.prepare('SELECT email, username FROM users WHERE id = ?').bind(id).first();
				await env.jimbo77_community_db.prepare('DELETE FROM users WHERE id = ?').bind(id).run();
				
				await security.logAudit(userPayload.id, 'ADMIN_DELETE_USER', 'user', String(id), {}, request);

				// Notification
				if (userToDelete) {
					const setting = await env.jimbo77_community_db.prepare("SELECT value FROM settings WHERE key = 'notify_on_user_delete'").first();
					if (setting && setting.value === '1') {
						const emailHtml = `
							<h1>Konto zostało usunięte</h1>
							<p>Twoje konto (nazwa użytkownika: <strong>${userToDelete.username}</strong>) zostało usunięte przez administratora.</p>
							<p>Jeśli uważasz, że to pomyłka, skontaktuj się z administratorem.</p>
						`;
						ctx.waitUntil(sendEmail(userToDelete.email as string, 'Twoje konto zostało usunięte', emailHtml, env).catch(console.error));
					}
				}

				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}

		// DELETE /api/admin/posts/:id
		if (url.pathname.startsWith('/api/admin/posts/') && method === 'DELETE') {
			const id = url.pathname.split('/').pop();
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Brak autoryzacji' }, 403);

				// Delete images in post
				const post = await env.jimbo77_community_db.prepare('SELECT content, author_id FROM posts WHERE id = ?').bind(id).first();
				if (post) {
					const imageUrls = extractImageUrls(post.content as string);
					if (imageUrls.length > 0) {
						ctx.waitUntil(Promise.all(imageUrls.map(url => deleteImage(env as unknown as S3Env, url, post.author_id as number))).catch(err => console.error('Failed to delete post images', err)));
					}
				}

				await env.jimbo77_community_db.prepare('DELETE FROM likes WHERE post_id = ?').bind(id).run();
				await env.jimbo77_community_db.prepare('DELETE FROM comments WHERE post_id = ?').bind(id).run();
				await env.jimbo77_community_db.prepare('DELETE FROM posts WHERE id = ?').bind(id).run();
				
				await security.logAudit(userPayload.id, 'ADMIN_DELETE_POST', 'post', String(id), {}, request);
				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}

		// DELETE /api/admin/comments/:id
		if (url.pathname.startsWith('/api/admin/comments/') && method === 'DELETE') {
			const id = url.pathname.split('/').pop();
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Brak autoryzacji' }, 403);

				// Delete the comment AND its children (orphans prevention)
				await env.jimbo77_community_db.prepare('DELETE FROM comments WHERE parent_id = ?').bind(id).run();
				await env.jimbo77_community_db.prepare('DELETE FROM comments WHERE id = ?').bind(id).run();
				
				await security.logAudit(userPayload.id, 'ADMIN_DELETE_COMMENT', 'comment', String(id), {}, request);
				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/admin/posts/:id/pin
		if (url.pathname.match(/^\/api\/admin\/posts\/\d+\/pin$/) && method === 'POST') {
			const id = url.pathname.split('/')[4];
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Brak autoryzacji' }, 403);

				const body = await request.json() as any;
				const { pinned } = body;
				await env.jimbo77_community_db.prepare('UPDATE posts SET is_pinned = ? WHERE id = ?').bind(pinned ? 1 : 0, id).run();
				
				await security.logAudit(userPayload.id, 'ADMIN_PIN_POST', 'post', id, { pinned }, request);
				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/admin/posts/:id/move
		if (url.pathname.match(/^\/api\/admin\/posts\/\d+\/move$/) && method === 'POST') {
			const id = url.pathname.split('/')[4];
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Brak autoryzacji' }, 403);

				const body = await request.json() as any;
				const { category_id } = body;
				
				// Validate category exists if provided
				if (category_id) {
					const category = await env.jimbo77_community_db.prepare('SELECT id FROM categories WHERE id = ?').bind(category_id).first();
					if (!category) return jsonResponse({ error: 'Category not found' }, 404);
				}

				await env.jimbo77_community_db.prepare('UPDATE posts SET category_id = ? WHERE id = ?').bind(category_id || null, id).run();
				
				await security.logAudit(userPayload.id, 'ADMIN_MOVE_POST', 'post', id, { category_id }, request);
				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}

		// GET /api/admin/cleanup/analyze
		if (url.pathname === '/api/admin/cleanup/analyze' && method === 'GET') {
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Brak autoryzacji' }, 403);
                                
				// 1. List all S3 objects
				const allKeys = await listAllKeys(env as unknown as S3Env);
				
				// 2. Gather used URLs
				const usedKeys = new Set<string>();

				// Users avatars
				const users = await env.jimbo77_community_db.prepare('SELECT avatar_url FROM users WHERE avatar_url IS NOT NULL').all();
				for (const u of users.results) {
					const uUrl = u.avatar_url as string;
					const key = uUrl ? getKeyFromUrl(env as unknown as S3Env, uUrl) : null;
					if (key) usedKeys.add(key);
				}

				// Posts images
				const posts = await env.jimbo77_community_db.prepare('SELECT content FROM posts').all();
				for (const p of posts.results) {
					const urls = extractImageUrls(p.content as string);
					for (const uUrl of urls) {
						const key = uUrl ? getKeyFromUrl(env as unknown as S3Env, uUrl) : null;
						if (key) usedKeys.add(key);
					}
				}

				// 3. Find orphans
				const orphans = allKeys.filter(key => !usedKeys.has(key));

				return jsonResponse({ 
					total_files: allKeys.length,
					used_files: usedKeys.size,
					orphaned_files: orphans.length,
					orphans: orphans
				});

			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/admin/cleanup/execute
		if (url.pathname === '/api/admin/cleanup/execute' && method === 'POST') {
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Brak autoryzacji' }, 403);
				
				const body = await request.json() as any;
				const { orphans } = body;
				
				if (!orphans || !Array.isArray(orphans)) return jsonResponse({ error: 'Nieprawidłowe parametry' }, 400);

				const deletePromises = orphans.map(key => deleteImage(env as unknown as S3Env, key));
				
				ctx.waitUntil(Promise.all(deletePromises).catch(err => console.error('Cleanup failed', err)));
				
				return jsonResponse({ success: true, message: `Deletion of ${orphans.length} files started` });
			} catch (e) {
				return handleError(e);
			}
		}

		// GET /api/admin/audit-logs — view audit trail
		if (url.pathname === '/api/admin/audit-logs' && method === 'GET') {
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Brak autoryzacji' }, 403);

				const limit = parseInt(url.searchParams.get('limit') || '50');
				const offset = parseInt(url.searchParams.get('offset') || '0');
				const action = url.searchParams.get('action');
				const userId = url.searchParams.get('user_id');

				let query = `SELECT audit_logs.*, users.username
					 FROM audit_logs
					 LEFT JOIN users ON audit_logs.user_id = users.id`;
				let countQuery = `SELECT COUNT(*) as total FROM audit_logs`;
				const conditions: string[] = [];
				const params: any[] = [];
				const countParams: any[] = [];

				if (action) {
					conditions.push('audit_logs.action = ?');
					params.push(action);
					countParams.push(action);
				}
				if (userId) {
					conditions.push('audit_logs.user_id = ?');
					params.push(userId);
					countParams.push(userId);
				}

				if (conditions.length) {
					const where = ` WHERE ${conditions.join(' AND ')}`;
					query += where;
					countQuery += where;
				}

				query += ` ORDER BY audit_logs.created_at DESC LIMIT ? OFFSET ?`;
				params.push(limit, offset);

				const [logsResult, countResult] = await Promise.all([
					env.jimbo77_community_db.prepare(query).bind(...params).all(),
					env.jimbo77_community_db.prepare(countQuery).bind(...countParams).first()
				]);

				return jsonResponse({
					logs: logsResult.results,
					total: countResult ? (countResult as any).total : 0
				});
			} catch (e) {
				return handleError(e);
			}
		}

		// GET /api/user/sessions — list active sessions
		if (url.pathname === '/api/user/sessions' && method === 'GET') {
			try {
				const userPayload = await authenticate(request);
				const { results } = await env.jimbo77_community_db.prepare(
					'SELECT jti, created_at, expires_at FROM sessions WHERE user_id = ? AND expires_at > ? ORDER BY created_at DESC'
				).bind(userPayload.id, Math.floor(Date.now() / 1000)).all();
				return jsonResponse(results);
			} catch (e) {
				return handleError(e);
			}
		}

		// DELETE /api/user/sessions/:jti — revoke a specific session
		if (url.pathname.match(/^\/api\/user\/sessions\/[\w-]+$/) && method === 'DELETE') {
			const jti = url.pathname.split('/').pop();
			try {
				const userPayload = await authenticate(request);
				await env.jimbo77_community_db.prepare('DELETE FROM sessions WHERE jti = ? AND user_id = ?').bind(jti, userPayload.id).run();
				await security.logAudit(userPayload.id, 'REVOKE_SESSION', 'session', String(jti), {}, request);
				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/user/sessions/revoke-all — revoke all sessions except current
		if (url.pathname === '/api/user/sessions/revoke-all' && method === 'POST') {
			try {
				const userPayload = await authenticate(request);
				const authHeader = request.headers.get('Authorization');
				// We can't easily get the JTI from outside security module, so delete all and re-login is safer
				await env.jimbo77_community_db.prepare('DELETE FROM sessions WHERE user_id = ?').bind(userPayload.id).run();
				await security.logAudit(userPayload.id, 'REVOKE_ALL_SESSIONS', 'user', String(userPayload.id), {}, request);
				return jsonResponse({ success: true, message: 'All sessions revoked. Please log in again.' });
			} catch (e) {
				return handleError(e);
			}
		}

		// --- END ADMIN ROUTES ---

		// TEST: Email Debug
		if (url.pathname === '/api/test-email' && method === 'POST') {
			try {
				const body = await request.json() as any;
				const { to } = body;
				if (!to) return jsonResponse({ error: 'Brak adresu odbiorcy' }, 400);

				console.log('[DEBUG] Starting test email to:', to);
				await sendEmail(to, 'E-mail testowy', '<h1>Cześć</h1><p>To jest testowy e-mail.</p>', env);
				console.log('[DEBUG] Test email sent successfully');
				
				return jsonResponse({ success: true, message: 'E-mail został wysłany' });
			} catch (e) {
				console.error('[DEBUG] Test email failed:', e);
				return handleError(e);
			}
		}

		// AUTH: Register
		if (url.pathname === '/api/register' && method === 'POST') {
			try {
				const body = await request.json() as any;

				// Turnstile Check
				const ip = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
				if (!(await checkTurnstile(body, ip))) {
					return jsonResponse({ error: 'Weryfikacja CAPTCHA nie powiodła się' }, 403);
				}

				const { email, username, password } = body;
				if (!email || !username || !password) {
					return jsonResponse({ error: 'Wypełnij wszystkie pola (e-mail, nazwa, hasło)' }, 400);
				}

				if (email.length > 50) return jsonResponse({ error: 'E-mail max 50 znaków' }, 400);

				if (username.length > 20) return jsonResponse({ error: 'Nazwa użytkownika max 20 znaków' }, 400);
				if (isVisuallyEmpty(username)) return jsonResponse({ error: 'Nazwa użytkownika nie może być pusta' }, 400);
				if (hasInvisibleCharacters(username)) return jsonResponse({ error: 'Nazwa zawiera niedozwolone niewidoczne znaki' }, 400);
				if (hasControlCharacters(username)) return jsonResponse({ error: 'Nazwa zawiera niedozwolone znaki sterujące' }, 400);
				if (hasRestrictedKeywords(username)) return jsonResponse({ error: 'Nazwa zawiera zastrzeżone słowa kluczowe' }, 400);

				if (password.length < 8 || password.length > 16) return jsonResponse({ error: 'Hasło musi mieć 8–16 znaków' }, 400);

				// Check Uniqueness (Combined Query for Performance)
				const existing = await env.jimbo77_community_db.prepare('SELECT email, username FROM users WHERE email = ? OR username = ?').bind(email, username).first();
				if (existing) {
					if (existing.email === email) return jsonResponse({ error: 'Ten e-mail jest już zarejestrowany' }, 409);
					return jsonResponse({ error: 'Ta nazwa użytkownika jest już zajęta' }, 409);
				}

				const passwordHash = await hashPassword(password);
				const verificationToken = generateToken();

				// Try to send verification email; if SMTP fails → auto-verify
				let emailSent = false;
				let autoVerified = false;
				const baseUrl = getBaseUrl();
				const verifyLink = `${baseUrl}/api/verify?token=${verificationToken}`;
				
				const emailHtml = `
					<h1>Witaj na forum, ${username}!</h1>
					<p>Kliknij poniższy link, aby zweryfikować swój adres e-mail:</p>
					<a href="${verifyLink}">Zweryfikuj e-mail</a>
					<p>Jeśli nie prosiłeś o tę operację, zignoruj tego e-maila.</p>
				`;

				try {
					await sendEmail(email, 'Zweryfikuj swój adres e-mail', emailHtml, env);
					emailSent = true;
				} catch (e) {
					console.warn('[Registration] Email send failed, auto-verifying user:', e instanceof Error ? e.message : e);
					autoVerified = true;
				}

				// If email was sent → verified=0 (wait for click). If email failed → verified=1 (auto-activate)
				const verifiedFlag = autoVerified ? 1 : 0;
				const tokenOrNull = autoVerified ? null : verificationToken;

				const { success, meta } = await env.jimbo77_community_db.prepare(
					'INSERT INTO users (email, username, password, role, verified, verification_token) VALUES (?, ?, ?, "user", ?, ?)'
				).bind(email, username, passwordHash, verifiedFlag, tokenOrNull).run();

				if (success) {
					// Generate Default Avatar (Identicon)
					const userId = meta?.last_row_id;
					if (userId) {
						const identicon = await generateIdenticon(String(userId));
						await env.jimbo77_community_db.prepare('UPDATE users SET avatar_url = ? WHERE id = ?').bind(identicon, userId).run();
					} else {
						const identicon = await generateIdenticon(username);
						await env.jimbo77_community_db.prepare('UPDATE users SET avatar_url = ? WHERE username = ?').bind(identicon, username).run();
					}
				}

				const message = autoVerified
					? 'Rejestracja udana — konto aktywne, możesz się zalogować!'
					: 'Rejestracja udana — sprawdź e-mail, aby dokończyć weryfikację.';

				return jsonResponse({ success, message, auto_verified: autoVerified }, 201);
			} catch (e: any) {
				if (e.message && e.message.includes('UNIQUE constraint failed')) {
					return jsonResponse({ error: 'Ten e-mail jest już zarejestrowany' }, 409);
				}
				return handleError(e);
			}
		}

		// AUTH: Verify Email
		if (url.pathname === '/api/verify' && method === 'GET') {
			const token = url.searchParams.get('token');
			if (!token) {
				return new Response('Brak tokena', { status: 400 });
			}

			try {
				const { success } = await env.jimbo77_community_db.prepare(
					'UPDATE users SET verified = 1, verification_token = NULL WHERE verification_token = ?'
				).bind(token).run();

				if (success) {
					// Redirect to home page with verified param
					return Response.redirect(`${getBaseUrl()}/?verified=true`, 302);
				} else {
					return new Response('Token nieprawidłowy lub wygasł', { status: 400 });
				}
			} catch (e) {
				return new Response('Weryfikacja nie powiodła się', { status: 500 });
			}
		}

		// GET /users
		if (url.pathname === '/api/users' && method === 'GET') {
			try {
				// Wymaga uwierzytelnienia — tylko admin widzi pełną listę z e-mailami
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') {
					// Zwykły user widzi tylko id, username, avatar
					const { results } = await env.jimbo77_community_db.prepare(
						'SELECT id, username, avatar_url, created_at FROM users'
					).all();
					return jsonResponse(results);
				}
				const { results } = await env.jimbo77_community_db.prepare(
					'SELECT id, email, username, avatar_url, role, verified, created_at FROM users'
				).all();
				return jsonResponse(results);
			} catch (e) {
				return handleError(e);
			}
		}

		// GET /api/user/likes (Get all post IDs liked by user)
		if (url.pathname === '/api/user/likes' && method === 'GET') {
			try {
				const userPayload = await authenticate(request);
				const { results } = await env.jimbo77_community_db.prepare('SELECT post_id FROM likes WHERE user_id = ?').bind(userPayload.id).all();
				return jsonResponse(results.map((r: any) => r.post_id));
			} catch (e) {
				return handleError(e);
			}
		}

		// GET /posts
		if (url.pathname === '/api/posts' && method === 'GET') {
			try {
				const limit = parseInt(url.searchParams.get('limit') || '20');
				const offset = parseInt(url.searchParams.get('offset') || '0');
				const categoryId = url.searchParams.get('category_id');
				const q = (url.searchParams.get('q') || url.searchParams.get('query') || '').trim();
				const sortByRaw = (url.searchParams.get('sort_by') || 'time').trim().toLowerCase();
				const sortDirRaw = (url.searchParams.get('sort_dir') || 'desc').trim().toLowerCase();
				const sortDir = sortDirRaw === 'asc' ? 'ASC' : 'DESC';
				
				let query = `SELECT 
                        posts.*, 
                        users.username as author_name, 
                        users.avatar_url as author_avatar,
                        users.role as author_role,
                        categories.name as category_name,
                        (SELECT COUNT(*) FROM likes WHERE likes.post_id = posts.id) as like_count,
                        (SELECT COUNT(*) FROM comments WHERE comments.post_id = posts.id) as comment_count
                     FROM posts 
                     JOIN users ON posts.author_id = users.id 
                     LEFT JOIN categories ON posts.category_id = categories.id`;
                
                let countQuery = `SELECT COUNT(*) as total FROM posts`;

                const params: any[] = [];
                const countParams: any[] = [];
				const conditions: string[] = [];

                if (categoryId) {
                    if (categoryId === 'uncategorized') {
						conditions.push(`posts.category_id IS NULL`);
                    } else {
						conditions.push(`posts.category_id = ?`);
                        params.push(categoryId);
                        countParams.push(categoryId);
                    }
                }

				if (q) {
					conditions.push(`(posts.title LIKE ? OR posts.content LIKE ?)`);
					const like = `%${q}%`;
					params.push(like, like);
					countParams.push(like, like);
				}

				if (conditions.length) {
					query += ` WHERE ${conditions.join(' AND ')}`;
					countQuery += ` WHERE ${conditions.join(' AND ')}`;
				}

				const sortExpr =
					sortByRaw === 'likes'
						? `like_count ${sortDir}`
						: sortByRaw === 'comments'
							? `comment_count ${sortDir}`
							: sortByRaw === 'views'
								? `posts.view_count ${sortDir}`
								: `posts.created_at ${sortDir}`;

                query += ` ORDER BY is_pinned DESC, ${sortExpr}, posts.created_at DESC LIMIT ? OFFSET ?`;
                params.push(limit, offset);
				
				const [postsResult, countResult] = await Promise.all([
                    env.jimbo77_community_db.prepare(query).bind(...params).all(),
                    env.jimbo77_community_db.prepare(countQuery).bind(...countParams).first()
                ]);

				return jsonResponse({
                    posts: postsResult.results,
                    total: countResult ? countResult.total : 0
                });
			} catch (e) {
				return handleError(e);
			}
		}

		// GET /api/posts/:id
		if (url.pathname.match(/^\/api\/posts\/\d+$/) && method === 'GET') {
			const postId = url.pathname.split('/')[3];
			try {
				const post = await env.jimbo77_community_db.prepare(
					`SELECT 
                        posts.*, 
                        users.username as author_name, 
                        users.avatar_url as author_avatar,
                        users.role as author_role,
                        categories.name as category_name,
                        (SELECT COUNT(*) FROM likes WHERE likes.post_id = posts.id) as like_count,
                        (SELECT COUNT(*) FROM comments WHERE comments.post_id = posts.id) as comment_count
                     FROM posts 
                     JOIN users ON posts.author_id = users.id 
                     LEFT JOIN categories ON posts.category_id = categories.id
                     WHERE posts.id = ?`
				).bind(postId).first();
				
				if (!post) return jsonResponse({ error: 'Post nie znaleziony' }, 404);

				try {
					await env.jimbo77_community_db.prepare('UPDATE posts SET view_count = COALESCE(view_count, 0) + 1 WHERE id = ?').bind(postId).run();
					(post as any).view_count = Number((post as any).view_count || 0) + 1;
				} catch {}
				
				// Check like status if user_id provided
				const userId = url.searchParams.get('user_id');
				if (userId) {
					const like = await env.jimbo77_community_db.prepare('SELECT id FROM likes WHERE post_id = ? AND user_id = ?').bind(postId, userId).first();
					(post as any).liked = !!like;
				}

				return jsonResponse(post);
			} catch (e) {
				return handleError(e);
			}
		}

		// PUT /api/posts/:id
		if (url.pathname.match(/^\/api\/posts\/\d+$/) && method === 'PUT') {
			const postId = url.pathname.split('/')[3];
			try {
				const userPayload = await authenticate(request);
				const body = await request.json() as any;
				const { title, content, category_id } = body; // user_id not needed from body

				if (!title || !content) {
					return jsonResponse({ error: 'Podaj tytuł i treść posta' }, 400);
				}

				if (isVisuallyEmpty(title) || isVisuallyEmpty(content)) return jsonResponse({ error: 'Tytuł lub treść nie mogą być puste' }, 400);

				if (hasInvisibleCharacters(title) || hasInvisibleCharacters(content)) return jsonResponse({ error: 'Title or content contains invalid invisible characters' }, 400);

				// Check ownership or admin
				const post = await env.jimbo77_community_db.prepare('SELECT author_id FROM posts WHERE id = ?').bind(postId).first();
				if (!post) return jsonResponse({ error: 'Post nie znaleziony' }, 404);

				// Use userPayload for RBAC
				if (post.author_id !== userPayload.id && userPayload.role !== 'admin') {
					return jsonResponse({ error: 'Brak autoryzacji' }, 403);
				}

				// Validate Lengths
				if (title.length > 30) return jsonResponse({ error: 'Title too long (Max 30 chars)' }, 400);
				if (content.length > 3000) return jsonResponse({ error: 'Content too long (Max 3000 chars)' }, 400);
				if (hasControlCharacters(title) || hasControlCharacters(content)) return jsonResponse({ error: 'Title or content contains invalid control characters' }, 400);

				// Validate Category
				if (category_id) {
					const category = await env.jimbo77_community_db.prepare('SELECT id FROM categories WHERE id = ?').bind(category_id).first();
					if (!category) return jsonResponse({ error: 'Category not found' }, 400);
				}

				await env.jimbo77_community_db.prepare(
					'UPDATE posts SET title = ?, content = ?, category_id = ? WHERE id = ?'
				).bind(title.trim(), content.trim(), category_id || null, postId).run();
				
				await security.logAudit(userPayload.id, 'UPDATE_POST', 'post', postId, { title_length: title.length }, request);

				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}

		// DELETE /api/posts/:id (User delete own post)
		if (url.pathname.match(/^\/api\/posts\/\d+$/) && method === 'DELETE') {
			const id = url.pathname.split('/')[3];
			try {
				const userPayload = await authenticate(request);
				
				// Check ownership
				const post = await env.jimbo77_community_db.prepare('SELECT author_id, content FROM posts WHERE id = ?').bind(id).first();
				if (!post) return jsonResponse({ error: 'Post nie znaleziony' }, 404);
				
				if (post.author_id !== userPayload.id) {
					return jsonResponse({ error: 'Brak autoryzacji' }, 403);
				}

				// Delete images in post
				const imageUrls = extractImageUrls(post.content as string);
				if (imageUrls.length > 0) {
					ctx.waitUntil(Promise.all(imageUrls.map(url => deleteImage(env as unknown as S3Env, url, userPayload.id))).catch(err => console.error('Failed to delete post images', err)));
				}

				await env.jimbo77_community_db.prepare('DELETE FROM likes WHERE post_id = ?').bind(id).run();
				await env.jimbo77_community_db.prepare('DELETE FROM comments WHERE post_id = ?').bind(id).run();
				await env.jimbo77_community_db.prepare('DELETE FROM posts WHERE id = ?').bind(id).run();
				
				await security.logAudit(userPayload.id, 'DELETE_POST', 'post', id, {}, request);
				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}

		// GET /api/posts/:id/comments
		if (url.pathname.match(/^\/api\/posts\/\d+\/comments$/) && method === 'GET') {
			const postId = url.pathname.split('/')[3];
			try {
				const { results } = await env.jimbo77_community_db.prepare(
					`SELECT comments.*, users.username, users.avatar_url, users.role 
                     FROM comments 
                     JOIN users ON comments.author_id = users.id 
                     WHERE post_id = ? 
                     ORDER BY created_at ASC`
				).bind(postId).all();
				return jsonResponse(results);
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/posts/:id/comments (create comment)
		if (url.pathname.match(/^\/api\/posts\/\d+\/comments$/) && method === 'POST') {
			const postId = url.pathname.split('/')[3];
			try {
				const userPayload = await authenticate(request);
				const body = await request.json() as any;
				let { content, parent_id } = body;

				if (!content) return jsonResponse({ error: 'Podaj treść komentarza' }, 400);
				if (isVisuallyEmpty(content)) return jsonResponse({ error: 'Comment cannot be empty' }, 400);
				if (hasInvisibleCharacters(content)) return jsonResponse({ error: 'Comment contains invalid invisible characters' }, 400);
				if (hasControlCharacters(content)) return jsonResponse({ error: 'Comment contains invalid control characters' }, 400);
				if (content.length > 1000) return jsonResponse({ error: 'Comment too long (Max 1000 chars)' }, 400);

				// Verify post exists
				const post = await env.jimbo77_community_db.prepare('SELECT id, title, author_id FROM posts WHERE id = ?').bind(postId).first();
				if (!post) return jsonResponse({ error: 'Post nie znaleziony' }, 404);

				// Verify parent comment exists (if replying)
				if (parent_id) {
					const parent = await env.jimbo77_community_db.prepare('SELECT id FROM comments WHERE id = ? AND post_id = ?').bind(parent_id, postId).first();
					if (!parent) return jsonResponse({ error: 'Parent comment not found' }, 404);
				}

				// HTML escape
				content = content
					.replace(/&/g, '&amp;')
					.replace(/</g, '&lt;')
					.replace(/>/g, '&gt;')
					.replace(/"/g, '&quot;')
					.replace(/'/g, '&#039;');

				const { success, meta } = await env.jimbo77_community_db.prepare(
					'INSERT INTO comments (post_id, parent_id, author_id, content) VALUES (?, ?, ?, ?)'
				).bind(postId, parent_id || null, userPayload.id, content.trim()).run();

				await security.logAudit(userPayload.id, 'CREATE_COMMENT', 'comment', String(meta?.last_row_id || 'new'), { post_id: postId }, request);

				// Email notification to post author (background)
				if (post.author_id !== userPayload.id) {
					const postAuthor = await env.jimbo77_community_db.prepare(
						'SELECT email, username, email_notifications FROM users WHERE id = ?'
					).bind(post.author_id).first<{ email: string; username: string; email_notifications: number }>();
					if (postAuthor && postAuthor.email_notifications) {
						const commenterUser = await env.jimbo77_community_db.prepare('SELECT username FROM users WHERE id = ?').bind(userPayload.id).first<{ username: string }>();
						const emailHtml = `
							<h1>Nowy komentarz do Twojego posta</h1>
							<p><strong>${commenterUser?.username || 'Użytkownik'}</strong> skomentował Twój post "${post.title}".</p>
							<p>Zaloguj się, aby zobaczyć komentarz.</p>
						`;
						ctx.waitUntil(sendEmail(postAuthor.email, 'Nowy komentarz do Twojego posta', emailHtml, env).catch(console.error));
					}
				}

				// Return the new comment with user data
				const newComment = await env.jimbo77_community_db.prepare(
					`SELECT comments.*, users.username, users.avatar_url, users.role
					 FROM comments JOIN users ON comments.author_id = users.id
					 WHERE comments.id = ?`
				).bind(meta?.last_row_id).first();

				return jsonResponse(newComment || { success }, 201);
			} catch (e) {
				return handleError(e);
			}
		}

		// DELETE /api/comments/:id
		if (url.pathname.match(/^\/api\/comments\/\d+$/) && method === 'DELETE') {
			const id = url.pathname.split('/').pop();
			try {
				const userPayload = await authenticate(request);
				
				// Fetch comment to check ownership
				const comment = await env.jimbo77_community_db.prepare('SELECT author_id FROM comments WHERE id = ?').bind(id).first();
				
				if (!comment) return jsonResponse({ error: 'Komentarz nie znaleziony' }, 404);

				// Allow deletion if user is author OR admin
				if (comment.author_id !== userPayload.id && userPayload.role !== 'admin') {
					return jsonResponse({ error: 'Brak autoryzacji' }, 403);
				}

				// Delete the comment AND its children (orphans prevention)
				await env.jimbo77_community_db.prepare('DELETE FROM comments WHERE parent_id = ?').bind(id).run();
				await env.jimbo77_community_db.prepare('DELETE FROM comments WHERE id = ?').bind(id).run();
				
				await security.logAudit(userPayload.id, 'DELETE_COMMENT', 'comment', String(id), {}, request);
				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/posts/:id/like
		if (url.pathname.match(/^\/api\/posts\/\d+\/like$/) && method === 'POST') {
			const postId = url.pathname.split('/')[3];
			try {
				const userPayload = await authenticate(request);
				const userId = userPayload.id;

				// Toggle like
				const existing = await env.jimbo77_community_db.prepare(
					'SELECT id FROM likes WHERE post_id = ? AND user_id = ?'
				).bind(postId, userId).first();

				if (existing) {
					await env.jimbo77_community_db.prepare('DELETE FROM likes WHERE id = ?').bind(existing.id).run();
					return jsonResponse({ liked: false });
				} else {
					await env.jimbo77_community_db.prepare('INSERT INTO likes (post_id, user_id) VALUES (?, ?)').bind(postId, userId).run();
					return jsonResponse({ liked: true });
				}
			} catch (e) {
				return handleError(e);
			}
		}
		
		// GET /api/posts/:id/like-status
		if (url.pathname.match(/^\/api\/posts\/\d+\/like-status$/) && method === 'GET') {
			const postId = url.pathname.split('/')[3];
			
			try {
				const userPayload = await authenticate(request);
				const existing = await env.jimbo77_community_db.prepare(
					'SELECT id FROM likes WHERE post_id = ? AND user_id = ?'
				).bind(postId, userPayload.id).first();
				return jsonResponse({ liked: !!existing });
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /posts (Protected - in real app check token)
		if (url.pathname === '/api/posts' && method === 'POST') {
			try {
				const userPayload = await authenticate(request);
				const body = await request.json() as any;

				// Turnstile Check
				const ip = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
				if (!(await checkTurnstile(body, ip))) {
					return jsonResponse({ error: 'Turnstile verification failed' }, 403);
				}

				const { title, content: rawContent, category_id } = body;
				let content = rawContent;
				
				if (!title || !content) {
					return jsonResponse({ error: 'Podaj tytuł i treść' }, 400);
				}
				
				// --- Input Sanitization & Validation (Sync with Frontend) ---
				if (isVisuallyEmpty(title) || isVisuallyEmpty(content)) return jsonResponse({ error: 'Title or content cannot be empty' }, 400);
				
				if (hasInvisibleCharacters(title) || hasInvisibleCharacters(content)) return jsonResponse({ error: 'Title or content contains invalid invisible characters' }, 400);

				// Validate Lengths
				if (title.length > 30) return jsonResponse({ error: 'Title too long (Max 30 chars)' }, 400);
				if (content.length > 3000) return jsonResponse({ error: 'Content too long (Max 3000 chars)' }, 400);

				if (hasControlCharacters(title) || hasControlCharacters(content)) return jsonResponse({ error: 'Title or content contains invalid control characters' }, 400);

				// HTML Escape Content (Backend Enforcement)
				content = content
					.replace(/&/g, '&amp;')
					.replace(/</g, '&lt;')
					.replace(/>/g, '&gt;')
					.replace(/"/g, '&quot;')
					.replace(/'/g, '&#039;');
				
				// Escape Title as well just in case
				const safeTitle = title
					.replace(/&/g, '&amp;')
					.replace(/</g, '&lt;')
					.replace(/>/g, '&gt;')
					.replace(/"/g, '&quot;')
					.replace(/'/g, '&#039;');

				// Validate Category
				if (category_id) {
					const category = await env.jimbo77_community_db.prepare('SELECT id FROM categories WHERE id = ?').bind(category_id).first();
					if (!category) return jsonResponse({ error: 'Category not found' }, 400);
				}

				const { success } = await env.jimbo77_community_db.prepare(
					'INSERT INTO posts (author_id, title, content, category_id) VALUES (?, ?, ?, ?)'
				).bind(userPayload.id, safeTitle.trim(), content.trim(), category_id || null).run();
				
				await security.logAudit(userPayload.id, 'CREATE_POST', 'post', 'new', { title_length: safeTitle.length }, request);

				return jsonResponse({ success }, 201);
			} catch (e) {
				return handleError(e);
			}
		}

		if (method === 'GET' && !url.pathname.startsWith('/api')) {
			const pathname = url.pathname;
			const postMatch = pathname.match(/^\/posts\/(\d+)$/);
			if (postMatch) {
				const redirectUrl = new URL(request.url);
				redirectUrl.pathname = '/post';
				redirectUrl.search = `?id=${postMatch[1]}`;
				return Response.redirect(redirectUrl.toString(), 302);
			}
			const postAltMatch = pathname.match(/^\/post\/(\d+)$/);
			if (postAltMatch) {
				const redirectUrl = new URL(request.url);
				redirectUrl.pathname = '/post';
				redirectUrl.search = `?id=${postAltMatch[1]}`;
				return Response.redirect(redirectUrl.toString(), 302);
			}

			if (!(env as any).ASSETS?.fetch) return new Response('Not Found', { status: 404 });
			const mapped =
				pathname === '/login' ? '/login.html' :
				pathname === '/register' ? '/register.html' :
				pathname === '/forgot' ? '/forgot.html' :
				pathname === '/reset' ? '/reset.html' :
				pathname === '/settings' ? '/settings.html' :
				pathname === '/admin' ? '/admin.html' :
				pathname === '/post' ? '/post.html' :
				pathname;

			const assetUrl = new URL(request.url);
			assetUrl.pathname = mapped;
			const assetRes = await (env as any).ASSETS.fetch(new Request(assetUrl, request));
			if (assetRes.status !== 404) return assetRes;
			if (mapped !== pathname) {
				const directRes = await (env as any).ASSETS.fetch(request);
				if (directRes.status !== 404) return directRes;
			}
			return new Response('Not Found', { status: 404 });
		}

		return new Response('Not Found', { status: 404 });
	}
};
