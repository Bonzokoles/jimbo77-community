export function formatDate(date: string | number | null | undefined): string {
	if (!date) return '';
	try {
		return new Intl.DateTimeFormat('pl-PL', {
			year: 'numeric',
			month: 'short',
			day: 'numeric',
			hour: '2-digit',
			minute: '2-digit'
		}).format(new Date(date));
	} catch {
		return String(date);
	}
}

export function getSecurityHeaders(method: string, contentType?: string | null): Record<string, string> {
	const headers: Record<string, string> = {};
	if (contentType !== null) {
		headers['Content-Type'] = contentType ?? 'application/json';
	}
	if (['POST', 'PUT', 'DELETE'].includes(method.toUpperCase())) {
		headers['X-Timestamp'] = String(Math.floor(Date.now() / 1000));
		headers['X-Nonce'] = crypto.randomUUID();
	}
	return headers;
}

export async function apiFetch<T = unknown>(path: string, init?: RequestInit): Promise<T> {
	const token = typeof window !== 'undefined' ? localStorage.getItem('auth_token') : null;
	const headers: Record<string, string> = {
		...(init?.headers as Record<string, string> | undefined)
	};
	if (token) headers['Authorization'] = `Bearer ${token}`;
	const res = await fetch(`/api${path}`, { ...init, headers });
	if (!res.ok) {
		let msg = `Błąd ${res.status}`;
		try {
			const body = await res.text();
			if (body) {
				try {
					const json = JSON.parse(body);
					msg = json?.error || json?.message || body;
				} catch {
					msg = body;
				}
			}
		} catch {}
		throw new Error(msg);
	}
	const text = await res.text();
	if (!text) return undefined as T;
	return JSON.parse(text) as T;
}

export interface Category {
	id: number;
	name: string;
	description?: string;
}

export interface Post {
	id: number;
	title: string;
	content: string;
	author_name: string;
	author_avatar?: string;
	author_role?: string;
	category_name?: string;
	created_at: string;
	like_count?: number;
	comment_count?: number;
	view_count?: number;
	is_pinned?: boolean;
}

export interface Comment {
	id: number;
	content: string;
	author_name: string;
	author_avatar?: string;
	author_role?: string;
	created_at: string;
	like_count?: number;
}
