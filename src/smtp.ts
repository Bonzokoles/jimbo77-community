
import { connect } from 'cloudflare:sockets';

const DEFAULT_FROM_NAME = '论坛管理员';

// Timeout helper
function withTimeout<T>(promise: Promise<T>, ms: number, errorMsg: string): Promise<T> {
    return Promise.race([
        promise,
        new Promise<T>((_, reject) => 
            setTimeout(() => reject(new Error(errorMsg)), ms)
        )
    ]);
}

// SMTP configuration will be pulled from environment variables when
// sendViaSMTP is invoked.  There is no hardcoded secret in source control.
// Expected env vars:
//   SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM, SMTP_FROM_NAME

interface SmtpConfig {
    hostname: string;
    port: number;
    user: string;
    pass: string;
    from: string;
    fromName: string;
}

function getSmtpConfig(env: any): SmtpConfig {
    const hostname = env.SMTP_HOST;
    const port = Number(env.SMTP_PORT || 0);
    const user = env.SMTP_USER;
    const pass = env.SMTP_PASS;
    const from = env.SMTP_FROM || user;
    const fromName = env.SMTP_FROM_NAME || DEFAULT_FROM_NAME;

    if (!hostname) {
        throw new Error('SMTP_HOST environment variable is not set');
    }
    if (!port || port <= 0) {
        throw new Error('SMTP_PORT environment variable is not set or invalid');
    }
    if (!user) {
        throw new Error('SMTP_USER environment variable is not set');
    }
    if (!pass) {
        throw new Error('SMTP_PASS environment variable is not set');
    }
    
    console.log(`[SMTP Config] Host: ${hostname}:${port}, User: ${user}, From: ${from}`);
    return { hostname, port, user, pass, from, fromName };
}

// Helper to check MX records via DNS-over-HTTPS (Cloudflare DNS)
async function checkMX(email: string): Promise<boolean> {
    const domain = email.split('@')[1];
    if (!domain) return false;

    try {
        console.log(`[MX Check] Checking MX records for ${domain}...`);
        const res = await withTimeout(
            fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=MX`, {
                headers: { 'Accept': 'application/dns-json' }
            }),
            5000,
            `MX check timeout for ${domain}`
        );
        
        if (!res.ok) {
            console.warn(`[MX Check] DoH API failed for ${domain}, skipping check.`);
            return true; // Fail open if API is down
        }
        
        const data: any = await res.json();
        
        // Status 0 means NOERROR. 
        // If Status is NXDOMAIN (3), domain doesn't exist.
        if (data.Status !== 0) {
             console.error(`[MX Check] DNS Error for ${domain}: Status ${data.Status}`);
             return false;
        }
        
        // Check if Answer exists and has entries
        // Note: Some domains might rely on A record fallback, but it's rare and bad practice.
        // We strictly check for MX records as requested.
        // Cloudflare returns "Answer" array if records exist.
        if (!data.Answer || !Array.isArray(data.Answer) || data.Answer.length === 0) {
             console.error(`[MX Check] No MX records found for ${domain}`);
             return false;
        }

        console.log(`[MX Check] ✓ Found ${data.Answer.length} MX record(s) for ${domain}`);
        return true;
    } catch (e) {
        console.error(`[MX Check] Failed to resolve MX for ${domain}`, e);
        return true; // Fail open on network error
    }
}

// Simple helper to send a command and wait for expected response code
async function sendCommand(
    writer: WritableStreamDefaultWriter<Uint8Array>,
    reader: ReadableStreamDefaultReader<Uint8Array>,
    command: string | null,
    expectedCode: number
): Promise<string> {
    if (command) {
        console.log(`[SMTP] Sending: ${command.startsWith('PASS') || command.startsWith('AUTH') ? '***' : command}`);
        await writer.write(new TextEncoder().encode(command + '\r\n'));
    } else {
        console.log(`[SMTP] Waiting for initial greeting...`);
    }

    let response = '';
    const decoder = new TextDecoder();
    
    const readResponse = async () => {
        while (true) {
            const { value, done } = await reader.read();
            if (done) {
                console.error('[SMTP] Connection closed unexpectedly');
                throw new Error('Connection closed unexpectedly');
            }
            
            const chunk = decoder.decode(value, { stream: true });
            response += chunk;
            
            // Check if we have a full response line
            if (response.endsWith('\n')) {
                const lines = response.split('\n').map(l => l.trim()).filter(l => l.length > 0);
                if (lines.length > 0) {
                    const lastLine = lines[lines.length - 1];
                    if (lastLine.match(/^\d{3} /)) {
                        break;
                    }
                }
            }
        }
        return response;
    };
    
    // Add 10 second timeout for each command
    response = await withTimeout(
        readResponse(),
        10000,
        `SMTP command timeout: ${command || 'greeting'}`
    );
    
    console.log(`[SMTP] Response: ${response.trim()}`);

    const lastLine = response.trim().split('\n').pop()?.trim();
    if (!lastLine?.startsWith(String(expectedCode))) {
        throw new Error(`SMTP Error: Expected ${expectedCode}, got ${response}`);
    }
    return response;
}

// Helper to encode headers (RFC 2047) if they contain non-ASCII characters
function encodeHeader(str: string): string {
    // Check if string contains only ASCII (printable)
    if (/^[\x20-\x7E]*$/.test(str)) {
        return str;
    }
    
    // Use Base64 encoding for UTF-8
    const utf8Bytes = new TextEncoder().encode(str);
    const binary = String.fromCharCode(...utf8Bytes);
    const base64 = btoa(binary);
    
    return `=?UTF-8?B?${base64}?=`;
}

// SMTP Send Function
async function sendViaSMTP(to: string, subject: string, htmlContent: string, env: any) {
    const SMTP_CONFIG = getSmtpConfig(env);
    console.log(`[SMTP] Connecting to ${SMTP_CONFIG.hostname}:${SMTP_CONFIG.port}...`);
    
    const socket = connect({ 
        hostname: SMTP_CONFIG.hostname, 
        port: SMTP_CONFIG.port 
    }, { 
        secureTransport: 'on',
        allowHalfOpen: false
    });

    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();

    try {
        // Initial greeting
        await sendCommand(writer, reader, null, 220);
        
        // EHLO to get server capabilities (use sender's domain)
        const senderDomain = SMTP_CONFIG.from.split('@')[1] || 'localhost';
        const ehloResponse = await sendCommand(writer, reader, `EHLO ${senderDomain}`, 250);
        console.log('[SMTP] Server capabilities:', ehloResponse.trim());
        
        // Use AUTH LOGIN (most reliable and widely supported)
        let authSuccess = false;
        
        try {
            console.log('[SMTP] Attempting AUTH LOGIN authentication...');
            await sendCommand(writer, reader, 'AUTH LOGIN', 334);
            await sendCommand(writer, reader, btoa(SMTP_CONFIG.user), 334);
            await sendCommand(writer, reader, btoa(SMTP_CONFIG.pass), 235);
            console.log('[SMTP] ✓ AUTH LOGIN successful');
            authSuccess = true;
        } catch (loginError) {
            console.warn('[SMTP] AUTH LOGIN failed, trying AUTH PLAIN...', loginError);
            
            // Fallback to AUTH PLAIN (one-line format)
            // Format: base64(\0username\0password)
            try {
                const authPlain = '\0' + SMTP_CONFIG.user + '\0' + SMTP_CONFIG.pass;
                const authPlainB64 = btoa(authPlain);
                await sendCommand(writer, reader, `AUTH PLAIN ${authPlainB64}`, 235);
                console.log('[SMTP] ✓ AUTH PLAIN successful');
                authSuccess = true;
            } catch (plainError) {
                console.error('[SMTP] Both AUTH LOGIN and AUTH PLAIN failed');
            }
        }
        
        if (!authSuccess) {
            throw new Error(`SMTP 认证失败。请检查：\n1. SMTP_USER 和 SMTP_PASS 是否正确\n2. 是否使用了应用专用密码（QQ企业邮箱、Gmail等需要）\n3. 邮箱服务器是否限制了登录（如频繁失败导致临时锁定）`);
        }
        
        await sendCommand(writer, reader, `MAIL FROM: <${SMTP_CONFIG.from}>`, 250);
        await sendCommand(writer, reader, `RCPT TO: <${to}>`, 250);
        await sendCommand(writer, reader, 'DATA', 354);

        const boundary = 'boundary_' + Date.now();
        const messageId = `<${Date.now()}@${senderDomain}>`;
        const date = new Date().toUTCString();
        
        // Encode Subject if necessary
        const encodedSubject = encodeHeader(subject);

        // IMPORTANT: SMTP requires CRLF (\r\n) for line breaks
        // Added Message-ID and Date headers to comply with stricter spam filters (like Cloudflare Email Routing)
        const message = 
`From: ${encodeHeader(SMTP_CONFIG.fromName)} <${SMTP_CONFIG.from}>
To: ${to}
Subject: ${encodedSubject}
Date: ${date}
Message-ID: ${messageId}
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="${boundary}"

--${boundary}
Content-Type: text/plain; charset=utf-8

${htmlContent.replace(/<[^>]*>/g, '')}

--${boundary}
Content-Type: text/html; charset=utf-8

${htmlContent}

--${boundary}--
.`
        .replace(/\r\n/g, '\n') // Normalize to LF first
        .replace(/\n/g, '\r\n'); // Convert all LF to CRLF

        await sendCommand(writer, reader, message, 250);
        await sendCommand(writer, reader, 'QUIT', 221);
        console.log('[SMTP] Email sent successfully');

    } catch (e) {
        console.error('[SMTP] Failed to send email:', e);
        throw e;
    } finally {
        try {
            writer.releaseLock();
            reader.releaseLock();
            socket.close();
        } catch (e) { }
    }
}

// Resend API Send Function
async function sendViaResend(env: any, to: string, subject: string, htmlContent: string) {
    if (!env.RESEND_KEY) {
        throw new Error('环境变量缺少 RESEND_KEY');
    }
    
    console.log('[Resend] Sending email via API...');
    const res = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${env.RESEND_KEY}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            from: `${DEFAULT_FROM_NAME} <${env.RESEND_SEND || 'onboarding@resend.dev'}>`,
            to: [to],
            subject: subject,
            html: htmlContent,
        })
    });

    if (!res.ok) {
        const err = await res.text();
        console.error('[Resend] API Error:', err);
        throw new Error(`Resend API 错误：${err}`);
    } else {
        console.log('[Resend] Email sent successfully');
    }
}

// Main export
export async function sendEmail(to: string, subject: string, htmlContent: string, env?: any) {
    console.log(`[Email] Starting email send to ${to} - Subject: ${subject}`);
    
    // 1. Check MX Records first
    try {
        if (!(await checkMX(to))) {
            throw new Error(`邮箱域名无效（未找到 MX 记录：${to}）`);
        }
    } catch (e) {
        console.error('[Email] MX check failed:', e);
        throw e;
    }

    // Try Resend if configured
    if (env && env.RESEND_KEY) {
        try {
            await sendViaResend(env, to, subject, htmlContent);
            return;
        } catch (e) {
            console.error('[Resend] Failed, falling back to SMTP if possible...', e);
        }
    }

    // Fallback to SMTP
    try {
        await sendViaSMTP(to, subject, htmlContent, env || {});
        console.log(`[Email] ✓ Email successfully sent to ${to}`);
    } catch (e) {
        console.error('[Email] Failed to send email:', e);
        throw e;
    }
}
