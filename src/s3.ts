
import { AwsClient } from 'aws4fetch';

export interface S3Env {
    BUCKET?: R2Bucket;
    R2_PUBLIC_BASE_URL?: string;
    AWS_ACCESS_KEY_ID?: string;
    AWS_SECRET_ACCESS_KEY?: string;
    AWS_REGION?: string;
    AWS_ENDPOINT?: string;
    AWS_BUCKET?: string;
    AWS_PATH_PREFIX?: string;
}

function getClient(env: S3Env) {
    return new AwsClient({
        accessKeyId: env.AWS_ACCESS_KEY_ID,
        secretAccessKey: env.AWS_SECRET_ACCESS_KEY,
        region: env.AWS_REGION,
        service: 's3',
    });
}

export async function uploadImage(env: S3Env, file: File, userId: string | number, postId: string | number = 'general', type: 'post' | 'avatar' = 'post'): Promise<string> {
    const pathPrefix = env.AWS_PATH_PREFIX || '';
    const filename = `${Date.now()}-${file.name.replace(/[^a-zA-Z0-9.-]/g, '')}`;
    let key = '';
    
    if (type === 'avatar') {
        key = `${pathPrefix}/usr/${userId}/avatar/${filename}`.replace(/^\/+/, '');
    } else {
        key = `${pathPrefix}/usr/${userId}/post/${postId}/${filename}`.replace(/^\/+/, '');
    }

    if (env.BUCKET) {
        const buffer = await file.arrayBuffer();
        await env.BUCKET.put(key, buffer, {
            httpMetadata: {
                contentType: file.type,
            },
        });
        return key;
    }

    if (!env.AWS_ENDPOINT || !env.AWS_BUCKET) {
        throw new Error('S3/R2 not configured: Either bind an R2 bucket (BUCKET) or set AWS_ENDPOINT and AWS_BUCKET environment variables');
    }
    try {
        new URL(env.AWS_ENDPOINT);
    } catch (e) {
        throw new Error(`Invalid AWS_ENDPOINT: ${env.AWS_ENDPOINT}`);
    }
    if (env.AWS_ENDPOINT.includes('<') || env.AWS_ENDPOINT.includes('your-account-id')) {
        throw new Error(`AWS_ENDPOINT looks like a placeholder; replace it with your real R2 endpoint URL: ${env.AWS_ENDPOINT}`);
    }

    const s3 = getClient(env);
    
    const cleanedEndpoint = env.AWS_ENDPOINT.replace(/\/+$/, '');
    const url = `${cleanedEndpoint}/${env.AWS_BUCKET}/${key}`;

    try {
        new URL(url);
    } catch (e) {
        throw new Error(`Invalid upload URL generated: ${url}`);
    }

    let res;
    try {
        res = await s3.fetch(url, {
            method: 'PUT',
            body: file,
            headers: {
                'Content-Type': file.type || 'application/octet-stream',
            }
        });
    } catch (e: any) {
        throw new Error(`S3 fetch error: ${e.message}`);
    }

    if (!res.ok) {
        const err = await res.text();
        throw new Error(`S3 Upload Failed: ${res.status} ${err}`);
    }

    return key;
}

export function getKeyFromUrl(env: S3Env, imageUrl: string): string | null {
    if (!imageUrl) return null;

    // R2 binding: accept raw key, /r2/... path, or full URL containing /r2/...
    if (env.BUCKET) {
        if (!imageUrl.includes('://') && !imageUrl.startsWith('/')) return imageUrl;
        if (imageUrl.startsWith('/r2/')) return imageUrl.slice('/r2/'.length);
        if (env.R2_PUBLIC_BASE_URL) {
            const base = env.R2_PUBLIC_BASE_URL.replace(/\/+$/, '');
            if (imageUrl.startsWith(base + '/')) return imageUrl.slice(base.length + 1);
        }
        if (imageUrl.includes('://')) {
            try {
                const parsed = new URL(imageUrl);
                if (parsed.pathname.startsWith('/r2/')) return parsed.pathname.slice('/r2/'.length);
            } catch (e) {
                return null;
            }
        }
    }

    if (env.AWS_ENDPOINT && env.AWS_BUCKET) {
        const prefix = `${env.AWS_ENDPOINT.replace(/\/+$/, '')}/${env.AWS_BUCKET}/`;
        if (imageUrl.startsWith(prefix)) return imageUrl.substring(prefix.length);
    }

    return null;
}

export async function deleteImage(env: S3Env, imageUrl: string, expectedOwnerId?: string | number): Promise<boolean> {
    const key = getKeyFromUrl(env, imageUrl);
    if (!key) return false;

    if (expectedOwnerId) {
        const userSegment = `/usr/${expectedOwnerId}/`;
        if (!key.includes(userSegment)) {
            console.error(`[Security] Blocked unauthorized image deletion. Key: ${key}, Expected Owner: ${expectedOwnerId}`);
            return false;
        }
    }

    if (env.BUCKET) {
        await env.BUCKET.delete(key);
        return true;
    }

    if (!env.AWS_ENDPOINT || !env.AWS_BUCKET) return false;

    const s3 = getClient(env);
    const url = `${env.AWS_ENDPOINT.replace(/\/+$/, '')}/${env.AWS_BUCKET}/${key}`;
    const res = await s3.fetch(url, { method: 'DELETE' });
    return res.ok;
}

export async function listAllKeys(env: S3Env): Promise<string[]> {
    const keys: string[] = [];
    const pathPrefix = env.AWS_PATH_PREFIX || '';
    
    // Use R2 binding if available
    if (env.BUCKET) {
        const prefix = pathPrefix.replace(/^\/+/, '');
        const options = prefix ? { prefix } : {};
        
        const listed = await env.BUCKET.list(options);
        for (const object of listed.objects) {
            keys.push(object.key);
        }
        
        // Handle pagination if needed
        let cursor = listed.truncated ? listed.cursor : undefined;
        while (cursor) {
            const nextListed = await env.BUCKET.list({ ...options, cursor });
            for (const object of nextListed.objects) {
                keys.push(object.key);
            }
            cursor = nextListed.truncated ? nextListed.cursor : undefined;
        }
        
        return keys;
    }
    
    // S3 API fallback
    if (!env.AWS_ENDPOINT || !env.AWS_BUCKET) {
        return keys;
    }
    
    const s3 = getClient(env);
    let continuationToken: string | undefined = undefined;
    
    do {
        let url = `${env.AWS_ENDPOINT}/${env.AWS_BUCKET}?list-type=2`;
        if (pathPrefix) {
             const prefix = pathPrefix.replace(/^\/+/, '');
             url += `&prefix=${encodeURIComponent(prefix)}`;
        }

        if (continuationToken) {
            url += `&continuation-token=${encodeURIComponent(continuationToken)}`;
        }
        
        const res = await s3.fetch(url, { method: 'GET' });
        if (!res.ok) throw new Error(`List failed: ${res.status}`);
        
        const text = await res.text();
        
        const matches = text.matchAll(/<Key>(.*?)<\/Key>/g);
        for (const match of matches) {
            keys.push(match[1]);
        }
        
        const nextTokenMatch = text.match(/<NextContinuationToken>(.*?)<\/NextContinuationToken>/);
        continuationToken = nextTokenMatch ? nextTokenMatch[1] : undefined;
        
    } while (continuationToken);
    
    return keys;
}

export function getPublicUrl(env: S3Env, key: string, baseUrl?: string): string {
    if (env.BUCKET) {
        const base = (baseUrl || env.R2_PUBLIC_BASE_URL || '/r2').replace(/\/+$/, '');
        return `${base}/${key}`;
    }
    return `${env.AWS_ENDPOINT}/${env.AWS_BUCKET}/${key}`;
}
