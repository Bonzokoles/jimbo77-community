import * as React from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { apiFetch, getSecurityHeaders } from '@/lib/api';
import { saveAuth } from '@/lib/auth';
import { TurnstileWidget } from '@/components/turnstile';
import { useConfig } from '@/hooks/use-config';

export function LoginPage() {
	const { config } = useConfig();
	const [email, setEmail] = React.useState('');
	const [password, setPassword] = React.useState('');
	const [totp, setTotp] = React.useState('');
	const [error, setError] = React.useState('');
	const [loading, setLoading] = React.useState(false);
	const [turnstileToken, setTurnstileToken] = React.useState('');
	const [turnstileResetKey, setTurnstileResetKey] = React.useState(0);

	const enabled = !!config?.turnstile_enabled;
	const siteKey = config?.turnstile_site_key || '';
	const turnstileActive = enabled && !!siteKey;

	async function handleSubmit(e: React.FormEvent) {
		e.preventDefault();
		setError('');
		if (turnstileActive && !turnstileToken) {
			setError('Proszę wypełnić weryfikację CAPTCHA');
			return;
		}
		setLoading(true);
		try {
			const res = await apiFetch<{ token: string; user: any }>('/login', {
				method: 'POST',
				headers: getSecurityHeaders('POST'),
				body: JSON.stringify({
					email,
					password,
					totp_code: totp || undefined,
					'cf-turnstile-response': turnstileToken
				})
			});
			saveAuth(res.token, res.user);
			window.location.href = '/';
		} catch (e: any) {
			setError(String(e?.message || e));
			setTurnstileToken('');
			setTurnstileResetKey((v) => v + 1);
		} finally {
			setLoading(false);
		}
	}

	return (
		<div className="flex min-h-screen items-center justify-center p-4">
			<Card className="w-full max-w-sm">
				<CardHeader>
					<CardTitle>Logowanie</CardTitle>
				</CardHeader>
				<CardContent>
					<form className="space-y-4" onSubmit={handleSubmit}>
						{error ? (
							<div className="rounded-md border border-destructive/50 bg-destructive/5 p-3 text-sm text-destructive">{error}</div>
						) : null}
						<div className="space-y-2">
						<Label htmlFor="email">E-mail</Label>
						<Input id="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoComplete="email" />
						</div>
						<div className="space-y-2">
							<Label htmlFor="password">Hasło</Label>
							<Input id="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required autoComplete="current-password" />
						</div>
						<div className="space-y-2">
							<Label htmlFor="totp">Kod 2FA (opcjonalnie)</Label>
							<Input id="totp" value={totp} onChange={(e) => setTotp(e.target.value)} autoComplete="one-time-code" inputMode="numeric" maxLength={6} />
						</div>
						<TurnstileWidget enabled={turnstileActive} siteKey={siteKey} onToken={setTurnstileToken} resetKey={turnstileResetKey} />
						<Button type="submit" className="w-full" disabled={loading}>
							{loading ? 'Logowanie...' : 'Zaloguj się'}
						</Button>
						<div className="flex justify-between text-sm">
							<a href="/register" className="text-muted-foreground hover:underline">Zarejestruj się</a>
							<a href="/forgot" className="text-muted-foreground hover:underline">Zapomniałem hasła</a>
						</div>
					</form>
				</CardContent>
			</Card>
		</div>
	);
}
