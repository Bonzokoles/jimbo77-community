import * as React from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { apiFetch, getSecurityHeaders } from '@/lib/api';
import { TurnstileWidget } from '@/components/turnstile';
import { useConfig } from '@/hooks/use-config';

export function RegisterPage() {
	const { config } = useConfig();
	const [username, setUsername] = React.useState('');
	const [email, setEmail] = React.useState('');
	const [password, setPassword] = React.useState('');
	const [error, setError] = React.useState('');
	const [success, setSuccess] = React.useState('');
	const [loading, setLoading] = React.useState(false);
	const [turnstileToken, setTurnstileToken] = React.useState('');
	const [turnstileResetKey, setTurnstileResetKey] = React.useState(0);

	const enabled = !!config?.turnstile_enabled;
	const siteKey = config?.turnstile_site_key || '';
	const turnstileActive = enabled && !!siteKey;

	async function handleSubmit(e: React.FormEvent) {
		e.preventDefault();
		setError('');
		setSuccess('');
		if (turnstileActive && !turnstileToken) {
			setError('Proszę wypełnić weryfikację CAPTCHA');
			return;
		}
		setLoading(true);
		try {
			await apiFetch('/register', {
				method: 'POST',
				headers: getSecurityHeaders('POST'),
				body: JSON.stringify({
					username,
					email,
					password,
					'cf-turnstile-response': turnstileToken
				})
			});
			setSuccess('Rejestracja udana! Sprawdź swój e-mail, aby zweryfikować konto.');
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
					<CardTitle>Rejestracja</CardTitle>
				</CardHeader>
				<CardContent>
					<form className="space-y-4" onSubmit={handleSubmit}>
						{error ? (
							<div className="rounded-md border border-destructive/50 bg-destructive/5 p-3 text-sm text-destructive">{error}</div>
						) : null}
						{success ? (
							<div className="rounded-md border border-green-500/50 bg-green-500/5 p-3 text-sm text-green-700 dark:text-green-300">{success}</div>
						) : null}
						<div className="space-y-2">
							<Label htmlFor="username">Nazwa użytkownika</Label>
							<Input id="username" value={username} onChange={(e) => setUsername(e.target.value)} required autoComplete="username" />
						</div>
						<div className="space-y-2">
							<Label htmlFor="email">Adres e-mail</Label>
							<Input id="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoComplete="email" />
						</div>
						<div className="space-y-2">
							<Label htmlFor="password">Hasło</Label>
							<Input id="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required autoComplete="new-password" />
						</div>
						<TurnstileWidget enabled={turnstileActive} siteKey={siteKey} onToken={setTurnstileToken} resetKey={turnstileResetKey} />
						<Button type="submit" className="w-full" disabled={loading}>
							{loading ? 'Rejestracja...' : 'Zarejestruj się'}
						</Button>
						<div className="text-center text-sm">
							<a href="/login" className="text-muted-foreground hover:underline">Masz już konto? Zaloguj się</a>
						</div>
					</form>
				</CardContent>
			</Card>
		</div>
	);
}
