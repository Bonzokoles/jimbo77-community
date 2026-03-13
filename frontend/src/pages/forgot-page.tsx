import * as React from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { apiFetch, getSecurityHeaders } from '@/lib/api';
import { TurnstileWidget } from '@/components/turnstile';
import { useConfig } from '@/hooks/use-config';

export function ForgotPage() {
	const { config } = useConfig();
	const [email, setEmail] = React.useState('');
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
			await apiFetch('/auth/forgot-password', {
				method: 'POST',
				headers: getSecurityHeaders('POST'),
				body: JSON.stringify({
					email,
					'cf-turnstile-response': turnstileToken
				})
			});
			setSuccess('Jeśli konto istnieje, wysłaliśmy link do resetowania hasła na podany adres e-mail.');
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
					<CardTitle>Resetowanie hasła</CardTitle>
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
							<Label htmlFor="email">Adres e-mail</Label>
							<Input id="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoComplete="email" />
						</div>
						<TurnstileWidget enabled={turnstileActive} siteKey={siteKey} onToken={setTurnstileToken} resetKey={turnstileResetKey} />
						<Button type="submit" className="w-full" disabled={loading}>
							{loading ? 'Wysyłanie...' : 'Wyślij link resetujący'}
						</Button>
						<div className="text-center text-sm">
							<a href="/login" className="text-muted-foreground hover:underline">Wróć do logowania</a>
						</div>
					</form>
				</CardContent>
			</Card>
		</div>
	);
}
