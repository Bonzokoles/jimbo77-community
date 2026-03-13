import * as React from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { apiFetch, getSecurityHeaders } from '@/lib/api';

export function ResetPage() {
	const [password, setPassword] = React.useState('');
	const [confirm, setConfirm] = React.useState('');
	const [error, setError] = React.useState('');
	const [success, setSuccess] = React.useState('');
	const [loading, setLoading] = React.useState(false);

	const token = React.useMemo(() => {
		const params = new URLSearchParams(window.location.search);
		return params.get('token') || '';
	}, []);

	async function handleSubmit(e: React.FormEvent) {
		e.preventDefault();
		setError('');
		setSuccess('');
		if (password !== confirm) {
			setError('Hasła nie są identyczne');
			return;
		}
		if (!token) {
			setError('Nieprawidłowy token resetowania');
			return;
		}
		setLoading(true);
		try {
			await apiFetch('/auth/reset-password', {
				method: 'POST',
				headers: getSecurityHeaders('POST'),
				body: JSON.stringify({ token, password })
			});
			setSuccess('Hasło zostało zmienione. Możesz się teraz zalogować.');
		} catch (e: any) {
			setError(String(e?.message || e));
		} finally {
			setLoading(false);
		}
	}

	return (
		<div className="flex min-h-screen items-center justify-center p-4">
			<Card className="w-full max-w-sm">
				<CardHeader>
					<CardTitle>Nowe hasło</CardTitle>
				</CardHeader>
				<CardContent>
					<form className="space-y-4" onSubmit={handleSubmit}>
						{error ? (
							<div className="rounded-md border border-destructive/50 bg-destructive/5 p-3 text-sm text-destructive">{error}</div>
						) : null}
						{success ? (
							<div className="rounded-md border border-green-500/50 bg-green-500/5 p-3 text-sm text-green-700 dark:text-green-300">
								{success}{' '}
								<a href="/login" className="underline">Zaloguj się</a>
							</div>
						) : null}
						<div className="space-y-2">
							<Label htmlFor="password">Nowe hasło</Label>
							<Input id="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required autoComplete="new-password" />
						</div>
						<div className="space-y-2">
							<Label htmlFor="confirm">Potwierdź hasło</Label>
							<Input id="confirm" type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required autoComplete="new-password" />
						</div>
						<Button type="submit" className="w-full" disabled={loading}>
							{loading ? 'Zapisywanie...' : 'Zmień hasło'}
						</Button>
					</form>
				</CardContent>
			</Card>
		</div>
	);
}
