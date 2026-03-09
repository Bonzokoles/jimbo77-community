import * as React from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PageShell } from '@/components/page-shell';
import { apiFetch, getSecurityHeaders } from '@/lib/api';
import { getToken, getUser, saveAuth, clearAuth } from '@/lib/auth';

export function SettingsPage() {
	const token = getToken();
	const user = React.useMemo(() => getUser(), [token]);

	const [displayName, setDisplayName] = React.useState(user?.display_name || user?.username || '');
	const [bio, setBio] = React.useState(user?.bio || '');
	const [profileMsg, setProfileMsg] = React.useState('');
	const [profileErr, setProfileErr] = React.useState('');
	const [profileLoading, setProfileLoading] = React.useState(false);

	const [currentPassword, setCurrentPassword] = React.useState('');
	const [newPassword, setNewPassword] = React.useState('');
	const [confirmPassword, setConfirmPassword] = React.useState('');
	const [passwordMsg, setPasswordMsg] = React.useState('');
	const [passwordErr, setPasswordErr] = React.useState('');
	const [passwordLoading, setPasswordLoading] = React.useState(false);

	const [email, setEmail] = React.useState(user?.email || '');
	const [emailMsg, setEmailMsg] = React.useState('');
	const [emailErr, setEmailErr] = React.useState('');
	const [emailLoading, setEmailLoading] = React.useState(false);

	const [totpEnabled, setTotpEnabled] = React.useState<boolean>(!!user?.totp_enabled);
	const [totpSecret, setTotpSecret] = React.useState('');
	const [totpQr, setTotpQr] = React.useState('');
	const [totpCode, setTotpCode] = React.useState('');
	const [totpMsg, setTotpMsg] = React.useState('');
	const [totpErr, setTotpErr] = React.useState('');
	const [totpLoading, setTotpLoading] = React.useState(false);

	const [avatarMsg, setAvatarMsg] = React.useState('');
	const [avatarErr, setAvatarErr] = React.useState('');
	const [avatarLoading, setAvatarLoading] = React.useState(false);
	const [avatarPreview, setAvatarPreview] = React.useState<string>(user?.avatar || '');

	const [notifyReplies, setNotifyReplies] = React.useState<boolean>(user?.notify_replies !== false);
	const [notifyMsg, setNotifyMsg] = React.useState('');
	const [notifyErr, setNotifyErr] = React.useState('');
	const [notifyLoading, setNotifyLoading] = React.useState(false);

	if (!user) {
		return (
			<PageShell>
				<div className="p-4 text-sm text-muted-foreground">
					Musisz być zalogowany, aby wyświetlić ustawienia.{' '}
					<a href="/login" className="underline">Zaloguj się</a>
				</div>
			</PageShell>
		);
	}

	async function saveProfile(e: React.FormEvent) {
		e.preventDefault();
		setProfileMsg(''); setProfileErr('');
		setProfileLoading(true);
		try {
			const res = await apiFetch<{ user: any }>('/user/profile', {
				method: 'POST',
				headers: getSecurityHeaders('POST'),
				body: JSON.stringify({ display_name: displayName, bio })
			});
			if (res.user) saveAuth(token!, res.user);
			setProfileMsg('Profil został zaktualizowany.');
		} catch (e: any) {
			setProfileErr(String(e?.message || e));
		} finally {
			setProfileLoading(false);
		}
	}

	async function changePassword(e: React.FormEvent) {
		e.preventDefault();
		setPasswordMsg(''); setPasswordErr('');
		if (newPassword !== confirmPassword) { setPasswordErr('Nowe hasła nie są identyczne'); return; }
		setPasswordLoading(true);
		try {
			await apiFetch('/user/password', {
				method: 'POST',
				headers: getSecurityHeaders('POST'),
				body: JSON.stringify({ current_password: currentPassword, new_password: newPassword })
			});
			setPasswordMsg('Hasło zostało zmienione.');
			setCurrentPassword(''); setNewPassword(''); setConfirmPassword('');
		} catch (e: any) {
			setPasswordErr(String(e?.message || e));
		} finally {
			setPasswordLoading(false);
		}
	}

	async function changeEmail(e: React.FormEvent) {
		e.preventDefault();
		setEmailMsg(''); setEmailErr('');
		setEmailLoading(true);
		try {
			await apiFetch('/user/email', {
				method: 'POST',
				headers: getSecurityHeaders('POST'),
				body: JSON.stringify({ email })
			});
			setEmailMsg('Link weryfikacyjny został wysłany na nowy adres e-mail.');
		} catch (e: any) {
			setEmailErr(String(e?.message || e));
		} finally {
			setEmailLoading(false);
		}
	}

	async function enableTotp() {
		setTotpMsg(''); setTotpErr('');
		setTotpLoading(true);
		try {
			const res = await apiFetch<{ secret: string; qr: string }>('/user/totp/setup', {
				method: 'POST',
				headers: getSecurityHeaders('POST'),
				body: JSON.stringify({})
			});
			setTotpSecret(res.secret);
			setTotpQr(res.qr);
		} catch (e: any) {
			setTotpErr(String(e?.message || e));
		} finally {
			setTotpLoading(false);
		}
	}

	async function confirmTotp(e: React.FormEvent) {
		e.preventDefault();
		setTotpMsg(''); setTotpErr('');
		setTotpLoading(true);
		try {
			const res = await apiFetch<{ user: any }>('/user/totp/confirm', {
				method: 'POST',
				headers: getSecurityHeaders('POST'),
				body: JSON.stringify({ code: totpCode })
			});
			if (res.user) saveAuth(token!, res.user);
			setTotpEnabled(true);
			setTotpSecret(''); setTotpQr(''); setTotpCode('');
			setTotpMsg('Uwierzytelnianie dwuetapowe (2FA) zostało włączone.');
		} catch (e: any) {
			setTotpErr(String(e?.message || e));
		} finally {
			setTotpLoading(false);
		}
	}

	async function disableTotp() {
		setTotpMsg(''); setTotpErr('');
		setTotpLoading(true);
		try {
			const res = await apiFetch<{ user: any }>('/user/totp/disable', {
				method: 'POST',
				headers: getSecurityHeaders('POST'),
				body: JSON.stringify({})
			});
			if (res.user) saveAuth(token!, res.user);
			setTotpEnabled(false);
			setTotpMsg('Uwierzytelnianie dwuetapowe (2FA) zostało wyłączone.');
		} catch (e: any) {
			setTotpErr(String(e?.message || e));
		} finally {
			setTotpLoading(false);
		}
	}

	async function saveNotifications(e: React.FormEvent) {
		e.preventDefault();
		setNotifyMsg(''); setNotifyErr('');
		setNotifyLoading(true);
		try {
			const res = await apiFetch<{ user: any }>('/user/notifications', {
				method: 'POST',
				headers: getSecurityHeaders('POST'),
				body: JSON.stringify({ notify_replies: notifyReplies })
			});
			if (res.user) saveAuth(token!, res.user);
			setNotifyMsg('Ustawienia powiadomień zostały zapisane.');
		} catch (e: any) {
			setNotifyErr(String(e?.message || e));
		} finally {
			setNotifyLoading(false);
		}
	}

	return (
		<PageShell>
			<div className="space-y-6 max-w-2xl mx-auto">
				<h1 className="text-2xl font-semibold tracking-tight">Ustawienia konta</h1>

				{/* Profil */}
				<Card>
					<CardHeader><CardTitle>Profil</CardTitle></CardHeader>
					<CardContent>
						<form className="space-y-4" onSubmit={saveProfile}>
							{profileErr ? <div className="rounded-md border border-destructive/50 bg-destructive/5 p-3 text-sm text-destructive">{profileErr}</div> : null}
							{profileMsg ? <div className="rounded-md border border-green-500/50 bg-green-500/5 p-3 text-sm text-green-700 dark:text-green-300">{profileMsg}</div> : null}
							<div className="space-y-2">
								<Label htmlFor="display-name">Wyświetlana nazwa</Label>
								<Input id="display-name" value={displayName} onChange={(e) => setDisplayName(e.target.value)} maxLength={50} />
							</div>
							<div className="space-y-2">
								<Label htmlFor="bio">O mnie</Label>
								<Input id="bio" value={bio} onChange={(e) => setBio(e.target.value)} maxLength={200} />
							</div>
							<Button type="submit" disabled={profileLoading}>{profileLoading ? 'Zapisywanie...' : 'Zapisz profil'}</Button>
						</form>
					</CardContent>
				</Card>

				{/* Avatar */}
				<Card>
					<CardHeader><CardTitle>Zdjęcie profilowe</CardTitle></CardHeader>
					<CardContent>
						<div className="space-y-4">
							{avatarErr ? <div className="rounded-md border border-destructive/50 bg-destructive/5 p-3 text-sm text-destructive">{avatarErr}</div> : null}
							{avatarMsg ? <div className="rounded-md border border-green-500/50 bg-green-500/5 p-3 text-sm text-green-700 dark:text-green-300">{avatarMsg}</div> : null}
							{avatarPreview ? (
								<img src={avatarPreview} alt="Avatar" className="h-20 w-20 rounded-full object-cover" />
							) : null}
							<input
								type="file"
								accept="image/*"
								className="block w-full text-sm"
								onChange={async (e) => {
									const file = e.target.files?.[0];
									if (!file) return;
									setAvatarErr('');
									if (file.size > 1 * 1024 * 1024) { setAvatarErr('Plik jest zbyt duży (maksymalnie 1MB)'); return; }
									setAvatarLoading(true);
									try {
										const formData = new FormData();
										formData.append('file', file);
										formData.append('type', 'avatar');
										const res = await fetch('/api/upload', {
											method: 'POST',
											headers: getSecurityHeaders('POST', null),
											body: formData
										});
										const data = await res.json();
										if (!res.ok) throw new Error(data?.error || 'Błąd przesyłania');
										const res2 = await apiFetch<{ user: any }>('/user/avatar', {
											method: 'POST',
											headers: getSecurityHeaders('POST'),
											body: JSON.stringify({ avatar: data.url })
										});
										if (res2.user) saveAuth(token!, res2.user);
										setAvatarPreview(data.url);
										setAvatarMsg('Zdjęcie profilowe zostało zaktualizowane.');
									} catch (err: any) {
										setAvatarErr(String(err?.message || err));
									} finally {
										setAvatarLoading(false);
									}
								}}
							/>
							{avatarLoading ? <div className="text-sm text-muted-foreground">Przesyłanie...</div> : null}
						</div>
					</CardContent>
				</Card>

				{/* Zmiana e-mail */}
				<Card>
					<CardHeader><CardTitle>Adres e-mail</CardTitle></CardHeader>
					<CardContent>
						<form className="space-y-4" onSubmit={changeEmail}>
							{emailErr ? <div className="rounded-md border border-destructive/50 bg-destructive/5 p-3 text-sm text-destructive">{emailErr}</div> : null}
							{emailMsg ? <div className="rounded-md border border-green-500/50 bg-green-500/5 p-3 text-sm text-green-700 dark:text-green-300">{emailMsg}</div> : null}
							<div className="space-y-2">
								<Label htmlFor="email">Nowy adres e-mail</Label>
								<Input id="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
							</div>
							<Button type="submit" disabled={emailLoading}>{emailLoading ? 'Wysyłanie...' : 'Zmień e-mail'}</Button>
						</form>
					</CardContent>
				</Card>

				{/* Zmiana hasła */}
				<Card>
					<CardHeader><CardTitle>Zmiana hasła</CardTitle></CardHeader>
					<CardContent>
						<form className="space-y-4" onSubmit={changePassword}>
							{passwordErr ? <div className="rounded-md border border-destructive/50 bg-destructive/5 p-3 text-sm text-destructive">{passwordErr}</div> : null}
							{passwordMsg ? <div className="rounded-md border border-green-500/50 bg-green-500/5 p-3 text-sm text-green-700 dark:text-green-300">{passwordMsg}</div> : null}
							<div className="space-y-2">
								<Label htmlFor="current-password">Obecne hasło</Label>
								<Input id="current-password" type="password" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} required autoComplete="current-password" />
							</div>
							<div className="space-y-2">
								<Label htmlFor="new-password">Nowe hasło</Label>
								<Input id="new-password" type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} required autoComplete="new-password" />
							</div>
							<div className="space-y-2">
								<Label htmlFor="confirm-password">Potwierdź nowe hasło</Label>
								<Input id="confirm-password" type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} required autoComplete="new-password" />
							</div>
							<Button type="submit" disabled={passwordLoading}>{passwordLoading ? 'Zmienianie...' : 'Zmień hasło'}</Button>
						</form>
					</CardContent>
				</Card>

				{/* 2FA */}
				<Card>
					<CardHeader><CardTitle>Uwierzytelnianie dwuetapowe (2FA)</CardTitle></CardHeader>
					<CardContent>
						<div className="space-y-4">
							{totpErr ? <div className="rounded-md border border-destructive/50 bg-destructive/5 p-3 text-sm text-destructive">{totpErr}</div> : null}
							{totpMsg ? <div className="rounded-md border border-green-500/50 bg-green-500/5 p-3 text-sm text-green-700 dark:text-green-300">{totpMsg}</div> : null}
							{totpEnabled ? (
								<div className="space-y-2">
									<p className="text-sm text-green-700 dark:text-green-300">✓ 2FA jest włączone</p>
									<Button variant="outline" onClick={disableTotp} disabled={totpLoading}>
										{totpLoading ? 'Wyłączanie...' : 'Wyłącz 2FA'}
									</Button>
								</div>
							) : totpSecret ? (
								<form className="space-y-4" onSubmit={confirmTotp}>
									<p className="text-sm text-muted-foreground">Zeskanuj kod QR w aplikacji uwierzytelniającej (np. Google Authenticator, Authy).</p>
									{totpQr ? <img src={totpQr} alt="Kod QR dla 2FA" className="h-40 w-40" /> : null}
									<p className="text-xs text-muted-foreground font-mono break-all">Sekret: {totpSecret}</p>
									<div className="space-y-2">
										<Label htmlFor="totp-code">Kod weryfikacyjny</Label>
										<Input id="totp-code" value={totpCode} onChange={(e) => setTotpCode(e.target.value)} inputMode="numeric" maxLength={6} required />
									</div>
									<Button type="submit" disabled={totpLoading}>{totpLoading ? 'Weryfikacja...' : 'Potwierdź i włącz 2FA'}</Button>
								</form>
							) : (
								<div className="space-y-2">
									<p className="text-sm text-muted-foreground">2FA nie jest włączone. Zwiększ bezpieczeństwo swojego konta.</p>
									<Button variant="outline" onClick={enableTotp} disabled={totpLoading}>
										{totpLoading ? 'Ładowanie...' : 'Włącz 2FA'}
									</Button>
								</div>
							)}
						</div>
					</CardContent>
				</Card>

				{/* Powiadomienia */}
				<Card>
					<CardHeader><CardTitle>Powiadomienia</CardTitle></CardHeader>
					<CardContent>
						<form className="space-y-4" onSubmit={saveNotifications}>
							{notifyErr ? <div className="rounded-md border border-destructive/50 bg-destructive/5 p-3 text-sm text-destructive">{notifyErr}</div> : null}
							{notifyMsg ? <div className="rounded-md border border-green-500/50 bg-green-500/5 p-3 text-sm text-green-700 dark:text-green-300">{notifyMsg}</div> : null}
							<div className="flex items-center gap-3">
								<input
									id="notify-replies"
									type="checkbox"
									checked={notifyReplies}
									onChange={(e) => setNotifyReplies(e.target.checked)}
									className="h-4 w-4"
								/>
								<Label htmlFor="notify-replies">Powiadamiaj mnie e-mailem o nowych komentarzach pod moimi postami</Label>
							</div>
							<Button type="submit" disabled={notifyLoading}>{notifyLoading ? 'Zapisywanie...' : 'Zapisz ustawienia'}</Button>
						</form>
					</CardContent>
				</Card>
			</div>
		</PageShell>
	);
}
