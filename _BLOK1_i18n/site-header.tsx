import * as React from 'react';
import { Moon, Sun, User, LogOut, Settings, Shield } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { getToken, getUser, clearAuth } from '@/lib/auth';

export function SiteHeader() {
	const token = getToken();
	const user = React.useMemo(() => getUser(), [token]);
	const [dark, setDark] = React.useState(() => document.documentElement.classList.contains('dark'));
	const [menuOpen, setMenuOpen] = React.useState(false);
	const menuRef = React.useRef<HTMLDivElement>(null);

	function toggleDark() {
		const next = !dark;
		setDark(next);
		document.documentElement.classList.toggle('dark', next);
		localStorage.setItem('theme', next ? 'dark' : 'light');
	}

	React.useEffect(() => {
		function handleClick(e: MouseEvent) {
			if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
				setMenuOpen(false);
			}
		}
		document.addEventListener('mousedown', handleClick);
		return () => document.removeEventListener('mousedown', handleClick);
	}, []);

	function logout() {
		clearAuth();
		window.location.href = '/';
	}

	return (
		<header className="sticky top-0 z-40 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
			<div className="container mx-auto flex h-14 items-center justify-between px-4">
				<a href="/" className="flex items-center gap-2 font-semibold text-lg">
					Jimbo77 Community
				</a>
				<div className="flex items-center gap-2">
					<Button variant="ghost" size="sm" onClick={toggleDark} aria-label={dark ? 'Tryb jasny' : 'Tryb ciemny'}>
						{dark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
					</Button>
					{user ? (
						<div className="relative" ref={menuRef}>
							<Button
								variant="ghost"
								size="sm"
								className="flex items-center gap-2"
								onClick={() => setMenuOpen((v) => !v)}
								aria-haspopup="menu"
								aria-expanded={menuOpen}
							>
								{user.avatar ? (
									<img src={user.avatar} alt="" className="h-6 w-6 rounded-full object-cover" />
								) : (
									<User className="h-4 w-4" />
								)}
								<span className="hidden sm:inline">{user.display_name || user.username}</span>
							</Button>
							{menuOpen ? (
								<div className="absolute right-0 top-full z-50 mt-1 w-44 rounded-md border bg-background p-1 shadow-md">
									<a
										href="/settings"
										className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-sm hover:bg-muted"
									>
										<Settings className="h-4 w-4" />
										Ustawienia
									</a>
									{user.role === 'admin' ? (
										<a
											href="/admin"
											className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-sm hover:bg-muted"
										>
											<Shield className="h-4 w-4" />
											Panel admina
										</a>
									) : null}
									<div className="my-1 h-px bg-border" />
									<button
										type="button"
										onClick={logout}
										className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-sm text-destructive hover:bg-destructive/10"
									>
										<LogOut className="h-4 w-4" />
										Wyloguj się
									</button>
								</div>
							) : null}
						</div>
					) : (
						<div className="flex items-center gap-2">
							<Button variant="ghost" size="sm" asChild>
								<a href="/login">Zaloguj się</a>
							</Button>
							<Button size="sm" asChild>
								<a href="/register">Zarejestruj się</a>
							</Button>
						</div>
					)}
				</div>
			</div>
		</header>
	);
}
