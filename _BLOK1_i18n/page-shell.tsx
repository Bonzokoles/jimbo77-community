import * as React from 'react';
import { SiteHeader } from '@/components/site-header';

interface PageShellProps {
	children: React.ReactNode;
}

export function PageShell({ children }: PageShellProps) {
	return (
		<div className="flex min-h-screen flex-col">
			<SiteHeader />
			<main className="container mx-auto flex-1 px-4 py-6">{children}</main>
			<footer className="border-t py-4 text-center text-xs text-muted-foreground">
				© 2026 Jimbo77 Community
			</footer>
		</div>
	);
}
