import * as React from 'react';
import { ChevronDown, ChevronLeft, ChevronRight, ChevronUp, Eye, EyeOff, Heart, MessageCircle, MoreVertical, Pin, RefreshCw, Search, Shield, Trash2, User, X } from 'lucide-react';

import { TurnstileWidget } from '@/components/turnstile';
import { PageShell } from '@/components/page-shell';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { useConfig } from '@/hooks/use-config';
import { apiFetch, formatDate, getSecurityHeaders, type Category, type Post } from '@/lib/api';
import { getToken, getUser } from '@/lib/auth';
import { attachFancybox, highlightCodeBlocks, renderMarkdownToHtml } from '@/lib/markdown';
import { validateText } from '@/lib/validators';

export function IndexPage() {
	const { config } = useConfig();
	const token = getToken();
	const user = React.useMemo(() => getUser(), [token]);
	const [banner, setBanner] = React.useState<string>('');
	const [categories, setCategories] = React.useState<Category[]>([]);
	const [selectedCategory, setSelectedCategory] = React.useState<string>('');
	const [searchInput, setSearchInput] = React.useState<string>('');
	const [searchQuery, setSearchQuery] = React.useState<string>('');
	const [posts, setPosts] = React.useState<Post[]>([]);
	const [totalPosts, setTotalPosts] = React.useState<number>(0);
	const [pageOffset, setPageOffset] = React.useState<number>(0);
	const [loading, setLoading] = React.useState<boolean>(true);
	const [error, setError] = React.useState<string>('');
	const pageLimit = 10;
	const [jumpTo, setJumpTo] = React.useState<string>('');

	const [newTitle, setNewTitle] = React.useState('');
	const [newContent, setNewContent] = React.useState('');
	const [newCategoryId, setNewCategoryId] = React.useState<string>('');
	const [previewOpen, setPreviewOpen] = React.useState(true);
	const [createOpen, setCreateOpen] = React.useState(false);
	const [createLoading, setCreateLoading] = React.useState(false);
	const [createError, setCreateError] = React.useState('');
	const [uploadLoading, setUploadLoading] = React.useState(false);
	const [uploadError, setUploadError] = React.useState('');

	function insertIntoContent(insertText: string) {
		if (newContentRef.current) {
			const el = newContentRef.current;
			const start = el.selectionStart;
			const end = el.selectionEnd;
			const before = newContent.slice(0, start);
			const after = newContent.slice(end);
			const updated = before + insertText + after;
			setNewContent(updated);
			setTimeout(() => {
				el.selectionStart = el.selectionEnd = start + insertText.length;
				el.focus();
			}, 0);
		} else {
			setNewContent(newContent + insertText);
		}
	}

	function applyEdit(transform: (text: string, start: number, end: number) => { text: string; selectionStart: number; selectionEnd: number }) {
		const el = newContentRef.current;
		const start = el ? el.selectionStart : newContent.length;
		const end = el ? el.selectionEnd : newContent.length;
		const result = transform(newContent, start, end);
		setNewContent(result.text);
		setTimeout(() => {
			const target = newContentRef.current;
			if (!target) return;
			target.selectionStart = result.selectionStart;
			target.selectionEnd = result.selectionEnd;
			target.focus();
		}, 0);
	}

	function wrapSelection(prefix: string, suffix: string, placeholder: string) {
		applyEdit((text, start, end) => {
			const selected = text.slice(start, end) || placeholder;
			const next = text.slice(0, start) + prefix + selected + suffix + text.slice(end);
			const selectionStart = start + prefix.length;
			const selectionEnd = selectionStart + selected.length;
			return { text: next, selectionStart, selectionEnd };
		});
	}

	function wrapBlock(fence: string) {
		applyEdit((text, start, end) => {
			const selected = text.slice(start, end);
			const block = `${fence}\n${selected}\n${fence}`;
			const next = text.slice(0, start) + block + text.slice(end);
			const selectionStart = start + fence.length + 1;
			const selectionEnd = selectionStart + selected.length;
			return { text: next, selectionStart, selectionEnd };
		});
	}

	function transformLines(transform: (line: string, index: number, lines: string[]) => string) {
		applyEdit((text, start, end) => {
			const lineStart = text.lastIndexOf('\n', start - 1) + 1;
			const lineEnd = text.indexOf('\n', end);
			const endIndex = lineEnd === -1 ? text.length : lineEnd;
			const segment = text.slice(lineStart, endIndex);
			const lines = segment.split('\n');
			const nextSegment = lines.map(transform).join('\n');
			const next = text.slice(0, lineStart) + nextSegment + text.slice(endIndex);
			return { text: next, selectionStart: lineStart, selectionEnd: lineStart + nextSegment.length };
		});
	}

	function setHeading(level: number) {
		transformLines((line) => {
			const cleaned = line.replace(/^\s{0,3}#{1,6}\s+/, '');
			if (level === 0) return cleaned;
			return `${'#'.repeat(level)} ${cleaned}`;
		});
	}

	function toggleLinePrefix(prefix: string, matcher: RegExp) {
		transformLines((line) => {
			if (matcher.test(line)) return line.replace(matcher, '');
			return `${prefix}${line}`;
		});
	}

	function toggleBlockquote() {
		transformLines((line) => (line.startsWith('> ') ? line.slice(2) : `> ${line}`));
	}

	function toggleList(ordered: boolean) {
		transformLines((line, index, lines) => {
			if (ordered) {
				if (/^\d+\.\s+/.test(line)) return line.replace(/^\d+\.\s+/, '');
				return `${index + 1}. ${line}`;
			}
			if (/^[-*+]\s+/.test(line)) return line.replace(/^[-*+]\s+/, '');
			return `- ${line}`;
		});
	}

	function indentLines() {
		transformLines((line) => `  ${line}`);
	}

	function outdentLines() {
		transformLines((line) => line.replace(/^(\t| {1,2})/, ''));
	}

	function insertLink(isImage: boolean) {
		applyEdit((text, start, end) => {
			const selected = text.slice(start, end) || (isImage ? 'alt' : 'tekst');
			const link = isImage ? `![${selected}](url)` : `[${selected}](url)`;
			const next = text.slice(0, start) + link + text.slice(end);
			const urlStart = start + (isImage ? 2 : 1) + selected.length + 2;
			const urlEnd = urlStart + 3;
			return { text: next, selectionStart: urlStart, selectionEnd: urlEnd };
		});
	}

	function insertTable() {
		applyEdit((text, start, end) => {
			const table = `| Nagłówek | Nagłówek |\n| --- | --- |\n| Komórka | Komórka |`;
			const next = text.slice(0, start) + table + text.slice(end);
			const selectionStart = start + 2;
			const selectionEnd = selectionStart + 8;
			return { text: next, selectionStart, selectionEnd };
		});
	}

	function handleEditorKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
		const isMod = e.ctrlKey || e.metaKey;
		if (!isMod) return;
		const key = e.key.toLowerCase();
		const shift = e.shiftKey;
		if (!shift && key === 'b') { e.preventDefault(); wrapSelection('**', '**', 'tekst'); return; }
		if (!shift && key === 'i') { e.preventDefault(); wrapSelection('*', '*', 'tekst'); return; }
		if (!shift && key === 'u') { e.preventDefault(); wrapSelection('<u>', '</u>', 'tekst'); return; }
		if (!shift && key === 'k') { e.preventDefault(); insertLink(false); return; }
		if (!shift && key === 't') { e.preventDefault(); insertTable(); return; }
		if (shift && key === 'i') { e.preventDefault(); insertLink(true); return; }
		if (!shift && key === '0') { e.preventDefault(); setHeading(0); return; }
		if (!shift && key === '1') { e.preventDefault(); setHeading(1); return; }
		if (!shift && key === '2') { e.preventDefault(); setHeading(2); return; }
		if (!shift && key === '3') { e.preventDefault(); setHeading(3); return; }
		if (shift && key === 'k') { e.preventDefault(); wrapBlock('```'); return; }
		if (shift && key === 'm') { e.preventDefault(); wrapBlock('$$'); return; }
		if (shift && key === 'q') { e.preventDefault(); toggleBlockquote(); return; }
		if (shift && key === '[') { e.preventDefault(); toggleList(true); return; }
		if (shift && key === ']') { e.preventDefault(); toggleList(false); return; }
		if (!shift && key === '[') { e.preventDefault(); outdentLines(); return; }
		if (!shift && key === ']') { e.preventDefault(); indentLines(); return; }
		if (shift && (e.code === 'Backquote' || key === '`')) { e.preventDefault(); wrapSelection('`', '`', 'kod'); return; }
		if (e.altKey && shift && e.code === 'Digit5') { e.preventDefault(); wrapSelection('~~', '~~', 'tekst'); return; }
	}

	const [turnstileToken, setTurnstileToken] = React.useState('');
	const [turnstileResetKey, setTurnstileResetKey] = React.useState(0);
	const previewRef = React.useRef<HTMLDivElement | null>(null);
	const newContentRef = React.useRef<HTMLTextAreaElement | null>(null);
	const [adminMenuPostId, setAdminMenuPostId] = React.useState<number | null>(null);
	const [adminActionPostId, setAdminActionPostId] = React.useState<number | null>(null);
	const [sortOption, setSortOption] = React.useState('time_desc');
	const listTopRef = React.useRef<HTMLDivElement | null>(null);
	const lastOffsetRef = React.useRef<number | null>(null);

	const enabled = !!config?.turnstile_enabled;
	const siteKey = config?.turnstile_site_key || '';
	const turnstileActive = enabled && !!siteKey;

	const fetchCategories = React.useCallback(async () => {
		try {
			const list = await apiFetch<Category[]>('/categories');
			setCategories(list);
		} catch {
			setCategories([]);
		}
	}, []);

	const fetchPosts = React.useCallback(
		async (offset: number) => {
			setLoading(true);
			setError('');
			try {
				const sortBy =
					sortOption === 'likes_desc'
						? 'likes'
						: sortOption === 'comments_desc'
							? 'comments'
							: sortOption === 'views_desc'
								? 'views'
								: 'time';
				const sortDir = sortOption === 'time_asc' ? 'asc' : 'desc';
				const categoryParam = selectedCategory ? `&category_id=${encodeURIComponent(selectedCategory)}` : '';
				const searchParam = searchQuery ? `&q=${encodeURIComponent(searchQuery)}` : '';
				const sortParam = `&sort_by=${encodeURIComponent(sortBy)}&sort_dir=${encodeURIComponent(sortDir)}`;
				const res = await fetch(`/api/posts?limit=${pageLimit}&offset=${offset}${categoryParam}${searchParam}${sortParam}`);
				if (!res.ok) {
					let msg = `Błąd ładowania postów (${res.status})`;
					try {
						const body = await res.text();
						if (body) msg += `: ${body}`;
					} catch {}
					throw new Error(msg);
				}
				const data = (await res.json()) as any;
				const list: Post[] = Array.isArray(data) ? data : (data.posts as Post[]);
				const total = Array.isArray(data) ? list.length : Number(data.total || 0);

				const processed = list.map((p) => ({
					...p,
					like_count: p.like_count || 0,
					comment_count: p.comment_count || 0
				}));

				setPosts(processed);
				setTotalPosts(total);
				setPageOffset(offset);
			} catch (e: any) {
				setError(String(e?.message || e));
			} finally {
				setLoading(false);
			}
		},
		[selectedCategory, searchQuery, sortOption]
	);

	React.useEffect(() => { fetchCategories(); }, [fetchCategories]);
	React.useEffect(() => { fetchPosts(0); }, [fetchPosts]);

	React.useEffect(() => {
		const params = new URLSearchParams(window.location.search);
		if (params.get('verified') === 'true') {
			setBanner('Weryfikacja e-mail zakończona sukcesem. Możesz się teraz zalogować.');
			params.delete('verified');
			window.history.replaceState({}, document.title, `${window.location.pathname}${params.toString() ? `?${params.toString()}` : ''}`);
		} else if (params.get('email_changed') === 'true') {
			setBanner('Adres e-mail został pomyślnie zmieniony.');
			params.delete('email_changed');
			window.history.replaceState({}, document.title, `${window.location.pathname}${params.toString() ? `?${params.toString()}` : ''}`);
		}
	}, []);

	React.useEffect(() => {
		if (!previewOpen) return;
		const el = previewRef.current;
		if (!el) return;
		highlightCodeBlocks(el);
		const cleanup = attachFancybox(el);
		return cleanup;
	}, [previewOpen, newContent]);

	React.useEffect(() => {
		if (adminMenuPostId == null) return;
		function close() { setAdminMenuPostId(null); }
		document.addEventListener('mousedown', close);
		document.addEventListener('touchstart', close);
		return () => {
			document.removeEventListener('mousedown', close);
			document.removeEventListener('touchstart', close);
		};
	}, [adminMenuPostId]);

	React.useEffect(() => {
		if (lastOffsetRef.current !== null && lastOffsetRef.current !== pageOffset && !loading) {
			listTopRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
		}
		lastOffsetRef.current = pageOffset;
	}, [pageOffset, loading]);

	async function adminTogglePin(post: Post) {
		if (!user || user.role !== 'admin') return;
		setAdminActionPostId(post.id);
		try {
			const next = !post.is_pinned;
			await apiFetch(`/admin/posts/${post.id}/pin`, {
				method: 'POST',
				headers: getSecurityHeaders('POST'),
				body: JSON.stringify({ pinned: next })
			});
			setAdminMenuPostId(null);
			await fetchPosts(pageOffset);
		} catch {
			return;
		} finally {
			setAdminActionPostId(null);
		}
	}

	async function adminDeletePost(post: Post) {
		if (!user || user.role !== 'admin') return;
		if (!confirm('Czy na pewno chcesz usunąć ten post? Tej operacji nie można cofnąć.')) return;
		setAdminActionPostId(post.id);
		try {
			await apiFetch(`/admin/posts/${post.id}`, {
				method: 'DELETE',
				headers: getSecurityHeaders('DELETE')
			});
			setAdminMenuPostId(null);
			await fetchPosts(pageOffset);
		} catch {
			return;
		} finally {
			setAdminActionPostId(null);
		}
	}

	async function adminMovePost(post: Post, categoryId: number | null) {
		if (!user || user.role !== 'admin') return;
		setAdminActionPostId(post.id);
		try {
			await apiFetch(`/admin/posts/${post.id}/move`, {
				method: 'POST',
				headers: getSecurityHeaders('POST'),
				body: JSON.stringify({ category_id: categoryId })
			});
			setAdminMenuPostId(null);
			await fetchPosts(pageOffset);
		} catch {
			return;
		} finally {
			setAdminActionPostId(null);
		}
	}

	async function createPost(e: React.FormEvent) {
		e.preventDefault();
		if (!user) { window.location.href = '/login'; return; }

		setCreateError('');
		const titleErr = validateText(newTitle, 'tytuł');
		if (titleErr) return setCreateError(titleErr);
		const contentErr = validateText(newContent, 'treść');
		if (contentErr) return setCreateError(contentErr);
		if (newTitle.length > 30) return setCreateError('Tytuł jest zbyt długi (maksymalnie 30 znaków)');
		if (newContent.length > 3000) return setCreateError('Treść jest zbyt długa (maksymalnie 3000 znaków)');
		if (turnstileActive && !turnstileToken) return setCreateError('Proszę wypełnić weryfikację CAPTCHA');

		setCreateLoading(true);
		try {
			await apiFetch<{ success: boolean }>('/posts', {
				method: 'POST',
				headers: getSecurityHeaders('POST'),
				body: JSON.stringify({
					title: newTitle,
					content: newContent,
					category_id: newCategoryId ? Number(newCategoryId) : null,
					'cf-turnstile-response': turnstileToken
				})
			});
			setNewTitle('');
			setNewContent('');
			setNewCategoryId('');
			setTurnstileToken('');
			setTurnstileResetKey((v) => v + 1);
			setCreateOpen(false);
			await fetchPosts(0);
		} catch (e: any) {
			setCreateError(String(e?.message || e));
			setTurnstileToken('');
			setTurnstileResetKey((v) => v + 1);
		} finally {
			setCreateLoading(false);
		}
	}

	const currentPage = Math.floor(pageOffset / pageLimit) + 1;
	const totalPages = Math.max(1, Math.ceil(totalPosts / pageLimit));
	const pages: Array<number | 'ellipsis'> = [];
	if (totalPages <= 7) {
		for (let p = 1; p <= totalPages; p++) pages.push(p);
	} else {
		const start = Math.max(2, currentPage - 2);
		const end = Math.min(totalPages - 1, currentPage + 2);
		pages.push(1);
		if (start > 2) pages.push('ellipsis');
		for (let p = start; p <= end; p++) pages.push(p);
		if (end < totalPages - 1) pages.push('ellipsis');
		pages.push(totalPages);
	}

	function getCoverImageUrl(markdown: string) {
		const mdMatch = markdown.match(/!\[[^\]]*\]\(([^)\s]+)\)/i);
		const htmlMatch = markdown.match(/<img[^>]+src=["']([^"']+)["']/i);
		let url = mdMatch?.[1] || htmlMatch?.[1] || '';
		if (!url) return '';
		if (!/^https?:\/\//i.test(url) && !url.startsWith('/') && !url.startsWith('data:')) {
			url = `/r2/${url.replace(/^\/+/, '')}`;
		}
		return url;
	}

	return (
		<PageShell>
			<div className="space-y-6">
				{banner ? <div className="rounded-md border bg-muted/40 p-3 text-sm">{banner}</div> : null}
				<div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
					<div>
						<h1 className="text-2xl font-semibold tracking-tight">Jimbo77 Community</h1>
						<p className="text-sm text-muted-foreground">Forum społeczności — Cloudflare Workers, Pages, D1, R2.</p>
					</div>
					<div className="flex items-center gap-2">
						<label className="text-sm text-muted-foreground" htmlFor="category-filter">
							Kategoria
						</label>
						<select
							id="category-filter"
							className="h-9 rounded-md border bg-background px-3 text-sm"
							value={selectedCategory}
							onChange={(e) => { setSelectedCategory(e.target.value); setPageOffset(0); }}
						>
							<option value="">Wszystkie</option>
							<option value="uncategorized">Bez kategorii</option>
							{categories.map((c) => (
								<option key={c.id} value={String(c.id)}>{c.name}</option>
							))}
						</select>
						<label className="text-sm text-muted-foreground" htmlFor="sort-filter">
							Sortuj
						</label>
						<select
							id="sort-filter"
							className="h-9 rounded-md border bg-background px-3 text-sm"
							value={sortOption}
							onChange={(e) => { setSortOption(e.target.value); setPageOffset(0); }}
						>
							<option value="time_desc">Najnowsze</option>
							<option value="time_asc">Najstarsze</option>
							<option value="likes_desc">Najwięcej polubień</option>
							<option value="comments_desc">Najwięcej komentarzy</option>
							<option value="views_desc">Najwięcej wyświetleń</option>
						</select>
						<form
							className="flex items-center gap-2"
							onSubmit={(e) => { e.preventDefault(); setPageOffset(0); setSearchQuery(searchInput.trim()); }}
						>
							<Input
								value={searchInput}
								onChange={(e) => setSearchInput(e.target.value)}
								placeholder="Szukaj w tytule/treści"
								className="h-9 w-48"
							/>
							<Button variant="outline" size="sm" type="submit" disabled={loading}>
								<Search className="h-4 w-4" />
								<span className="sr-only">Szukaj</span>
							</Button>
							{searchInput || searchQuery ? (
								<Button
									variant="outline"
									size="sm"
									type="button"
									onClick={() => { setSearchInput(''); setSearchQuery(''); setPageOffset(0); }}
									disabled={loading}
								>
									<X className="h-4 w-4" />
									<span className="sr-only">Wyczyść</span>
								</Button>
							) : null}
						</form>
						<Button variant="outline" size="sm" onClick={() => fetchPosts(0)} disabled={loading}>
							<RefreshCw className="h-4 w-4" />
							<span className="sr-only">Odśwież</span>
						</Button>
					</div>
				</div>

				{user ? (
					<Card>
						<CardHeader>
							<CardTitle className="flex items-center justify-between gap-2">
								<span>Nowy post</span>
								<Button type="button" variant="outline" size="sm" onClick={() => setCreateOpen((v) => !v)}>
									{createOpen ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
									<span className="sr-only">{createOpen ? 'Zwiń' : 'Rozwiń'}</span>
								</Button>
							</CardTitle>
						</CardHeader>
						<CardContent>
							{!createOpen ? (
								<div className="text-sm text-muted-foreground">Kliknij przycisk po prawej, aby rozwinąć edytor.</div>
							) : (
								<form className="space-y-4" onSubmit={createPost}>
									{createError ? <div className="rounded-md border border-destructive/50 bg-destructive/5 p-3 text-sm text-destructive">{createError}</div> : null}
									<div className="space-y-4">
										<div className="space-y-2">
											<Label htmlFor="new-title">Tytuł</Label>
											<Input id="new-title" maxLength={30} value={newTitle} onChange={(e) => setNewTitle(e.target.value)} required />
										</div>
										<div className="space-y-2">
											<Label htmlFor="new-category">Kategoria (opcjonalna)</Label>
											<select
												id="new-category"
												className="h-9 w-full rounded-md border bg-background px-3 text-sm"
												value={newCategoryId}
												onChange={(e) => setNewCategoryId(e.target.value)}
											>
												<option value="">Bez kategorii</option>
												{categories.map((c) => (
													<option key={c.id} value={String(c.id)}>{c.name}</option>
												))}
											</select>
										</div>
									</div>
									<div className="space-y-2">
										<div className="flex flex-wrap items-center justify-between gap-2">
											<Label htmlFor="new-content">Treść (obsługuje Markdown)</Label>
											<div className="flex items-center gap-2">
												<span className="text-xs text-muted-foreground">Skróty: Ctrl+1/2/3, Ctrl+B/I/U, Ctrl+K, Ctrl+Shift+K</span>
												<Button type="button" variant="outline" size="sm" onClick={() => setPreviewOpen((v) => !v)}>
													{previewOpen ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
													<span className="sr-only">{previewOpen ? 'Ukryj podgląd' : 'Pokaż podgląd'}</span>
												</Button>
											</div>
										</div>
										<div className={previewOpen ? 'grid gap-3 lg:grid-cols-2' : 'space-y-2'}>
											<div className="space-y-2">
												<Textarea
													id="new-content"
													ref={newContentRef}
													value={newContent}
													onChange={(e) => setNewContent(e.target.value)}
													onKeyDown={handleEditorKeyDown}
													rows={10}
													className="min-h-[220px]"
													required
												/>
												<div className="text-xs text-muted-foreground">Ctrl+T tabela, Ctrl+Shift+M formuła, Ctrl+Shift+Q cytat, Alt+Shift+5 przekreślenie</div>
											</div>
											{previewOpen ? (
												<div className="rounded-md border bg-muted/20 p-3">
													<div className="mb-2 text-xs font-medium text-muted-foreground">Podgląd</div>
													<div
														ref={previewRef}
														className="prose max-w-none break-words [&_ul]:list-disc [&_ul]:pl-6 [&_ol]:list-decimal [&_ol]:pl-6 [&_li]:my-1"
														dangerouslySetInnerHTML={{ __html: renderMarkdownToHtml(newContent || '') }}
													/>
												</div>
											) : null}
										</div>
									</div>
									<div className="space-y-2">
										<label className="block text-sm font-medium text-muted-foreground">Prześlij zdjęcie</label>
										<input
											type="file"
											accept="image/*"
											className="block w-full text-sm"
											onChange={async (e) => {
												const file = e.target.files && e.target.files[0];
												if (!file) return;
												setUploadError('');
												if (file.size > 2 * 1024 * 1024) { setUploadError('Plik jest zbyt duży (maksymalnie 2MB)'); return; }
												setUploadLoading(true);
												try {
													const formData = new FormData();
													formData.append('file', file);
													formData.append('type', 'post');
													const res = await fetch('/api/upload', {
														method: 'POST',
														headers: getSecurityHeaders('POST', null),
														body: formData
													});
													const data = await res.json();
													if (!res.ok) throw new Error(data?.error || 'Błąd przesyłania');
													insertIntoContent(`\n\n![](${data.url})\n\n`);
													setPreviewOpen(true);
												} catch (err: any) {
													setUploadError(String(err?.message || err));
												} finally {
													setUploadLoading(false);
												}
											}}
										/>
										{uploadError ? <div className="text-sm text-destructive">{uploadError}</div> : null}
										{uploadLoading ? <div className="text-sm text-muted-foreground">Przesyłanie…</div> : null}
									</div>
									<TurnstileWidget enabled={turnstileActive} siteKey={siteKey} onToken={setTurnstileToken} resetKey={turnstileResetKey} />
									<Button type="submit" disabled={createLoading}>
										{createLoading ? 'Publikowanie...' : 'Opublikuj'}
									</Button>
								</form>
							)}
						</CardContent>
					</Card>
				) : (
					<Card>
						<CardContent className="py-6 text-sm text-muted-foreground">
							<a className="text-foreground underline" href="/login">Zaloguj się</a>{' '}
							aby publikować posty, polubienia i komentarze.
						</CardContent>
					</Card>
				)}

				{error ? <div className="rounded-md border border-destructive/50 bg-destructive/5 p-3 text-sm text-destructive">{error}</div> : null}

				<div className="space-y-4">
					<div ref={listTopRef} />
					{loading ? (
						<Card><CardContent className="py-6 text-sm text-muted-foreground">Ładowanie...</CardContent></Card>
					) : posts.length === 0 ? (
						<Card><CardContent className="py-6 text-sm text-muted-foreground">Brak postów</CardContent></Card>
					) : (
						posts.map((p) => {
							const coverUrl = getCoverImageUrl(p.content || '');
							const isAdmin = user?.role === 'admin';
							const menuOpen = adminMenuPostId === p.id;
							const actionLoading = adminActionPostId === p.id;
							return (
								<Card key={p.id}>
									<CardContent className="py-5">
										<div className="flex gap-4">
											{coverUrl ? (
												<img src={coverUrl} alt="" className="h-20 w-28 shrink-0 rounded-md object-cover" loading="lazy" referrerPolicy="no-referrer" />
											) : null}
											<div className="min-w-0 flex-1 space-y-1">
												<div className="flex items-start justify-between gap-2">
													<div className="flex min-w-0 items-center gap-2">
														{p.is_pinned ? (
															<span className="inline-flex items-center gap-1 rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-xs font-medium text-amber-700 dark:text-amber-300">
																<Pin className="h-3.5 w-3.5" />
																Przypięty
															</span>
														) : null}
														<a className="truncate text-lg font-semibold hover:underline" href={`/posts/${p.id}`}>{p.title}</a>
													</div>
													{isAdmin ? (
														<div className="relative">
															<Button
																type="button"
																variant="ghost"
																size="sm"
																disabled={actionLoading}
																onMouseDown={(e) => e.stopPropagation()}
																onTouchStart={(e) => e.stopPropagation()}
																onClick={(e) => { e.preventDefault(); e.stopPropagation(); setAdminMenuPostId((cur) => (cur === p.id ? null : p.id)); }}
																aria-haspopup="menu"
																aria-expanded={menuOpen}
															>
																<MoreVertical className="h-4 w-4" />
																<span className="sr-only">Więcej</span>
															</Button>
															{menuOpen ? (
																<div
																	className="absolute right-0 top-full z-50 mt-1 w-44 rounded-md border bg-background p-1 shadow-md"
																	onMouseDown={(e) => e.stopPropagation()}
																	onTouchStart={(e) => e.stopPropagation()}
																	onClick={(e) => e.stopPropagation()}
																>
																	<button
																		type="button"
																		disabled={actionLoading}
																		className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-sm hover:bg-muted disabled:opacity-50"
																		onClick={() => void adminTogglePin(p)}
																	>
																		<Pin className="h-4 w-4" />
																		{p.is_pinned ? 'Odepnij' : 'Przypnij'}
																	</button>
																	<button
																		type="button"
																		disabled={actionLoading}
																		className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-sm text-destructive hover:bg-destructive/10 disabled:opacity-50"
																		onClick={() => void adminDeletePost(p)}
																	>
																		<Trash2 className="h-4 w-4" />
																		Usuń
																	</button>
																	<div className="my-1 h-px bg-border" />
																	<div className="px-2 py-1 text-xs font-medium text-muted-foreground">Przenieś do kategorii</div>
																	<button
																		type="button"
																		disabled={actionLoading}
																		className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-sm hover:bg-muted disabled:opacity-50"
																		onClick={() => void adminMovePost(p, null)}
																	>
																		Bez kategorii
																	</button>
																	{categories.map((c) => (
																		<button
																			key={c.id}
																			type="button"
																			disabled={actionLoading}
																			className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-sm hover:bg-muted disabled:opacity-50"
																			onClick={() => void adminMovePost(p, c.id)}
																		>
																			{c.name}
																		</button>
																	))}
																</div>
															) : null}
														</div>
													) : null}
												</div>
												<div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm text-muted-foreground">
													<span className="inline-flex items-center gap-2">
														{p.author_avatar ? (
															<img src={p.author_avatar} alt="" className="h-6 w-6 rounded-full object-cover" loading="lazy" referrerPolicy="no-referrer" />
														) : (
															<span className="inline-flex h-6 w-6 items-center justify-center rounded-full bg-muted text-[10px] text-muted-foreground">
																<User className="h-4 w-4" />
															</span>
														)}
														<span className="truncate text-foreground">{p.author_name}</span>
														{p.author_role === 'admin' ? (
															<span className="inline-flex items-center gap-1 rounded border border-indigo-500/30 bg-indigo-500/10 px-1.5 py-0.5 text-[10px] font-medium text-indigo-700 dark:text-indigo-300">
																<Shield className="h-3 w-3" />
																<span className="sr-only">Administrator</span>
															</span>
														) : null}
													</span>
													{p.category_name ? (
														<><span>·</span><span className="truncate">{p.category_name}</span></>
													) : null}
													<span>·</span>
													<span className="whitespace-nowrap">{formatDate(p.created_at)}</span>
												</div>
												<div className="flex items-center gap-4 text-xs text-muted-foreground">
													<span className="inline-flex items-center gap-1"><Heart className="h-4 w-4 text-rose-600" />{p.like_count || 0}</span>
													<span className="inline-flex items-center gap-1"><MessageCircle className="h-4 w-4 text-sky-600" />{p.comment_count || 0}</span>
													<span className="inline-flex items-center gap-1"><Eye className="h-4 w-4 text-emerald-600" />{p.view_count || 0}</span>
												</div>
											</div>
										</div>
									</CardContent>
								</Card>
							);
						})
					)}
				</div>

				<div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
					<div className="flex items-center gap-2">
						<Button variant="outline" size="sm" disabled={currentPage <= 1 || loading} onClick={() => fetchPosts(Math.max(0, pageOffset - pageLimit))}>
							<ChevronLeft className="h-4 w-4" />
							<span className="sr-only">Poprzednia strona</span>
						</Button>
						<div className="flex items-center gap-1">
							{pages.map((p, idx) =>
								p === 'ellipsis' ? (
									<span key={`e-${idx}`} className="px-2 text-sm text-muted-foreground">…</span>
								) : (
									<Button key={p} variant={p === currentPage ? 'secondary' : 'outline'} size="sm" disabled={loading} onClick={() => fetchPosts((p - 1) * pageLimit)}>
										{p}
									</Button>
								)
							)}
						</div>
						<Button variant="outline" size="sm" disabled={currentPage >= totalPages || loading} onClick={() => fetchPosts(pageOffset + pageLimit)}>
							<ChevronRight className="h-4 w-4" />
							<span className="sr-only">Następna strona</span>
						</Button>
					</div>
					<form
						className="flex items-center gap-2"
						onSubmit={(e) => {
							e.preventDefault();
							const parsed = Number.parseInt(jumpTo, 10);
							if (!Number.isFinite(parsed)) return;
							const next = Math.min(Math.max(parsed, 1), totalPages);
							setJumpTo(String(next));
							fetchPosts((next - 1) * pageLimit);
						}}
					>
						<div className="text-sm text-muted-foreground">
							Strona {currentPage} / {totalPages}
						</div>
						<Input value={jumpTo} onChange={(e) => setJumpTo(e.target.value)} inputMode="numeric" placeholder="Skocz do" className="h-9 w-20" />
						<Button variant="outline" size="sm" type="submit" disabled={loading}>Skocz</Button>
					</form>
				</div>
			</div>
		</PageShell>
	);
}
