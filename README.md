# Jimbo77 Community

> Forum społeczności **[jimbo77.org](https://jimbo77.org)** — zbudowane na Cloudflare Workers + D1 + R2.

[![Deploy](https://img.shields.io/badge/Cloudflare-Workers-F38020?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Funkcje

| Moduł | Opis |
|-------|------|
| **Forum** | Posty, komentarze, wątki, przypinanie, kategorie, polubienia |
| **Użytkownicy** | Rejestracja, logowanie, weryfikacja e-mail, 2FA (TOTP) |
| **Upload** | Obrazki wysyłane do R2 z podglądem Markdown |
| **Profil** | Avatar, opis, ustawienia powiadomień |
| **Admin** | Panel zarządzania użytkownikami, kategoriami, konfiguracją |
| **Bezpieczeństwo** | PBKDF2 hashing, JWT, rate limiting, CORS lock, audit logi, Turnstile |
| **AI (wkrótce)** | Chat AI, generowanie grafiki — dostępne po rejestracji |

## Stos technologiczny

- **Backend:** Cloudflare Workers (TypeScript)
- **Baza danych:** Cloudflare D1 (SQLite)
- **Storage:** Cloudflare R2 (obrazy, avatary)
- **Frontend:** React 19 + Vite + TailwindCSS
- **Infrastruktura:** Cloudflare Pages + Worker routing

## Szybki start

```bash
# 1. Zainstaluj zależności
npm install

# 2. Zbuduj frontend
npm run build:frontend

# 3. Uruchom lokalnie
npm run dev
```

| Serwis | Adres |
|--------|-------|
| Worker API | `http://localhost:8787` |
| Frontend (Pages dev) | `http://localhost:8788` |

## Konfiguracja (Cloudflare Secrets)

Ustaw przez `wrangler secret put <NAZWA>` lub w Cloudflare Dashboard:

| Sekret | Opis |
|--------|------|
| `JWT_SECRET` | Losowy sekret ≥32 znaki do podpisywania tokenów |
| `ALLOWED_ORIGIN` | Dozwolony origin dla CORS, np. `https://jimbo77.org` |
| `SMTP_HOST` | Host serwera SMTP |
| `SMTP_PORT` | Port SMTP (587 / 465) |
| `SMTP_USER` | Login SMTP |
| `SMTP_PASS` | Hasło SMTP |
| `SMTP_FROM` | Adres nadawcy, np. `no-reply@jimbo77.org` |
| `SMTP_FROM_NAME` | Nazwa nadawcy, np. `Jimbo77 Community` |
| `TURNSTILE_SITE_KEY` | Klucz publiczny Cloudflare Turnstile |
| `TURNSTILE_SECRET_KEY` | Klucz prywatny Cloudflare Turnstile |
| `RESEND_KEY` | *(opcjonalnie)* API key Resend jako fallback email |

## Struktura projektu

```
src/
├── index.ts        # Główny handler API (~2000 linii)
├── security.ts     # JWT, nonce, audit logging
└── smtp.ts         # SMTP + Resend email sending
schema.sql          # Schemat bazy D1
wrangler.jsonc      # Konfiguracja Workers
```

## Bezpieczeństwo

- **Hasła:** PBKDF2 (100k iteracji, 16B random salt) z auto-migracją legacy SHA-256
- **Rate limiting:** 10 req / 60s per IP na endpointach auth
- **CORS:** Dynamiczny origin z `ALLOWED_ORIGIN` (nie wildcard)
- **JWT:** Tokeny z krótkim TTL, blacklist przez sesje w D1
- **Nonce:** Ochrona przed replay attacks na POST/PUT/DELETE
- **Audit:** Logi operacji w tabeli `audit_logs`

## API

```
POST   /api/auth/register       Rejestracja
POST   /api/auth/login          Logowanie
POST   /api/auth/forgot-password Reset hasła
GET    /api/posts               Lista postów
POST   /api/posts               Nowy post (auth)
GET    /api/posts/:id           Szczegóły posta
POST   /api/posts/:id/comments  Komentarz (auth)
POST   /api/posts/:id/like      Polubienie (auth)
GET    /api/users               Lista użytkowników (auth)
POST   /api/upload              Upload obrazka (auth)
```

## Licencja

Projekt udostępniany na otwartej licencji **MIT**.
