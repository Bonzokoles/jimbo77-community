# Jimbo77 Community Forum

Jimbo77 Community Forum to forum społeczności **Jimbo77.org**, zbudowane na Cloudflare Workers, D1, R2 oraz React 19.

## Funkcje

- Posty: tworzenie, edycja, usuwanie, przypinanie, kategorie
- Komentarze: wątki z odpowiedziami, podstawowa moderacja
- Użytkownicy: rejestracja, logowanie, weryfikacja e‑mail, 2FA (TOTP)
- Upload obrazków: wysyłka do R2 z podglądem w Markdown
- Profil: avatar, opis, ustawienia powiadomień
- Panel admina: użytkownicy, kategorie, konfiguracja systemu
- Statystyki: licznik wyświetleń posta, polubienia
- Ochrona: Cloudflare Turnstile, JWT, sesje, audit logi

## Stos technologiczny

- **Backend:** Cloudflare Workers (TypeScript)
- **Baza danych:** Cloudflare D1 (SQLite)
- **Storage:** Cloudflare R2 (obrazy postów i avatary)
- **Frontend:** React 19 + Vite + TailwindCSS
- **Infra:** Cloudflare Pages + hybrydowy routing (Pages + Worker)

## Uruchomienie lokalne

1. Zainstaluj zależności:

   ```bash
   npm install
Zbuduj frontend:

bash
npm run build:frontend
Uruchom Workers lokalnie:

bash
npm run dev
Aplikacja będzie dostępna pod adresem:

Worker: http://localhost:8787

Frontend (Pages dev): http://localhost:8788 (przy użyciu npm run dev:pages)

Zmienne środowiskowe (sekrety Workers)
W Cloudflare Dashboard / przez wrangler secret skonfiguruj:

JWT_SECRET – losowy, silny sekret do podpisywania tokenów

BASE_URL – publiczny adres forum, np. https://community.jimbo77.org

SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS – dane SMTP

SMTP_FROM – adres nadawcy, np. no-reply@jimbo77.org

SMTP_FROM_NAME – nazwa nadawcy, np. Jimbo77 Community

TURNSTILE_SITE_KEY, TURNSTILE_SECRET_KEY – klucze Cloudflare Turnstile

Domyślny administrator
Po wykonaniu migracji i inicjalizacji bazy tworzone jest konto administratora:

E‑mail: karol.bonzo@yahoo.com

Hasło: Admin@123 (zalecana natychmiastowa zmiana po pierwszym logowaniu)

Licencja
Projekt oparty jest na kodzie CForum (MIT). Ten fork również udostępniany jest na licencji MIT.
Szczegóły znajdziesz w pliku LICENSE w repozytorium źródłowym CForum.

text

***

### schema.sql
```sql
DROP TABLE IF EXISTS comments;
DROP TABLE IF EXISTS likes;
DROP TABLE IF EXISTS posts;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS settings;
DROP TABLE IF EXISTS nonces;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS categories;

CREATE TABLE users (
id INTEGER PRIMARY KEY AUTOINCREMENT,
email TEXT NOT NULL UNIQUE,
username TEXT NOT NULL,
password TEXT NOT NULL,
role TEXT DEFAULT 'user', -- 'user' or 'admin'
verified INTEGER DEFAULT 0,
verification_token TEXT,
totp_secret TEXT,
totp_enabled INTEGER DEFAULT 0,
reset_token TEXT,
reset_token_expires INTEGER, -- Timestamp
pending_email TEXT,
email_change_token TEXT,
avatar_url TEXT,
nickname TEXT,
email_notifications INTEGER DEFAULT 1,
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE categories (
id INTEGER PRIMARY KEY AUTOINCREMENT,
name TEXT NOT NULL UNIQUE,
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE posts (
id INTEGER PRIMARY KEY AUTOINCREMENT,
author_id INTEGER NOT NULL,
title TEXT NOT NULL,
content TEXT NOT NULL,
category_id INTEGER,
is_pinned INTEGER DEFAULT 0,
view_count INTEGER NOT NULL DEFAULT 0,
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
FOREIGN KEY (author_id) REFERENCES users(id),
FOREIGN KEY (category_id) REFERENCES categories(id)
);

CREATE TABLE comments (
id INTEGER PRIMARY KEY AUTOINCREMENT,
post_id INTEGER NOT NULL,
parent_id INTEGER,
author_id INTEGER NOT NULL,
content TEXT NOT NULL,
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
FOREIGN KEY (post_id) REFERENCES posts(id),
FOREIGN KEY (parent_id) REFERENCES comments(id),
FOREIGN KEY (author_id) REFERENCES users(id)
);

CREATE TABLE likes (
id INTEGER PRIMARY KEY AUTOINCREMENT,
post_id INTEGER NOT NULL,
user_id INTEGER NOT NULL,
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
UNIQUE(post_id, user_id),
FOREIGN KEY (post_id) REFERENCES posts(id),
FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE settings (
key TEXT PRIMARY KEY,
value TEXT
);

CREATE TABLE nonces (
nonce TEXT PRIMARY KEY,
expires_at INTEGER NOT NULL
);

CREATE TABLE sessions (
jti TEXT PRIMARY KEY,
user_id INTEGER NOT NULL,
expires_at INTEGER NOT NULL,
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE audit_logs (
id INTEGER PRIMARY KEY AUTOINCREMENT,
user_id INTEGER,
action TEXT NOT NULL,
resource_type TEXT,
resource_id TEXT,
details TEXT,
ip_address TEXT,
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO settings (key, value) VALUES ('turnstile_enabled', '0');

-- Insert some dummy data
-- Admin user (karol.bonzo@yahoo.com / Admin@123)
INSERT INTO users (email, username, password, role, verified, nickname) VALUES
('karol.bonzo@yahoo.com', 'Admin', 'e86f78a8a3caf0b60d8e74e5942aa6d86dc150cd3c03338aef25b7d2d7e3acc7', 'admin', 1, 'System Admin'),
('alice@example.com', 'Alice', 'ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f', 'user', 1, 'Alice Wonderland'),
('bob@example.com', 'Bob', 'ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f', 'user', 0, NULL);

INSERT INTO categories (name) VALUES ('Ogólne'), ('Tech'), ('Random');

INSERT INTO posts (author_id, title, content, category_id) VALUES (1, 'Welcome to Jimbo77 Community', 'This is an official announcement from the admin.', 1);
INSERT INTO posts (author_id, title, content, category_id) VALUES (2, 'Hello World', 'This is the first post by Alice!', 2);
