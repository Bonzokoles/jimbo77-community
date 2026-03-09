export function validateText(value: string, fieldName: string): string {
	if (!value || !value.trim()) {
		return `Pole "${fieldName}" nie może być puste`;
	}
	if (value.trim().length < 2) {
		return `Pole "${fieldName}" musi mieć co najmniej 2 znaki`;
	}
	return '';
}

export function validateUsername(value: string): string {
	if (!value || !value.trim()) return 'Nazwa użytkownika nie może być pusta';
	if (value.length < 3) return 'Nazwa użytkownika musi mieć co najmniej 3 znaki';
	if (value.length > 30) return 'Nazwa użytkownika może mieć maksymalnie 30 znaków';
	if (!/^[a-zA-Z0-9_-]+$/.test(value)) return 'Nazwa użytkownika może zawierać tylko litery, cyfry, _ i -';
	return '';
}

export function validatePassword(value: string): string {
	if (!value) return 'Hasło nie może być puste';
	if (value.length < 8) return 'Hasło musi mieć co najmniej 8 znaków';
	return '';
}

export function validateEmail(value: string): string {
	if (!value || !value.trim()) return 'Adres e-mail nie może być pusty';
	if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return 'Podaj prawidłowy adres e-mail';
	return '';
}
