declare module 'otpauth' {
	export class TOTP {
		constructor(config: {
			issuer?: string;
			label?: string;
			algorithm?: string;
			digits?: number;
			period?: number;
			secret?: Secret;
		});
		generate(): string;
		validate(options: { token: string; window?: number }): number | null;
		toString(): string;
	}

	export class Secret {
		constructor(config?: { buffer?: ArrayBuffer; size?: number });
		static fromBase32(base32: string): Secret;
		base32: string;
	}

	export class URI {
		static parse(uri: string): TOTP;
	}
}
