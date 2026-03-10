/**
 * Cloudflare Pages — konfiguracja deployu
 * Lokalne dev + deployment
 * 
 * Użycie:
 * - Lokalne dev: npm run dev:pages
 * - Deploy Pages: wrangler pages deploy
 */

export default {
	// Projekt Pages
	projectName: 'jimbo77-community',
	
	// Build
	build: {
		command: 'npm run build:frontend',
		outputDir: 'public'
	},
	
	// Dev
	dev: {
		port: 3010,
		local: true
	},
	
	// Routing
	routing: {
		// API → proxy do Functions/Worker
		'/api/*': 'functions/[[path]]',
		'/r2/*': 'functions/[[path]]',
		'/user': 'functions/[[path]]',
		'/user/*': 'functions/[[path]]',
		'/post/*': 'functions/[[path]]',
		'/admin': 'functions/[[path]]',
		'/settings': 'functions/[[path]]',
		
		// Statyczne pliki z public/
		'*': 'public/*'
	}
};
