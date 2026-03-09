export default {
  async fetch(request: Request, env: any, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url)
    const method = request.method

    // Funkcja pomocnicza do pobierania URL-u bazowego
    const getBaseUrl = () => {
      // Priorytet: 1. Zmienna env 2. Nagłówek X-Original-URL 3. Origin requestu
      if (env.BASEURL) {
        console.log('Używanie BASEURL z env:', env.BASEURL)
        return env.BASEURL
      }
      const xOriginalUrl = request.headers.get('X-Original-URL')
      if (xOriginalUrl) {
        console.log('Używanie X-Original-URL z Pages Functions:', xOriginalUrl)
        return xOriginalUrl
      }
      console.warn('BASEURL nie skonfigurowany i brak nagłówka X-Original-URL, fallback do origin requestu:', url.origin)
      return url.origin
    }

    // Nagłówki CORS
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, HEAD, POST, OPTIONS, DELETE, PUT',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Timestamp, X-Nonce',
    }

    // Obsługa preflight OPTIONS CORS
    if (method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders })
    }

    // Pomocnik zwracający JSON z CORS
    const jsonResponse = (data: any, status = 200) =>
      Response.json(data, { status, headers: corsHeaders })

    // ... reszta handlera (autentykacja, routing endpointów)
  }
}
