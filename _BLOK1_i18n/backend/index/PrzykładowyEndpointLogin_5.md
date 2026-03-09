// POST /api/login
if (url.pathname === '/api/login' && method === 'POST') {
  try {
    const body = await request.json() as any
    
    // Sprawdzenie Turnstile
    const ip = request.headers.get('CF-Connecting-IP') || '127.0.0.1'
    if (!await checkTurnstile(body, ip)) {
      return jsonResponse({ error: 'Turnstile verification failed' }, 403)
    }

    const { email, password, totpcode } = body
    if (!email || !password) {
      return jsonResponse({ error: 'Missing email or password' }, 400)
    }

    // Pobierz użytkownika
    const user = await env.cforumdb
      .prepare('SELECT * FROM users WHERE email = ?')
      .bind(email)
      .first<DBUser>()

    if (!user) return jsonResponse({ error: 'Username or Password Error' }, 401)
    if (!user.verified) return jsonResponse({ error: 'Please verify your email first' }, 403)

    // Weryfikacja hasła
    const passwordHash = await hashPassword(password)
    if (user.password !== passwordHash) {
      return jsonResponse({ error: 'Username or Password Error' }, 401)
    }

    // Sprawdzenie TOTP (2FA)
    if (user.totpenabled) {
      if (!totpcode) return jsonResponse({ error: 'TOTP_REQUIRED' }, 403)
      if (!user.totpsecret) return jsonResponse({ error: 'TOTP not configured' }, 500)
      
      const totp = new OTPAuth.TOTP({
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: OTPAuth.Secret.fromBase32String(user.totpsecret!),
      })
      const delta = totp.validate({ token: totpcode, window: 1 })
      if (delta === null) return jsonResponse({ error: 'Invalid TOTP code' }, 401)
    }

    // Generuj token JWT i sesję
    const { token, jti, expiresAt } = await security.generateToken({
      id: user.id,
      role: user.role!
    }, { user, email: user.email })

    await env.cforumdb.prepare(
      'INSERT INTO sessions (jti, userid, expiresat) VALUES (?, ?, ?)'
    ).bind(jti, user.id, expiresAt).run()

    await security.logAudit(user.id!, 'LOGIN', user, String(user.id!), user.email!, request)

    return jsonResponse({
      token,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        avatarurl: user.avatarurl,
        role: user.role!,
        totpenabled: !!user.totpenabled,
        emailnotifications: user.emailnotifications! ?? 1
      }
    })
  } catch (e) {
    return handleError(e)
  }
}
