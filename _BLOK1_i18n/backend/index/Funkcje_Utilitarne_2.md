// Narzędzie do wyciągania URL-i obrazów z treści Markdown
function extractImageUrls(content: string): string[] {
  if (!content) return []
  const urls: string[] = []
  const regex = /!\[.*?\]\((.*?)\)/g
  let match: RegExpExecArray | null
  while ((match = regex.exec(content)) !== null) {
    urls.push(match[1])
  }
  return urls
}

// Narzędzie do hashowania hasła
async function hashPassword(password: string): Promise<string> {
  const myText = new TextEncoder().encode(password)
  const myDigest = await crypto.subtle.digest('SHA-256', myText)
  const hashArray = Array.from(new Uint8Array(myDigest))
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
  return hashHex
}

function generateToken(): string {
  return crypto.randomUUID()
}

// Sprawdza znaki sterujące w stringu
function hasControlCharacters(str: string): boolean {
  return /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(str)
}

// Sprawdza czy string jest wizualnie pusty
function isVisuallyEmpty(str: string): boolean {
  if (!str) return true
  const stripped = str.replace(/[\u200B-\u200F\u2028\u2029\u180E\u3164\u115F-\u1160\u0000-\u001F\u007F]/g, '')
  return stripped.length === 0
}

// Sprawdza niewidoczne znaki
function hasInvisibleCharacters(str: string): boolean {
  return /[\u200B-\u200F\u2028\u2029\u180E\u3164\u115F\u1160]/.test(str)
}

// Sprawdza zabronione słowa kluczowe
function hasRestrictedKeywords(username: string): boolean {
  const restricted = ['admin', 'sudo', 'test']
  return restricted.some(keyword => username.toLowerCase().includes(keyword.toLowerCase()))
}
