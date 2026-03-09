import sendEmail from './smtp'
import { generateIdenticon } from './identicon'
import { uploadImage, deleteImage, listAllKeys, getPublicUrl, getKeyFromUrl, S3Env } from './s3'
import { as OTPAuth } from 'otpauth'
import { Security, UserPayload } from './security'

// Interfejs użytkownika bazy danych
interface DBUser {
  id: number
  email: string
  username: string
  password: string
  verified: number
  role?: string
  avatarurl?: string
  totpsecret?: string
  totpenabled?: number
  emailnotifications?: number
  resettoken?: string
  resettokenexpires?: number
  pendingemail?: string
  verificationtoken?: string
  emailchangetoken?: string
}

interface PostAuthorInfo {
  title: string
  authorid: number
  email: string
  emailnotifications: number
  username: string
}

interface DBUserEmail {
  email: string
}

interface DBUserTotp {
  totpsecret: string
}

interface DBCount {
  count: number
}

interface DBSetting {
  value: string
}
