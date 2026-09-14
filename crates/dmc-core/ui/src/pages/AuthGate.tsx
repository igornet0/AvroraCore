import { useState } from 'react'
import { api } from '../api/client'
import { Brand } from '../components/Brand'

type Mode = 'login' | 'setup-key' | 'setup-totp'

export function AuthGate({
  enrolled,
  authPath,
  onAuthed,
}: {
  enrolled: boolean
  authPath: string
  onAuthed: () => void
}) {
  const [mode, setMode] = useState<Mode>(enrolled ? 'login' : 'setup-key')
  const [accessKey, setAccessKey] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [secret, setSecret] = useState<string | null>(null)
  const [otpauthUrl, setOtpauthUrl] = useState<string | null>(null)
  const [qrPng, setQrPng] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [copied, setCopied] = useState(false)

  async function beginSetup(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const res = await api.authSetupBegin(accessKey.trim())
      setSecret(res.totp_secret)
      setOtpauthUrl(res.otpauth_url)
      setQrPng(res.qr_png_base64)
      setMode('setup-totp')
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  async function confirmSetup(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await api.authSetupConfirm(accessKey.trim(), totpCode.trim())
      onAuthed()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  async function login(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await api.authLogin(accessKey.trim(), totpCode.trim())
      onAuthed()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  async function copySecret() {
    if (!secret) return
    await navigator.clipboard.writeText(secret)
    setCopied(true)
  }

  const qrSrc = qrPng
    ? qrPng.startsWith('data:')
      ? qrPng
      : `data:image/png;base64,${qrPng}`
    : null

  return (
    <div className="unlock-screen">
      <div className="unlock-card">
        <div className="unlock-brand">
          <Brand tagline="Вход в UI" size="lg" />
        </div>

        <h1>
          {mode === 'login'
            ? 'Ключ и 2FA'
            : mode === 'setup-key'
              ? 'Первичная настройка'
              : 'Google Authenticator'}
        </h1>
        <p className="muted">
          {mode === 'login'
            ? 'Access key и 6-значный код из Google Authenticator (или другого TOTP-приложения).'
            : mode === 'setup-key'
              ? 'Задайте access key для UI (отдельно от master-ключа хранилища). Минимум 8 символов.'
              : 'Добавьте аккаунт в Google Authenticator по QR или секрету, затем введите текущий код.'}
        </p>
        <p className="mono muted path-line">{authPath}</p>

        {error && (
          <div className="banner error unlock-error" role="alert">
            {error}
          </div>
        )}

        {mode === 'setup-key' && (
          <form className="unlock-form" onSubmit={(e) => void beginSetup(e)}>
            <label>
              Access key
              <input
                type="password"
                autoComplete="new-password"
                value={accessKey}
                onChange={(e) => setAccessKey(e.target.value)}
                placeholder="не короче 8 символов"
                required
                minLength={8}
              />
            </label>
            <button type="submit" className="primary" disabled={busy}>
              {busy ? '…' : 'Далее: 2FA'}
            </button>
          </form>
        )}

        {mode === 'setup-totp' && secret && (
          <div className="auth-setup">
            {qrSrc && (
              <div className="auth-qr">
                <img src={qrSrc} alt="QR для Google Authenticator" width={180} height={180} />
              </div>
            )}
            <p className="muted">Или введите ключ вручную:</p>
            <code className="master-key-box">{secret}</code>
            <div className="row-actions">
              <button type="button" onClick={() => void copySecret()}>
                {copied ? 'Скопировано' : 'Копировать секрет'}
              </button>
              {otpauthUrl && (
                <a className="text-link" href={otpauthUrl}>
                  otpauth://
                </a>
              )}
            </div>
            <form className="unlock-form" onSubmit={(e) => void confirmSetup(e)}>
              <label>
                Код из приложения
                <input
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  pattern="[0-9]{6}"
                  maxLength={6}
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  placeholder="000000"
                  required
                />
              </label>
              <button type="submit" className="primary" disabled={busy || totpCode.length !== 6}>
                {busy ? '…' : 'Подтвердить и войти'}
              </button>
            </form>
          </div>
        )}

        {mode === 'login' && (
          <form className="unlock-form" onSubmit={(e) => void login(e)}>
            <label>
              Access key
              <input
                type="password"
                autoComplete="current-password"
                value={accessKey}
                onChange={(e) => setAccessKey(e.target.value)}
                required
                minLength={8}
              />
            </label>
            <label>
              Код 2FA
              <input
                inputMode="numeric"
                autoComplete="one-time-code"
                pattern="[0-9]{6}"
                maxLength={6}
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                placeholder="000000"
                required
              />
            </label>
            <button type="submit" className="primary" disabled={busy || totpCode.length !== 6}>
              {busy ? '…' : 'Войти'}
            </button>
          </form>
        )}
      </div>
    </div>
  )
}
