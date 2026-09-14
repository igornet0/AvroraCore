export function Brand({
  tagline = 'Secure · Reliable · Intelligent',
  size = 'md',
}: {
  tagline?: string
  size?: 'sm' | 'md' | 'lg'
}) {
  return (
    <div className={`brand brand-${size}`}>
      <img
        className="brand-logo"
        src="/icon.png"
        alt=""
        width={size === 'lg' ? 72 : size === 'sm' ? 36 : 48}
        height={size === 'lg' ? 72 : size === 'sm' ? 36 : 48}
        decoding="async"
      />
      <div className="brand-copy">
        <strong className="brand-name">Avrora</strong>
        <p className="brand-tagline">{tagline}</p>
      </div>
    </div>
  )
}
