// CSF mark: a faceted shield whose three tapering bars are the cascade
// (broad, cheap checks first; narrower, costlier stages after).
export default function Logo({ size = 38 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 40 40" fill="none" aria-label="CSF" role="img">
      <defs>
        <linearGradient id="lg-l" x1="6" y1="4" x2="20" y2="36" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#5f8df4" />
          <stop offset="1" stopColor="#1b46b4" />
        </linearGradient>
        <linearGradient id="lg-r" x1="20" y1="4" x2="34" y2="36" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#2f63d8" />
          <stop offset="1" stopColor="#0d2f84" />
        </linearGradient>
        <linearGradient id="lg-edge" x1="0" y1="0" x2="40" y2="40" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#ffffff" stopOpacity=".7" />
          <stop offset="1" stopColor="#ffffff" stopOpacity=".05" />
        </linearGradient>
      </defs>
      <path d="M20 3 L34 8.2 V19.5 C34 28 28 33.8 20 37 C12 33.8 6 28 6 19.5 V8.2 Z" fill="url(#lg-l)" />
      <path d="M20 3 L34 8.2 V19.5 C34 28 28 33.8 20 37 Z" fill="url(#lg-r)" />
      <path d="M20 3 L34 8.2 V19.5 C34 28 28 33.8 20 37 C12 33.8 6 28 6 19.5 V8.2 Z"
        stroke="url(#lg-edge)" strokeWidth="1" />
      <path d="M20 3 V37" stroke="#fff" strokeOpacity=".16" />
      <rect x="12" y="13" width="16" height="2.8" rx="1.4" fill="#fff" />
      <rect x="14.5" y="18.4" width="11" height="2.8" rx="1.4" fill="#fff" fillOpacity=".82" />
      <rect x="17" y="23.8" width="6" height="2.8" rx="1.4" fill="#fff" fillOpacity=".62" />
    </svg>
  )
}
