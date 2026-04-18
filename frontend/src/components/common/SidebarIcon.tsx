interface SidebarIconProps {
  id: string
}

export function SidebarIcon({ id }: SidebarIconProps) {
  switch (id) {
    case 'dashboard':
      return (
        <svg viewBox="0 0 24 24" className="nav-svg" aria-hidden="true">
          <rect x="4" y="4" width="6" height="6" rx="1.5" />
          <rect x="14" y="4" width="6" height="10" rx="1.5" />
          <rect x="4" y="14" width="6" height="6" rx="1.5" />
          <rect x="14" y="18" width="6" height="2" rx="1" />
        </svg>
      )
    case 'analysis':
      return (
        <svg viewBox="0 0 24 24" className="nav-svg" aria-hidden="true">
          <path d="M5 18V6" />
          <path d="M11 18V10" />
          <path d="M17 18v-5" />
          <path d="M3 20h18" />
        </svg>
      )
    case 'evidence':
      return (
        <svg viewBox="0 0 24 24" className="nav-svg" aria-hidden="true">
          <circle cx="6" cy="7" r="2" />
          <circle cx="18" cy="6" r="2" />
          <circle cx="12" cy="17" r="2" />
          <path d="M8 7h8" />
          <path d="M7.5 8.5 11 15" />
          <path d="M16.5 8 13 15" />
        </svg>
      )
    case 'hunt':
      return (
        <svg viewBox="0 0 24 24" className="nav-svg" aria-hidden="true">
          <circle cx="10" cy="10" r="5.5" />
          <path d="m14.5 14.5 5 5" />
        </svg>
      )
    case 'execution':
      return (
        <svg viewBox="0 0 24 24" className="nav-svg" aria-hidden="true">
          <path d="M5 6h7" />
          <path d="M12 6l-2-2" />
          <path d="M12 6l-2 2" />
          <path d="M19 18h-7" />
          <path d="M12 18l2-2" />
          <path d="M12 18l2 2" />
          <path d="M7 8v8" />
          <path d="M17 8v8" />
        </svg>
      )
    case 'history':
      return (
        <svg viewBox="0 0 24 24" className="nav-svg" aria-hidden="true">
          <path d="M12 7v5l3 2" />
          <path d="M5.5 9A7 7 0 1 1 5 12" />
          <path d="M5 5v4h4" />
        </svg>
      )
    case 'settings':
      return (
        <svg viewBox="0 0 24 24" className="nav-svg" aria-hidden="true">
          <circle cx="12" cy="12" r="3" />
          <path d="M19 12a7 7 0 0 0-.08-1l2.05-1.6-2-3.46-2.45 1a7.4 7.4 0 0 0-1.74-1L14.5 3h-4l-.28 2.94c-.62.23-1.21.57-1.74 1l-2.45-1-2 3.46L6.08 11a7 7 0 0 0 0 2l-2.05 1.6 2 3.46 2.45-1c.53.43 1.12.77 1.74 1L10.5 21h4l.28-2.94c.62-.23 1.21-.57 1.74-1l2.45 1 2-3.46L18.92 13c.05-.33.08-.66.08-1Z" />
        </svg>
      )
    default:
      return (
        <svg viewBox="0 0 24 24" className="nav-svg" aria-hidden="true">
          <circle cx="12" cy="12" r="7" />
        </svg>
      )
  }
}
