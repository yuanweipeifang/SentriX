import type { LoadState } from '../../hooks/useDashboardData'

interface DataStatusBannerProps {
  loadState: LoadState
  errorMessage?: string
}

export function DataStatusBanner({ loadState, errorMessage }: DataStatusBannerProps) {
  if (loadState === 'loading') {
    return (
      <div className="panel data-status-banner tone-loading-soft">
        <div className="mini-title text-blue">Connecting Backend</div>
        <div className="muted">正在请求后端 `/api/frontend-payload`，页面会在真实数据返回后自动刷新。</div>
      </div>
    )
  }

  if (loadState === 'fallback') {
    return (
      <div className="panel data-status-banner">
        <div className="mini-title text-orange">Data Unavailable</div>
        <div className="muted">后端真实数据暂不可用，当前页面展示空状态。原因：{errorMessage || 'unknown'}</div>
      </div>
    )
  }

  return (
    <div className="panel data-status-banner tone-info-soft">
      <div className="mini-title text-blue">Live Data Connected</div>
      <div className="muted">当前页面已从后端 `/api/frontend-payload` 成功获取真实数据。</div>
    </div>
  )
}
