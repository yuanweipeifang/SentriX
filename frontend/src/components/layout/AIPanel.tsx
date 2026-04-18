import { SectionTitle } from '../common/SectionTitle'
import type { AiPanelMessage } from '../../types/frontendPayload'

interface AIPanelProps {
  title: string
  subtitle: string
  messages: AiPanelMessage[]
}

export function AIPanel({ title, subtitle, messages }: AIPanelProps) {
  return (
    <aside className="ai-panel">
      <div className="panel ai-panel-inner">
        <SectionTitle eyebrow="LLM Console" title={title} tone="eyebrow-violet" />
        <p className="muted ai-subtitle">{subtitle}</p>
        <div className="message-list">
          {messages.length > 0 ? (
            messages.map((message) => (
              <article key={message.id} className={`message-card role-${message.role}`}>
                <div className="message-meta">{message.meta}</div>
                <div className="message-title">{message.title}</div>
                <div className="message-content">{message.content}</div>
              </article>
            ))
          ) : (
            <div className="empty-state">等待后端返回 AI 运行信息</div>
          )}
        </div>
        <div className="panel ai-floating-note">
          <div className="mini-title">真实数据链路</div>
          <div className="muted">
            当前页面仅消费后端 `frontend_payload`；接口未返回前展示空态，不再注入任何示例事件内容。
          </div>
        </div>
      </div>
    </aside>
  )
}
