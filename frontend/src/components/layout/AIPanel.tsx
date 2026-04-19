import { Fragment, type ReactNode, useEffect, useMemo, useRef, useState } from 'react'
import { sendCopilotChat } from '../../services/copilotApi'
import type { AiPanelMessage } from '../../types/frontendPayload'

interface AIPanelProps {
  title: string
  subtitle: string
  messages: AiPanelMessage[]
  context: {
    pageTitle: string
    eventSummary?: string
    topThreat?: string
    recommendedAction?: string
  }
}

const COPILOT_MODEL_GROUPS = [
  {
    label: 'Qwen 商业主力',
    models: [
      'qwen3-max',
      'qwen3-max-preview',
      'qwen-max',
      'qwen-max-latest',
      'qwen3.6-plus',
      'qwen3.5-plus',
      'qwen-plus',
      'qwen-plus-latest',
      'qwen-plus-us',
      'qwen3.6-flash',
      'qwen3.5-flash',
      'qwen-flash',
      'qwen-flash-us',
      'qwen-turbo',
      'qwen-turbo-latest',
    ],
  },
  {
    label: 'Qwen Coder / 推理 / 数学',
    models: [
      'qwen3-coder-plus',
      'qwen3-coder-flash',
      'qwen-coder-plus',
      'qwen-coder-plus-latest',
      'qwen-coder-turbo',
      'qwen-coder-turbo-latest',
      'qwq-plus',
      'qwq-plus-latest',
      'qwen-math-plus',
      'qwen-math-plus-latest',
      'qwen-math-turbo',
      'qwen-math-turbo-latest',
    ],
  },
  {
    label: 'Qwen 视觉',
    models: [
      'qwen-vl-plus',
      'qwen-vl-plus-latest',
      'qwen-vl-max',
      'qwen-vl-max-latest',
    ],
  },
  {
    label: 'Qwen 开源',
    models: [
      'qwen3.6-35b-a3b',
      'qwen3.5-397b-a17b',
      'qwen3.5-120b-a10b',
      'qwen3.5-35b-a3b',
      'qwen3.5-27b',
      'qwen3-next-80b-a3b-thinking',
      'qwen3-next-80b-a3b-instruct',
      'qwen3-235b-a22b',
      'qwen3-32b',
      'qwen3-30b-a3b',
      'qwen3-14b',
      'qwen3-8b',
      'qwen3-4b',
      'qwen3-1.7b',
      'qwen3-0.6b',
      'qwen2.5-72b-instruct',
      'qwen2.5-32b-instruct',
      'qwen2.5-14b-instruct',
      'qwen2.5-7b-instruct',
      'qwen2.5-3b-instruct',
      'qwen2.5-1.5b-instruct',
      'qwen2.5-0.5b-instruct',
    ],
  },
  {
    label: '快照版本',
    models: [
      'qwen3-max-2025-09-23',
      'qwen-max-2025-01-25',
      'qwen-max-2024-09-19',
      'qwen3.6-plus-2026-04-02',
      'qwen3.5-plus-2026-02-15',
      'qwen-plus-2024-12-20',
      'qwen-plus-2025-01-25',
      'qwen-plus-2025-12-01',
      'qwen-plus-2025-12-01-us',
      'qwen3.6-flash-2026-04-16',
      'qwen3.5-flash-2026-02-23',
      'qwen-flash-2025-07-28',
      'qwen-flash-2025-07-28-us',
      'qwen-turbo-2024-11-01',
      'qwen-turbo-2025-04-28',
      'qwen3-coder-plus-2025-07-22',
      'qwen3-coder-flash-2025-07-28',
      'qwen-coder-plus-2024-11-06',
      'qwen-coder-turbo-2024-09-19',
      'qwq-plus-2025-03-05',
      'qwen-math-plus-2024-08-16',
      'qwen-vl-plus-0815',
      'qwen-vl-plus-2025-01-25',
      'qwen-vl-plus-2025-07-10',
      'qwen-vl-plus-2025-08-15',
      'qwen-vl-max-0813',
      'qwen3-235b-a22b-thinking-2507',
      'qwen3-235b-a22b-instruct-2507',
      'qwen3-30b-a3b-thinking-2507',
      'qwen3-30b-a3b-instruct-2507',
      'qwen2.5-14b-instruct-1m',
      'qwen2.5-7b-instruct-1m',
    ],
  },
] as const

function normalizeSeedMessages(messages: AiPanelMessage[]): AiPanelMessage[] {
  return messages.map((message) => ({
    ...message,
    role: message.role === 'system' ? 'assistant' : message.role,
  }))
}

function renderInlineMarkdown(text: string): ReactNode[] {
  return text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g).filter(Boolean).map((part, index) => {
    if (part.startsWith('`') && part.endsWith('`')) {
      return (
        <code key={`inline-code-${index}`} className="ai-md-inline-code">
          {part.slice(1, -1)}
        </code>
      )
    }

    if (part.startsWith('**') && part.endsWith('**')) {
      return (
        <strong key={`inline-strong-${index}`} className="ai-md-strong">
          {part.slice(2, -2)}
        </strong>
      )
    }

    return <Fragment key={`inline-text-${index}`}>{part}</Fragment>
  })
}

function renderMarkdownSection(text: string, keyPrefix: string): ReactNode[] {
  return text
    .split(/\n{2,}/)
    .map((block) => block.trim())
    .filter(Boolean)
    .map((block, index) => {
      const lines = block.split('\n').map((line) => line.trimEnd())
      const bulletItems = lines.filter((line) => /^[-*]\s+/.test(line))
      const numberedItems = lines.filter((line) => /^\d+\.\s+/.test(line))
      const quoteItems = lines.filter((line) => /^>\s?/.test(line))
      const tableLike =
        lines.length >= 2 &&
        lines[0].includes('|') &&
        /^\s*\|?[\s:-]+(\|[\s:-]+)+\|?\s*$/.test(lines[1])

      if (bulletItems.length === lines.length) {
        return (
          <ul key={`${keyPrefix}-ul-${index}`} className="ai-md-list">
            {bulletItems.map((line, itemIndex) => (
              <li key={`${keyPrefix}-ul-item-${itemIndex}`}>{renderInlineMarkdown(line.replace(/^[-*]\s+/, ''))}</li>
            ))}
          </ul>
        )
      }

      if (numberedItems.length === lines.length) {
        return (
          <ol key={`${keyPrefix}-ol-${index}`} className="ai-md-list ai-md-ordered-list">
            {numberedItems.map((line, itemIndex) => (
              <li key={`${keyPrefix}-ol-item-${itemIndex}`}>{renderInlineMarkdown(line.replace(/^\d+\.\s+/, ''))}</li>
            ))}
          </ol>
        )
      }

      if (quoteItems.length === lines.length) {
        return (
          <blockquote key={`${keyPrefix}-quote-${index}`} className="ai-md-quote">
            {quoteItems.map((line, itemIndex) => (
              <p key={`${keyPrefix}-quote-item-${itemIndex}`} className="ai-md-quote-line">
                {renderInlineMarkdown(line.replace(/^>\s?/, ''))}
              </p>
            ))}
          </blockquote>
        )
      }

      if (tableLike) {
        const parseRow = (row: string) =>
          row
            .trim()
            .replace(/^\|/, '')
            .replace(/\|$/, '')
            .split('|')
            .map((cell) => cell.trim())

        const header = parseRow(lines[0])
        const bodyRows = lines.slice(2).map(parseRow)
        return (
          <div key={`${keyPrefix}-table-${index}`} className="ai-md-table-wrap">
            <table className="ai-md-table">
              <thead>
                <tr>
                  {header.map((cell, cellIndex) => (
                    <th key={`${keyPrefix}-th-${cellIndex}`}>{renderInlineMarkdown(cell)}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {bodyRows.map((row, rowIndex) => (
                  <tr key={`${keyPrefix}-tr-${rowIndex}`}>
                    {row.map((cell, cellIndex) => (
                      <td key={`${keyPrefix}-td-${rowIndex}-${cellIndex}`}>{renderInlineMarkdown(cell)}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      }

      return (
        <p key={`${keyPrefix}-p-${index}`} className="ai-md-paragraph">
          {lines.map((line, lineIndex) => (
            <Fragment key={`${keyPrefix}-line-${lineIndex}`}>
              {lineIndex > 0 ? <br /> : null}
              {renderInlineMarkdown(line)}
            </Fragment>
          ))}
        </p>
      )
    })
}

function renderMarkdownContent(content: string, onCopyCode: (code: string) => void): ReactNode[] {
  const nodes: ReactNode[] = []
  const codeBlockRegex = /```([\w-]+)?\n([\s\S]*?)```/g
  let lastIndex = 0
  let match: RegExpExecArray | null = codeBlockRegex.exec(content)
  let blockIndex = 0

  while (match) {
    const [fullMatch, language = '', code = ''] = match
    const before = content.slice(lastIndex, match.index).trim()
    if (before) {
      nodes.push(...renderMarkdownSection(before, `section-${blockIndex}`))
      blockIndex += 1
    }

    nodes.push(
      <div key={`code-${blockIndex}`} className="ai-md-code-block">
        <div className="ai-md-code-head">
          <div className="ai-md-code-label">{language || 'text'}</div>
          <button type="button" className="ai-md-code-copy" onClick={() => onCopyCode(code.trimEnd())}>
            复制代码
          </button>
        </div>
        <pre>
          <code>{code.trimEnd()}</code>
        </pre>
      </div>,
    )
    blockIndex += 1
    lastIndex = match.index + fullMatch.length
    match = codeBlockRegex.exec(content)
  }

  const rest = content.slice(lastIndex).trim()
  if (rest) {
    nodes.push(...renderMarkdownSection(rest, `section-${blockIndex}`))
  }

  return nodes.length > 0 ? nodes : [<p key="fallback" className="ai-md-paragraph" />]
}

export function AIPanel({ title, subtitle, messages, context }: AIPanelProps) {
  const seedMessages = useMemo(() => normalizeSeedMessages(messages), [messages])
  const [conversation, setConversation] = useState<AiPanelMessage[]>(seedMessages)
  const [draft, setDraft] = useState('')
  const [apiKey, setApiKey] = useState('')
  const [selectedModel, setSelectedModel] = useState('qwen-plus')
  const [showSettings, setShowSettings] = useState(false)
  const [showQuickPrompts, setShowQuickPrompts] = useState(false)
  const [isSending, setIsSending] = useState(false)
  const threadRef = useRef<HTMLDivElement | null>(null)
  const quickPromptGroups = useMemo(
    () => [
      {
        label: '页面理解',
        prompts: ['总结当前页面重点', '解释当前页面中最值得关注的信息'],
      },
      {
        label: '风险分析',
        prompts: ['解释当前风险等级并给出处置建议', '指出当前页面可能的误报或不确定项'],
      },
      {
        label: '执行建议',
        prompts: ['根据现有日志判断下一步应该做什么', '给我一个简短的排查步骤列表'],
      },
    ],
    [],
  )

  useEffect(() => {
    setConversation((current) => {
      const hasUserConversation = current.some((item) => item.role === 'user')
      return hasUserConversation ? current : seedMessages
    })
  }, [seedMessages])

  useEffect(() => {
    const node = threadRef.current
    if (!node) return
    node.scrollTop = node.scrollHeight
  }, [conversation, isSending])

  function handleClearConversation() {
    setConversation(seedMessages)
  }

  async function handleCopyReply(content: string) {
    try {
      await navigator.clipboard.writeText(content)
    } catch {
      // ignore clipboard failures in unsupported environments
    }
  }

  async function handleSend(overrideDraft?: string) {
    const message = (overrideDraft ?? draft).trim()
    if (!message || isSending) return

    const userMessage: AiPanelMessage = {
      id: `user-${Date.now()}`,
      role: 'user',
      title: '你',
      content: message,
      meta: 'INPUT',
    }

    const nextConversation = [...conversation, userMessage]
    setConversation(nextConversation)
    setDraft('')
    setIsSending(true)

    try {
      const response = await sendCopilotChat({
        message,
        apiKey: apiKey.trim() || undefined,
        model: selectedModel,
        context,
        history: nextConversation
          .filter((item) => item.role === 'user' || item.role === 'assistant')
          .map((item) => ({ role: item.role as 'user' | 'assistant', content: item.content })),
      })

      setSelectedModel(response.model || selectedModel)

      setConversation((current) => [
        ...current,
        {
          id: `assistant-${Date.now()}`,
          role: 'assistant',
          title: '副驾驶',
          content: response.reply,
          meta: `${response.provider} / ${response.model}${response.used_override_key ? ' / override' : ''}`,
        },
      ])
    } catch (error) {
      const messageText = error instanceof Error ? error.message : '副驾驶请求失败'
      setConversation((current) => [
        ...current,
        {
          id: `assistant-error-${Date.now()}`,
          role: 'assistant',
          title: '副驾驶',
          content: messageText,
          meta: 'ERROR',
        },
      ])
    } finally {
      setIsSending(false)
    }
  }

  return (
    <aside className="ai-panel">
      <div className="panel ai-panel-inner ai-copilot-panel">
        <header className="ai-panel-header">
          <div className="ai-copilot-top">
            <div>
              <div className="ai-copilot-kicker">AI Copilot</div>
              <div className="ai-workspace-title">{title}</div>
              <p className="muted ai-subtitle">{subtitle}</p>
            </div>
            <div className="ai-copilot-top-actions">
              <button type="button" className="ai-ghost-toggle" onClick={handleClearConversation}>
                清空
              </button>
              <button type="button" className="ai-settings-toggle" onClick={() => setShowSettings((value) => !value)}>
                设置
              </button>
            </div>
          </div>
          {showSettings ? (
            <div className="ai-settings-panel">
              <label className="ai-settings-field">
                <span>临时 API Key</span>
                <input
                  type="password"
                  value={apiKey}
                  onChange={(event) => setApiKey(event.target.value)}
                  placeholder="留空则使用服务端环境变量"
                />
              </label>
              <div className="ai-settings-hint">当前优先接入 Qwen / DashScope。未填写时自动走服务端环境变量。</div>
            </div>
          ) : null}
        </header>

        <div ref={threadRef} className="message-list ai-thread-list ai-copilot-thread">
          {conversation.length > 0 ? (
            conversation.map((message) => (
              <div key={message.id} className="ai-thread-item">
                <article className={`message-card ai-thread-card ai-copilot-card role-${message.role}`}>
                  <div className="ai-copilot-card-head">
                    <div>
                      <div className="message-title">{message.title}</div>
                      <div className="message-meta">{message.meta || 'Agent Event'}</div>
                    </div>
                    {message.role === 'assistant' ? (
                      <button
                        type="button"
                        className="ai-copy-button"
                        onClick={() => void handleCopyReply(message.content)}
                      >
                        复制
                      </button>
                    ) : null}
                  </div>
                  <div className="message-content ai-markdown-content">
                    {renderMarkdownContent(message.content, (code) => void handleCopyReply(code))}
                  </div>
                </article>
              </div>
            ))
          ) : (
            <div className="empty-state ai-empty-state">等待后端返回 AI 运行信息</div>
          )}
        </div>

        <div className="ai-copilot-composer">
          <div className={`ai-copilot-drawer ${showQuickPrompts ? 'is-open' : ''}`}>
            <button
              type="button"
              className="ai-copilot-drawer-toggle"
              onClick={() => setShowQuickPrompts((value) => !value)}
              aria-expanded={showQuickPrompts}
              aria-controls="ai-copilot-quick-prompts"
            >
              <span className="ai-copilot-drawer-title">快捷提问</span>
              <span className="ai-copilot-drawer-hint">{showQuickPrompts ? '收起' : '展开'}</span>
            </button>
            <div id="ai-copilot-quick-prompts" className="ai-copilot-drawer-body">
              <div className="ai-copilot-quick-groups">
                {quickPromptGroups.map((group) => (
                  <div key={group.label} className="ai-copilot-quick-group">
                    <div className="ai-copilot-quick-label">{group.label}</div>
                    <div className="ai-copilot-quick-actions">
                      {group.prompts.map((prompt) => (
                        <button
                          key={prompt}
                          type="button"
                          className="ai-copilot-quick-chip"
                          onClick={() => void handleSend(prompt)}
                          disabled={isSending}
                        >
                          {prompt}
                        </button>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
          <textarea
            className="ai-copilot-input"
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === 'Enter' && !event.shiftKey) {
                event.preventDefault()
                void handleSend()
              }
            }}
            placeholder="输入你的问题，例如：请解释当前风险等级并给出下一步动作"
            rows={4}
          />
          <div className="ai-copilot-actions">
            <label className="ai-copilot-model-picker">
              <span>模型</span>
              <select value={selectedModel} onChange={(event) => setSelectedModel(event.target.value)}>
                {COPILOT_MODEL_GROUPS.map((group) => (
                  <optgroup key={group.label} label={group.label}>
                    {group.models.map((model) => (
                      <option key={model} value={model}>
                        {model}
                      </option>
                    ))}
                  </optgroup>
                ))}
              </select>
            </label>
            <button
              type="button"
              className="ai-copilot-send"
              onClick={() => void handleSend()}
              disabled={isSending || !draft.trim()}
            >
              {isSending ? '发送中...' : '发送'}
            </button>
          </div>
        </div>
      </div>
    </aside>
  )
}
