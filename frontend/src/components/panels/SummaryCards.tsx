import type { SummaryCard } from '../../types/frontendPayload'

interface SummaryCardsProps {
  cards: SummaryCard[]
  cardToneMap: Record<string, string>
}

export function SummaryCards({ cards, cardToneMap }: SummaryCardsProps) {
  if (cards.length === 0) {
    return <section className="empty-state">等待后端返回摘要卡片</section>
  }

  return (
    <section className="cards-grid">
      {cards.map((card) => (
        <article key={card.key} className={`panel card-panel ${cardToneMap[card.tone] ?? 'tone-default'}`}>
          <div className="card-label">{card.label}</div>
          <div className="card-value">{card.value || '暂无数据'}</div>
        </article>
      ))}
    </section>
  )
}
