export type HuntBridgeAction = 'prefill' | 'generate'

export interface HuntBridgeIndicators {
  ioc: string[]
  cve: string[]
  host: string[]
  ip: string[]
  domain: string[]
  process: string[]
}

export interface HuntBridgePayload {
  requestId: number
  action: HuntBridgeAction
  sourceNodeId: string
  sourceNodeType: string
  sourceNodeLabel: string
  sourceNodeTitle: string
  indicators: HuntBridgeIndicators
}
