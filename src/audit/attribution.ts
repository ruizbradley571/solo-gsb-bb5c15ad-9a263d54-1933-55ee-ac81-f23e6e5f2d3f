/**
 * 流量样本归因（只读）。
 *
 * 粘贴一组流量样本（每条含唯一 id、源 IP、源端口、协议 TCP/UDP/ANY 与
 * 正数权重），对当前规则按「自上而下、首条命中」语义逐条归因：
 *
 *   - TCP / UDP 样本：按对应具体协议判定一次，贡献自身权重；
 *   - ANY 样本：同一权重分别判定 TCP 与 UDP，共贡献 2×权重，
 *     两个判定的命中规则 / 动作可以不同（分别归因）。
 *
 * 结果按「命中规则 × 动作」及「未命中任何规则」汇总权重与占比，
 * 每个汇总可展开查看按权重降序排列的样本判定明细。
 *
 * 校验在逐行阶段完成：ID 重复或任一字段非法的样本行整行拒绝、
 * 不参与统计，错误按行号逐条回报。非法规则与停用规则与主审计一致
 * 地被排除，不参与首命中计算。
 */
import { validateRules } from './engine'
import type { NormalizedRule, Protocol, RuleInput } from './types'

type ConcreteProtocol = Exclude<Protocol, 'ANY'>

/** 校验通过后的规范样本 */
export interface TrafficSample {
  /** 归一化后的唯一 ID（非空字符串） */
  id: string
  srcIp: string
  /** uint32，用于排序与区间判定 */
  srcIpInt: number
  srcPort: number
  protocol: Protocol
  weight: number
  /** 在粘贴数组中的行号（从 1 起） */
  line: number
}

export interface SampleError {
  line: number
  /** 尽力提取的 ID，供错误信息定位；无法识别时为 null */
  id: string | null
  messages: string[]
}

/** 单条样本在单个具体协议下的一次判定（ANY 样本会产生两条） */
export interface AttributionItem {
  sampleId: string
  srcIp: string
  srcIpInt: number
  srcPort: number
  /** 实际判定的具体协议 */
  protocol: ConcreteProtocol
  /** 样本声明协议（ANY 样本的两条明细均标注为 ANY） */
  declaredProtocol: Protocol
  weight: number
  line: number
}

/** 汇总桶：命中某条规则（含动作）或未命中任何规则 */
export interface AttributionBucket {
  kind: 'hit' | 'miss'
  /** hit 桶：规则在输入列表中的下标（#index+1 展示）；miss 桶为 -1 */
  ruleIndex: number
  ruleName: string
  /** miss 桶恒为 null */
  action: string | null
  weight: number
  /** 占全部判定权重之和的比例 */
  ratio: number
  count: number
  /** 样本判定明细，按权重降序（再按 IP / 端口 / 协议 / ID 确定性排序） */
  items: AttributionItem[]
}

export interface AttributionResult {
  samples: TrafficSample[]
  errors: SampleError[]
  /** 命中规则汇总桶（权重降序），其后拼接未命中桶 */
  buckets: AttributionBucket[]
  /** 参与统计的判定总数（TCP/UDP 样本各 1，ANY 样本 2） */
  decisionCount: number
  /** 参与统计的样本行数（不含错误行） */
  validCount: number
  /** 错误行数 */
  errorCount: number
  totalWeight: number
  hitWeight: number
  missWeight: number
  /** 参与归因的合法且启用规则数 */
  activeRuleCount: number
  /** 被排除的非法规则数 */
  invalidExcluded: number
  /** 被排除的停用规则数（合法但 enabled=false） */
  disabledExcluded: number
}

export type AttributionOutcome =
  | { ok: true; result: AttributionResult }
  | { ok: false; errors: string[] }

// ---------------------------------------------------------------------------
// 逐行校验
// ---------------------------------------------------------------------------

const CONCRETE: ConcreteProtocol[] = ['TCP', 'UDP']

/** uint32 -> 点分十进制 */
function intToIp(value: number): string {
  const v = value >>> 0
  return `${(v >>> 24) & 0xff}.${(v >>> 16) & 0xff}.${(v >>> 8) & 0xff}.${v & 0xff}`
}

/** 严格点分十进制 IPv4：必须四段、每段 0-255、无前导零（0 本身除外） */
export function parseIpv4Strict(text: string): number | null {
  const parts = text.split('.')
  if (parts.length !== 4) return null
  let value = 0
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null
    if (part.length > 1 && part.startsWith('0')) return null
    const octet = Number(part)
    if (octet < 0 || octet > 255) return null
    value = value * 256 + octet
  }
  return value >>> 0
}

interface RowOutcome {
  sample: TrafficSample | null
  messages: string[]
  /** 行内可识别的 ID（字符串 / 有限数字），用于重复检测；否则为 null */
  idKey: string | null
  /** 错误信息中展示的 ID 文本 */
  idLabel: string | null
}

function validateRow(item: unknown, line: number): RowOutcome {
  if (item === null || typeof item !== 'object' || Array.isArray(item)) {
    return { sample: null, messages: ['该行不是 JSON 对象'], idKey: null, idLabel: null }
  }
  const o = item as Record<string, unknown>
  const messages: string[] = []

  // ID：字符串或有限数字均可，空白字符串 / 布尔 / null / 对象拒绝
  let idKey: string | null = null
  let idLabel: string | null = null
  if (o.id === undefined || o.id === null) {
    messages.push('id 不能为空')
  } else if (typeof o.id === 'string') {
    const t = o.id.trim()
    if (!t) messages.push('id 不能为空字符串')
    else {
      idKey = t
      idLabel = t
    }
  } else if (typeof o.id === 'number' && Number.isFinite(o.id)) {
    idKey = String(o.id)
    idLabel = String(o.id)
  } else {
    messages.push(`id 必须为字符串或数字，收到 ${typeof o.id}`)
  }

  // 源 IP：严格四段点分十进制
  let srcIpInt: number | null = null
  let srcIp = ''
  if (typeof o.srcIp !== 'string') {
    messages.push(
      `srcIp 必须为字符串，收到 ${o.srcIp === undefined ? 'undefined' : typeof o.srcIp}`,
    )
  } else {
    const trimmed = o.srcIp.trim()
    srcIpInt = parseIpv4Strict(trimmed)
    if (srcIpInt === null) {
      messages.push(`srcIp 非法：“${o.srcIp}” 不是合法的点分十进制 IPv4`)
    } else {
      srcIp = intToIp(srcIpInt)
    }
  }

  // 源端口：0-65535 的整数（拒绝小数 / 布尔 / 字符串）
  let srcPort: number | null = null
  if (typeof o.srcPort !== 'number' || !Number.isInteger(o.srcPort)) {
    messages.push(
      `srcPort 必须为 0-65535 的整数，收到 ${
        typeof o.srcPort === 'number' ? String(o.srcPort) : typeof o.srcPort
      }`,
    )
  } else if (o.srcPort < 0 || o.srcPort > 65535) {
    messages.push(`srcPort 必须在 0-65535 之间，收到 ${o.srcPort}`)
  } else {
    srcPort = o.srcPort
  }

  // 协议：TCP / UDP / ANY
  let protocol: Protocol | null = null
  if (typeof o.protocol !== 'string') {
    messages.push(
      `protocol 必须为 TCP / UDP / ANY 字符串，收到 ${
        o.protocol === undefined ? 'undefined' : typeof o.protocol
      }`,
    )
  } else {
    const upper = o.protocol.trim().toUpperCase()
    if (upper !== 'TCP' && upper !== 'UDP' && upper !== 'ANY') {
      messages.push(`protocol 必须为 TCP / UDP / ANY，收到 “${o.protocol}”`)
    } else {
      protocol = upper
    }
  }

  // 权重：有限正数（允许小数）
  let weight: number | null = null
  if (typeof o.weight !== 'number' || !Number.isFinite(o.weight)) {
    messages.push(
      `weight 必须为正数，收到 ${
        o.weight === undefined
          ? 'undefined'
          : typeof o.weight === 'number'
            ? String(o.weight)
            : typeof o.weight
      }`,
    )
  } else if (!(o.weight > 0)) {
    messages.push(`weight 必须为正数，收到 ${o.weight}`)
  } else {
    weight = o.weight
  }

  if (
    messages.length > 0 ||
    idKey === null ||
    srcIpInt === null ||
    srcPort === null ||
    protocol === null ||
    weight === null
  ) {
    return { sample: null, messages, idKey, idLabel }
  }

  return {
    sample: { id: idKey, srcIp, srcIpInt, srcPort, protocol, weight, line },
    messages: [],
    idKey,
    idLabel,
  }
}

// ---------------------------------------------------------------------------
// 主归因流程
// ---------------------------------------------------------------------------

/** 点命中：按规则顺序返回首个覆盖 (ip, port, proto) 的合法启用规则 */
function firstHit(
  rules: NormalizedRule[],
  ipInt: number,
  port: number,
  proto: ConcreteProtocol,
): NormalizedRule | null {
  for (const rule of rules) {
    if (
      ipInt >= rule.ipStart &&
      ipInt <= rule.ipEnd &&
      port >= rule.portStart &&
      port <= rule.portEnd &&
      (rule.protocol === 'ANY' || rule.protocol === proto)
    ) {
      return rule
    }
  }
  return null
}

function compareItems(a: AttributionItem, b: AttributionItem): number {
  if (b.weight !== a.weight) return b.weight - a.weight
  if (a.srcIpInt !== b.srcIpInt) return a.srcIpInt - b.srcIpInt
  if (a.srcPort !== b.srcPort) return a.srcPort - b.srcPort
  if (a.protocol !== b.protocol) return a.protocol < b.protocol ? -1 : 1
  if (a.sampleId !== b.sampleId) return a.sampleId < b.sampleId ? -1 : 1
  return a.line - b.line
}

/**
 * 解析并归因。text 必须是 JSON 数组；根节点非法时返回顶层错误（无任何统计）。
 * 行级错误（重复 ID / 非法字段）逐行回报，错误行不计入统计，其余行正常归因。
 */
export function attributeTraffic(text: string, inputs: RuleInput[]): AttributionOutcome {
  let data: unknown
  try {
    data = JSON.parse(text)
  } catch (err) {
    return { ok: false, errors: [`JSON 解析失败：${(err as Error).message}`] }
  }
  if (!Array.isArray(data)) {
    return { ok: false, errors: ['根节点必须是 JSON 数组，形如 [{ "id": ..., "srcIp": ... }]'] }
  }

  const { valid: validRules, invalid } = validateRules(inputs)
  const active = validRules.filter((r) => r.enabled)
  const disabledCount = validRules.length - active.length

  const errors: SampleError[] = []
  const valid: TrafficSample[] = []
  const seenIds = new Map<string, number>()

  data.forEach((item, i) => {
    const line = i + 1
    const row = validateRow(item, line)
    const rowMessages = [...row.messages]

    if (row.idKey !== null) {
      const firstLine = seenIds.get(row.idKey)
      if (firstLine === undefined) {
        // 仅当本行其余字段也合法时才占用该 ID：
        // 非法行不进入统计，后续合法行复用同一 ID 不应被误判为重复。
        if (rowMessages.length === 0 && row.sample) {
          seenIds.set(row.idKey, line)
        }
      } else {
        rowMessages.push(`id 重复：“${row.idLabel ?? row.idKey}” 已在第 ${firstLine} 行出现`)
      }
    }

    if (rowMessages.length > 0) {
      errors.push({ line, id: row.idLabel, messages: rowMessages })
      return
    }
    valid.push(row.sample!)
  })

  // 桶键：`hit:<ruleIndex>` 或 `miss`
  const buckets = new Map<string, AttributionBucket>()
  const ensureBucket = (
    key: string,
    seed: Pick<AttributionBucket, 'kind' | 'ruleIndex' | 'ruleName' | 'action'>,
  ) => {
    let b = buckets.get(key)
    if (!b) {
      b = { ...seed, weight: 0, ratio: 0, count: 0, items: [] }
      buckets.set(key, b)
    }
    return b
  }

  let totalWeight = 0
  let hitWeight = 0
  let missWeight = 0
  let decisionCount = 0

  for (const sample of valid) {
    const protos: ConcreteProtocol[] = sample.protocol === 'ANY' ? CONCRETE : [sample.protocol]
    for (const proto of protos) {
      const item: AttributionItem = {
        sampleId: sample.id,
        srcIp: sample.srcIp,
        srcIpInt: sample.srcIpInt,
        srcPort: sample.srcPort,
        protocol: proto,
        declaredProtocol: sample.protocol,
        weight: sample.weight,
        line: sample.line,
      }
      decisionCount++
      totalWeight += sample.weight

      const hit = firstHit(active, sample.srcIpInt, sample.srcPort, proto)
      if (hit) {
        const b = ensureBucket(`hit:${hit.index}`, {
          kind: 'hit',
          ruleIndex: hit.index,
          ruleName: hit.name,
          action: hit.action,
        })
        b.weight += sample.weight
        b.items.push(item)
        hitWeight += sample.weight
      } else {
        const b = ensureBucket('miss', {
          kind: 'miss',
          ruleIndex: -1,
          ruleName: '',
          action: null,
        })
        b.weight += sample.weight
        b.items.push(item)
        missWeight += sample.weight
      }
    }
  }

  const list = [...buckets.values()]
  for (const b of list) {
    b.ratio = totalWeight === 0 ? 0 : b.weight / totalWeight
    b.items.sort(compareItems)
    b.count = b.items.length
  }
  // 命中桶在前（权重降序、再按规则位置升序），未命中桶固定在最后
  list.sort((a, b) => {
    if (a.kind !== b.kind) return a.kind === 'hit' ? -1 : 1
    if (b.weight !== a.weight) return b.weight - a.weight
    if (a.kind === 'hit') return a.ruleIndex - b.ruleIndex
    return 0
  })

  return {
    ok: true,
    result: {
      samples: valid,
      errors,
      buckets: list,
      decisionCount,
      validCount: valid.length,
      errorCount: errors.length,
      totalWeight,
      hitWeight,
      missWeight,
      activeRuleCount: active.length,
      invalidExcluded: invalid.length,
      disabledExcluded: disabledCount,
    },
  }
}
