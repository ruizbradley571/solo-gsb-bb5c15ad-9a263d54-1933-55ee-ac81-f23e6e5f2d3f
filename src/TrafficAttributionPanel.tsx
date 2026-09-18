import { useMemo, useState } from 'react'
import {
  attributeTraffic,
  type AttributionBucket,
  type AttributionItem,
  type AttributionResult,
  type SampleError,
} from './audit/attribution'
import type { RuleInput } from './audit/types'
import { formatPercent } from './format'

interface Props {
  rules: RuleInput[]
}

const PLACEHOLDER = `[
  { "id": "s1", "srcIp": "10.0.0.5", "srcPort": 8080, "protocol": "TCP", "weight": 10 },
  { "id": "s2", "srcIp": "192.168.1.1", "srcPort": 53, "protocol": "ANY", "weight": 3.5 }
]`

/** 权重允许小数：去除浮点误差后紧凑展示（最多 6 位小数） */
function formatWeight(n: number): string {
  if (Number.isInteger(n)) return n.toLocaleString('en-US')
  const rounded = Math.round(n * 1e6) / 1e6
  return String(rounded)
}

function BucketEntry({
  bucket,
  totalWeight,
}: {
  bucket: AttributionBucket
  totalWeight: number
}) {
  const [open, setOpen] = useState(false)
  const isMiss = bucket.kind === 'miss'
  const cls = isMiss ? 'entry-fully-shadowed' : 'entry-reachable'

  return (
    <div className={`entry attribution-bucket ${cls} ${open ? 'open' : ''}`}>
      <div className="entry-header" onClick={() => setOpen((v) => !v)}>
        <span className="chevron">▶</span>
        {isMiss ? (
          <span className="badge fully-shadowed">未命中任何规则</span>
        ) : (
          <>
            <span className="idx-cell">#{bucket.ruleIndex + 1}</span>
            <span className="title">{bucket.ruleName}</span>
            <span className="action-pill">{bucket.action}</span>
          </>
        )}
        <span className="spacer" />
        <span className="meta">
          权重 {formatWeight(bucket.weight)}（{formatPercent(bucket.ratio)}） ·{' '}
          {bucket.count} 条判定
        </span>
      </div>
      {open && (
        <div className="entry-body">
          <div style={{ overflowX: 'auto' }}>
            <table className="rule-table attribution-table">
              <thead>
                <tr>
                  <th>样本 ID</th>
                  <th>源 IP</th>
                  <th>源端口</th>
                  <th>判定协议</th>
                  <th>声明协议</th>
                  <th className="attribution-num">权重</th>
                  <th>行号</th>
                  <th>归因结果</th>
                </tr>
              </thead>
              <tbody>
                {bucket.items.map((item, i) => (
                  <ItemRow
                    key={`${item.line}:${item.protocol}:${i}`}
                    item={item}
                    isMiss={isMiss}
                    bucket={bucket}
                  />
                ))}
              </tbody>
            </table>
          </div>
          <div className="muted-text attribution-row-note">
            {isMiss
              ? '以上判定均不被任何合法且启用的规则覆盖。'
              : `按首条命中语义，以上判定的首个覆盖规则均为 #${
                  bucket.ruleIndex + 1
                } ${bucket.ruleName}（动作 ${bucket.action}）。`}
            合计权重 {formatWeight(bucket.weight)} / 全部判定权重{' '}
            {formatWeight(totalWeight)}。
          </div>
        </div>
      )}
    </div>
  )
}

function ItemRow({
  item,
  isMiss,
  bucket,
}: {
  item: AttributionItem
  isMiss: boolean
  bucket: AttributionBucket
}) {
  return (
    <tr>
      <td className="mono">{item.sampleId}</td>
      <td className="mono">{item.srcIp}</td>
      <td className="attribution-num">{item.srcPort}</td>
      <td>{item.protocol}</td>
      <td>
        {item.declaredProtocol === 'ANY' ? (
          <span className="attribution-any-tag" title="ANY 样本按同一权重分别判定 TCP 与 UDP">
            ANY
          </span>
        ) : (
          item.declaredProtocol
        )}
      </td>
      <td className="attribution-num">{formatWeight(item.weight)}</td>
      <td className="muted-text attribution-num">第 {item.line} 行</td>
      <td>
        {isMiss ? (
          <span className="muted-text">无规则覆盖</span>
        ) : (
          <span>
            #{bucket.ruleIndex + 1} {bucket.ruleName} ·{' '}
            <span className="action-pill">{bucket.action}</span>
          </span>
        )}
      </td>
    </tr>
  )
}

function ErrorList({ errors }: { errors: SampleError[] }) {
  return (
    <div className="notice error">
      <div>
        <strong>{errors.length}</strong> 行样本存在错误（重复 ID 或非法字段），已整行拒绝、不计入统计：
      </div>
      <ul className="error-list attribution-error-list">
        {errors.map((e) => (
          <li key={e.line}>
            第 {e.line} 行{e.id !== null ? <span className="mono">（id: {e.id}）</span> : null}：
            {e.messages.join('；')}
          </li>
        ))}
      </ul>
    </div>
  )
}

function ResultView({ result }: { result: AttributionResult }) {
  const allMiss = result.hitWeight === 0
  return (
    <div className="attribution-result">
      <div className="legend simplify-summary">
        参与统计 {result.validCount} 行样本、{result.decisionCount} 次判定（ANY 样本按 TCP/UDP
        各判定一次）；基于 {result.activeRuleCount} 条合法且启用的规则
        {result.invalidExcluded > 0 ? `（${result.invalidExcluded} 条非法规则已排除）` : ''}
        {result.disabledExcluded > 0 ? `（${result.disabledExcluded} 条停用规则已排除）` : ''}
        。合计权重 <strong>{formatWeight(result.totalWeight)}</strong>。
      </div>

      <div className="stats">
        <div className="stat-card ok">
          <div className="label">命中规则</div>
          <div className="value" style={{ fontSize: 18 }}>
            {formatWeight(result.hitWeight)}
          </div>
          <div className="label">{formatPercent(result.hitWeight / (result.totalWeight || 1))}</div>
        </div>
        <div className={`stat-card ${result.missWeight > 0 ? 'danger' : ''}`}>
          <div className="label">未命中任何规则</div>
          <div className="value" style={{ fontSize: 18 }}>
            {formatWeight(result.missWeight)}
          </div>
          <div className="label">{formatPercent(result.missWeight / (result.totalWeight || 1))}</div>
        </div>
        <div className="stat-card">
          <div className="label">有效样本行 / 判定次数</div>
          <div className="value" style={{ fontSize: 18 }}>
            {result.validCount} / {result.decisionCount}
          </div>
          <div className="label">
            汇总 {result.buckets.filter((b) => b.kind === 'hit').length} 条规则
            {result.missWeight > 0 ? ' + 未命中' : ''}
          </div>
        </div>
        <div className={`stat-card ${result.errorCount > 0 ? 'danger' : ''}`}>
          <div className="label">错误行（不计入统计）</div>
          <div className="value" style={{ fontSize: 18 }}>
            {result.errorCount}
          </div>
          <div className="label">合法权重合计 {formatWeight(result.totalWeight)}</div>
        </div>
      </div>

      {result.validCount === 0 ? (
        <div className="notice info" style={{ marginBottom: 0 }}>
          没有可参与统计的样本行：请修正下方错误后重新分析。
        </div>
      ) : allMiss ? (
        <div className="notice info">所有判定均未命中任何规则。</div>
      ) : null}

      <h3 className="reorder-section-title">
        归因汇总（{result.buckets.length} 组，按权重降序；点击展开样本明细）
      </h3>
      {result.buckets.map((b) => (
        <BucketEntry key={b.kind === 'hit' ? `hit:${b.ruleIndex}` : 'miss'} bucket={b} totalWeight={result.totalWeight} />
      ))}
    </div>
  )
}

export function TrafficAttributionPanel({ rules }: Props) {
  const [text, setText] = useState('')
  const [submitted, setSubmitted] = useState<string | null>(null)

  // 只读分析：提交后随规则编辑 / 调序 / 启停自动按当前规则重算；
  // 文本改动后给出“待重新分析”提示，与面板其余部分的只读刷新约定一致。
  const outcome = useMemo(
    () => (submitted === null ? null : attributeTraffic(submitted, rules)),
    [submitted, rules],
  )
  const stale = submitted !== null && text !== submitted

  const result = outcome?.ok ? outcome.result : null

  return (
    <div className="panel attribution-panel">
      <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap' }}>
        <h2 style={{ margin: 0 }}>流量样本归因（只读）</h2>
        <span className="legend" style={{ marginLeft: 12 }}>
          粘贴 JSON 数组，按当前规则的首条命中语义归因；每行样本需含唯一
          <span className="mono"> id</span>、<span className="mono">srcIp</span>、
          <span className="mono">srcPort</span>、<span className="mono">protocol</span>（TCP/UDP/ANY）
          与正数 <span className="mono">weight</span>，ANY 样本按同一权重分别判定 TCP 与 UDP
        </span>
      </div>

      <textarea
        className="attribution-input"
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder={PLACEHOLDER}
        spellCheck={false}
      />

      <div className="attribution-actions">
        <button className="primary" onClick={() => setSubmitted(text)}>
          {submitted === null ? '执行归因分析' : '重新分析'}
        </button>
        <button
          onClick={() => {
            setText('')
            setSubmitted(null)
          }}
        >
          清空
        </button>
        {stale && (
          <span className="muted-text">
            样本内容已修改，当前结果对应上次提交；点击「重新分析」以最新样本归因。
          </span>
        )}
      </div>

      {outcome && !outcome.ok && (
        <div className="notice error" style={{ marginBottom: 0 }}>
          {outcome.errors.map((e, i) => (
            <div key={i}>• {e}</div>
          ))}
        </div>
      )}

      {submitted === null && (
        <div className="notice info" style={{ marginBottom: 0 }}>
          粘贴样本数组后点击「执行归因分析」。结果按命中规则、动作及未命中状态汇总权重和占比，
          可展开查看按权重降序排列的样本明细；重复 ID 或非法字段会逐行报错，错误行不计入统计。
        </div>
      )}

      {result && <ErrorList errors={result.errors} />}
      {result && <ResultView result={result} />}
    </div>
  )
}
