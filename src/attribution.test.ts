/**
 * 流量样本归因自检：零依赖断言脚本，与 audit.test.ts 同风格。
 */
import assert from 'node:assert'
import { attributeTraffic, parseIpv4Strict } from './audit/attribution'
import type { RuleInput } from './audit/types'

let passed = 0
function test(name: string, fn: () => void) {
  fn()
  passed++
  console.log(`  ✓ ${name}`)
}

let seq = 0
function rule(partial: Partial<RuleInput>): RuleInput {
  return {
    id: `r${seq++}`,
    name: partial.name ?? `R${seq}`,
    cidr: partial.cidr ?? '0.0.0.0/0',
    portStart: partial.portStart ?? '0',
    portEnd: partial.portEnd ?? '65535',
    protocol: partial.protocol ?? 'ANY',
    action: partial.action ?? 'allow',
    enabled: partial.enabled ?? true,
  }
}

const RULES: RuleInput[] = [
  rule({ name: '内网 Web', cidr: '10.0.0.0/8', portStart: '80', portEnd: '443', protocol: 'TCP', action: 'allow' }),
  rule({ name: '内网 UDP', cidr: '10.0.0.0/8', portStart: '0', portEnd: '65535', protocol: 'UDP', action: 'allow' }),
  rule({ name: '其余拒绝', cidr: '0.0.0.0/0', portStart: '0', portEnd: '65535', protocol: 'ANY', action: 'deny' }),
]

function run(text: string, rules: RuleInput[] = RULES) {
  const out = attributeTraffic(text, rules)
  if (!out.ok) throw new Error(`意外的顶层错误：${out.errors.join('; ')}`)
  return out.result
}

// --- IP 严格解析 ---
test('parseIpv4Strict：常规地址、边界与前导零', () => {
  assert.equal(parseIpv4Strict('10.0.0.5'), 0x0a000005)
  assert.equal(parseIpv4Strict('0.0.0.0'), 0)
  assert.equal(parseIpv4Strict('255.255.255.255'), 0xffffffff)
  assert.equal(parseIpv4Strict('01.0.0.0'), null)
  assert.equal(parseIpv4Strict('256.0.0.0'), null)
  assert.equal(parseIpv4Strict('10.0.0'), null)
  assert.equal(parseIpv4Strict('10.0.0.1.2'), null)
  assert.equal(parseIpv4Strict('a.b.c.d'), null)
})

// --- 基础归因 ---
test('TCP 样本命中首个匹配规则', () => {
  const r = run(
    JSON.stringify([
      { id: 's1', srcIp: '10.0.0.5', srcPort: 80, protocol: 'TCP', weight: 10 },
    ]),
  )
  assert.equal(r.validCount, 1)
  assert.equal(r.decisionCount, 1)
  assert.equal(r.totalWeight, 10)
  assert.equal(r.hitWeight, 10)
  assert.equal(r.missWeight, 0)
  assert.equal(r.buckets.length, 1)
  assert.equal(r.buckets[0].kind, 'hit')
  assert.equal(r.buckets[0].ruleName, '内网 Web')
  assert.equal(r.buckets[0].action, 'allow')
  assert.equal(r.buckets[0].weight, 10)
  assert.equal(r.buckets[0].ratio, 1)
})

test('ANY 样本按同一权重分别判定 TCP 与 UDP，可落入不同规则', () => {
  // TCP 80 命中「内网 Web」；UDP 80 命中「内网 UDP」——两个不同规则
  const r = run(
    JSON.stringify([
      { id: 'a1', srcIp: '10.1.2.3', srcPort: 80, protocol: 'ANY', weight: 4 },
    ]),
  )
  assert.equal(r.validCount, 1)
  assert.equal(r.decisionCount, 2)
  assert.equal(r.totalWeight, 8)
  const hits = r.buckets.filter((b) => b.kind === 'hit')
  assert.equal(hits.length, 2)
  for (const b of hits) {
    assert.equal(b.weight, 4)
    assert.equal(b.count, 1)
    assert.equal(b.items[0].sampleId, 'a1')
    assert.equal(b.items[0].declaredProtocol, 'ANY')
  }
  const names = hits.map((b) => b.ruleName).sort()
  assert.deepEqual(names, ['内网 UDP', '内网 Web'])
})

test('未命中桶汇总无覆盖判定，且固定排在最后', () => {
  const rules = [rule({ name: '只覆盖 10/8', cidr: '10.0.0.0/8', action: 'permit' })]
  const r = run(
    JSON.stringify([
      { id: 'x', srcIp: '8.8.8.8', srcPort: 53, protocol: 'UDP', weight: 7 },
      { id: 'y', srcIp: '10.0.0.1', srcPort: 53, protocol: 'UDP', weight: 3 },
    ]),
    rules,
  )
  assert.equal(r.totalWeight, 10)
  assert.equal(r.hitWeight, 3)
  assert.equal(r.missWeight, 7)
  assert.equal(r.buckets.length, 2)
  assert.equal(r.buckets[0].kind, 'hit')
  assert.equal(r.buckets[0].weight, 3)
  assert.equal(r.buckets[1].kind, 'miss')
  assert.equal(r.buckets[1].weight, 7)
  assert.equal(r.buckets[1].ratio, 0.7)
})

test('命中桶按权重降序排列', () => {
  // s1/s2 走内网规则（allow），s3 走兜底（deny）
  const r = run(
    JSON.stringify([
      { id: 's1', srcIp: '10.0.0.1', srcPort: 80, protocol: 'TCP', weight: 1 },
      { id: 's2', srcIp: '10.0.0.2', srcPort: 80, protocol: 'TCP', weight: 1 },
      { id: 's3', srcIp: '8.8.8.8', srcPort: 1, protocol: 'TCP', weight: 5 },
    ]),
  )
  assert.equal(r.buckets[0].action, 'deny')
  assert.equal(r.buckets[0].weight, 5)
  assert.equal(r.buckets[1].action, 'allow')
  assert.equal(r.buckets[1].weight, 2)
})

// --- 明细排序 ---
test('展开明细按权重降序，并以 IP/端口/协议/ID 确定性打平', () => {
  const r = run(
    JSON.stringify([
      { id: 'lo', srcIp: '10.0.0.9', srcPort: 100, protocol: 'TCP', weight: 1 },
      { id: 'hi', srcIp: '10.0.0.1', srcPort: 100, protocol: 'TCP', weight: 9 },
      { id: 'mid', srcIp: '10.0.0.2', srcPort: 100, protocol: 'TCP', weight: 4 },
    ]),
  )
  const web = r.buckets.find((b) => b.ruleName === '内网 Web')!
  assert.deepEqual(
    web.items.map((i) => i.sampleId),
    ['hi', 'mid', 'lo'],
  )
})

// --- 逐行错误 ---
test('非法字段逐行报错，错误行不计入统计', () => {
  const r = run(
    JSON.stringify([
      { id: 'ok1', srcIp: '10.0.0.1', srcPort: 80, protocol: 'TCP', weight: 2 },
      { id: 'bad-ip', srcIp: '999.1.1.1', srcPort: 80, protocol: 'TCP', weight: 2 },
      { id: 'bad-port', srcIp: '10.0.0.1', srcPort: 70000, protocol: 'TCP', weight: 2 },
      { id: 'bad-proto', srcIp: '10.0.0.1', srcPort: 80, protocol: 'ICMP', weight: 2 },
      { id: 'zero-w', srcIp: '10.0.0.1', srcPort: 80, protocol: 'TCP', weight: 0 },
      { id: 'neg-w', srcIp: '10.0.0.1', srcPort: 80, protocol: 'TCP', weight: -3 },
      { id: 'float-port', srcIp: '10.0.0.1', srcPort: 80.5, protocol: 'TCP', weight: 2 },
      { id: 'bool-w', srcIp: '10.0.0.1', srcPort: 80, protocol: 'TCP', weight: true },
    ]),
  )
  assert.equal(r.validCount, 1)
  assert.equal(r.errorCount, 7)
  assert.equal(r.totalWeight, 2)
  const lines = r.errors.map((e) => e.line)
  assert.deepEqual(lines, [2, 3, 4, 5, 6, 7, 8])
  assert.ok(r.errors.find((e) => e.id === 'bad-ip')!.messages.some((m) => m.includes('srcIp')))
  assert.ok(r.errors.find((e) => e.id === 'zero-w')!.messages.some((m) => m.includes('正数')))
  assert.ok(r.errors.find((e) => e.id === 'bool-w')!.messages.some((m) => m.includes('正数')))
})

test('一行多个字段错误全部回报', () => {
  const r = run(
    JSON.stringify([{ id: '', srcIp: 'x', srcPort: -1, protocol: 'SCTP', weight: 0 }]),
  )
  assert.equal(r.validCount, 0)
  const msgs = r.errors[0].messages
  assert.ok(msgs.some((m) => m.includes('id')))
  assert.ok(msgs.some((m) => m.includes('srcIp')))
  assert.ok(msgs.some((m) => m.includes('srcPort')))
  assert.ok(msgs.some((m) => m.includes('protocol')))
  assert.ok(msgs.some((m) => m.includes('weight')))
})

test('重复 ID：首次合法出现保留，其余重复行报错', () => {
  const r = run(
    JSON.stringify([
      { id: 'dup', srcIp: '10.0.0.1', srcPort: 80, protocol: 'TCP', weight: 1 },
      { id: 'dup', srcIp: '10.0.0.2', srcPort: 80, protocol: 'TCP', weight: 1 },
      { id: 'dup', srcIp: '10.0.0.3', srcPort: 80, protocol: 'TCP', weight: 1 },
    ]),
  )
  assert.equal(r.validCount, 1)
  assert.equal(r.errorCount, 2)
  assert.equal(r.samples[0].srcIp, '10.0.0.1')
  for (const e of r.errors) {
    assert.ok(e.messages.some((m) => m.includes('id 重复') && m.includes('第 1 行')))
  }
})

test('非法行不占用 ID：后续合法行同名 ID 不算重复', () => {
  const r = run(
    JSON.stringify([
      { id: 'k', srcIp: 'bad', srcPort: 80, protocol: 'TCP', weight: 1 },
      { id: 'k', srcIp: '10.0.0.1', srcPort: 80, protocol: 'TCP', weight: 5 },
    ]),
  )
  assert.equal(r.validCount, 1)
  assert.equal(r.samples[0].id, 'k')
  assert.equal(r.totalWeight, 5)
  assert.equal(r.errors[0].line, 1)
  assert.ok(!r.errors[0].messages.some((m) => m.includes('重复')))
})

test('非对象元素与空数组按行 / 整体处理', () => {
  const r = run(JSON.stringify([42, 'str', null, ['nested']]))
  assert.equal(r.validCount, 0)
  assert.equal(r.errorCount, 4)
  assert.ok(r.errors.every((e) => e.messages[0].includes('不是 JSON 对象')))

  const empty = run('[]')
  assert.equal(empty.validCount, 0)
  assert.equal(empty.totalWeight, 0)
  assert.equal(empty.buckets.length, 0)
})

test('数字 ID 合法且参与重复检测', () => {
  const r = run(
    JSON.stringify([
      { id: 7, srcIp: '10.0.0.1', srcPort: 80, protocol: 'TCP', weight: 1 },
      { id: 7, srcIp: '10.0.0.2', srcPort: 80, protocol: 'TCP', weight: 1 },
    ]),
  )
  assert.equal(r.validCount, 1)
  assert.equal(r.samples[0].id, '7')
  assert.equal(r.errorCount, 1)
})

// --- 规则侧排除 ---
test('非法规则与停用规则不参与归因（首命中落到后续规则）', () => {
  const rules: RuleInput[] = [
    { ...rule({ name: '停用的精确规则', cidr: '10.0.0.0/8' }), enabled: false },
    RULES[0],
    RULES[1],
    RULES[2],
  ]
  const r = run(
    JSON.stringify([
      { id: 's1', srcIp: '10.0.0.1', srcPort: 22, protocol: 'TCP', weight: 1 },
    ]),
    rules,
  )
  assert.equal(r.activeRuleCount, 3)
  assert.equal(r.disabledExcluded, 1)
  // 22 不在 80-443，故 TCP 命中兜底 deny
  assert.equal(r.buckets[0].action, 'deny')
})

// --- 顶层错误 ---
test('JSON 语法错误与非数组根节点返回顶层错误', () => {
  const bad = attributeTraffic('{not json', RULES)
  assert.equal(bad.ok, false)
  if (bad.ok) throw new Error('unreachable')
  assert.ok(bad.errors[0].includes('JSON 解析失败'))

  const obj = attributeTraffic('{"samples":[]}', RULES)
  assert.equal(obj.ok, false)
  if (obj.ok) throw new Error('unreachable')
  assert.ok(obj.errors[0].includes('JSON 数组'))
})

// --- 权重守恒 ---
test('权重守恒：桶权重之和等于全部判定权重（ANY 双份）', () => {
  const r = run(
    JSON.stringify([
      { id: 'a', srcIp: '10.0.0.1', srcPort: 80, protocol: 'ANY', weight: 2.5 },
      { id: 'b', srcIp: '8.8.8.8', srcPort: 53, protocol: 'UDP', weight: 4 },
      { id: 'c', srcIp: '10.0.0.2', srcPort: 443, protocol: 'TCP', weight: 0.25 },
    ]),
  )
  const sum = r.buckets.reduce((s, b) => s + b.weight, 0)
  assert.ok(Math.abs(sum - r.totalWeight) < 1e-9)
  assert.equal(r.decisionCount, 4)
  assert.equal(r.totalWeight, 9.25)
  const ratioSum = r.buckets.reduce((s, b) => s + b.ratio, 0)
  assert.ok(Math.abs(ratioSum - 1) < 1e-9)
})

console.log(`\n全部 ${passed} 项测试通过 ✔`)
