<script setup>
import { computed, nextTick, onBeforeUnmount, onMounted, ref } from 'vue'

const reviews = ref([])
const analytics = ref(null)
const analyticsError = ref('')
const queueReviewerOptions = ref([])
const queueProviderOptions = ref([])
const selected = ref(null)
const config = ref(null)
const configText = ref('')
const loading = ref(false)
const initializing = ref(true)
const detailLoaded = ref(false)
const detailError = ref(false)
let detailRequestId = 0
let historyRequestId = 0
let analyticsRequestId = 0
let repositoryStorageKey = null
const saving = ref(false)
const savingFinding = ref('')
const findingMessage = ref('')
const dispositionDrafts = ref({})
// The finding whose disposition form is open; the form is shown on demand.
const editingDisposition = ref('')
const drawerRecord = ref(null)
const drawerView = ref(null)
const drawerError = ref('')
const drawerMessage = ref('')
const error = ref('')
const scope = ref('base')
const base = ref('main')
const analyticsWindow = ref(14)
const analyticsRange = ref('recent')
const analyticsDateFrom = ref('')
const analyticsDateTo = ref('')
const queueStatus = ref('all')
const queueReviewer = ref('')
const queueProvider = ref('')
const queueQuery = ref('')
const queueSavedViews = ref([])
const queueSavedViewId = ref('')
const queueViewName = ref('')
const queueViewMessage = ref('')
const analyticsReviewer = ref('')
const analyticsProvider = ref('')
const analyticsCategory = ref('')
const analyticsRule = ref('')
const verificationProfile = ref('')
const savedAnalyticsViews = ref([])
const selectedAnalyticsViewId = ref('')
const analyticsViewName = ref('')
const analyticsViewMessage = ref('')
const selectedAnalyticsDay = ref('')
const selectedAnalyticsSeverity = ref('')
const selectedVerificationDay = ref('')
const activeTab = ref('overview')
const analyticsLoading = ref(false)
const statusTone = value => ({ pass: 'good', block: 'bad', incomplete: 'warn' }[String(value).toLowerCase()] || 'muted')
const findings = computed(() => selected.value?.findings || [])
const supersession = computed(() => selected.value?.superseded_by || null)
const isOutdated = record => Boolean(supersession.value?.outdated_finding_ids?.includes(record.finding.id))
const impactPaths = computed(() => selected.value?.impact?.paths || [])
const impactedFiles = computed(() => new Set(impactPaths.value.map(path => path.affected_path)).size)
// Change risk is an ordinal tier over measured factors (see the research
// basis on each factor); it informs where to look and never changes the gate.
const risk = computed(() => selected.value?.risk || null)
const riskFlags = computed(() => (risk.value?.factors || []).filter(factor => factor.flagged))
const riskSummary = computed(() => riskFlags.value.length
  ? riskFlags.value.map(factor => `${factor.label.toLowerCase()}: ${factor.value}`).join(' · ')
  : 'no factor at its threshold')
const riskTitle = computed(() => (risk.value?.factors || [])
  .map(factor => `${factor.label}: ${factor.value} (flag at ${factor.threshold}) — ${factor.detail || 'none'}. Basis: ${factor.basis}`)
  .join('\n'))
const riskTone = tier => tier === 'high' ? 'bad' : tier === 'elevated' ? 'warn' : 'good'
const analyticsDimensions = computed(() => analytics.value?.review_dimensions || [])
// The latest gate evaluation outranks the status stored when the review ran:
// a review that awaited verification passes once that verification completes.
const currentGateStatus = computed(() => new Map(analyticsDimensions.value.map(item => [item.review_id, item.status])))
const reviewStatus = review => currentGateStatus.value.get(review.review_id) || review.status
const scopeLabels = { base: 'branch changes', staged: 'staged changes', working_tree: 'working tree' }
// A change-set scope in words; a single commit is `commit:<oid>`.
const scopeName = scope => {
  const value = String(scope || '')
  if (value.startsWith('commit:')) return `commit ${value.slice(7, 14)}`
  return scopeLabels[value] || value.replace(/_/g, ' ') || 'review'
}
// A content hash without its algorithm prefix, short enough to recognize.
const shortHash = value => String(value || '').replace(/^sha256:/, '').slice(0, 12)
const timeFormat = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
const formatTime = value => {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? String(value || '') : timeFormat.format(date)
}
// Axis labels for a bar chart scaled to `maximum`; the midpoint is shown only when it is a whole count.
const scaleLabels = maximum => [maximum, maximum % 2 === 0 ? maximum / 2 : '', 0]
// SARIF analyzers exit non-zero whenever they report anything; a run with no
// findings on the changed lines is what the gate treats as passing.
const verificationOutcome = run => run.status === 'failed' && run.analyzer_findings_on_changed_lines === 0 ? 'passed' : run.status
const verificationLabel = run => run.status === 'failed' && Number.isInteger(run.analyzer_findings_on_changed_lines)
  ? (run.analyzer_findings_on_changed_lines === 0 ? 'clean on changed lines' : `${run.analyzer_findings_on_changed_lines} analyzer findings on changed lines`)
  : String(run.status).replace('_', ' ')
const queueItems = computed(() => {
  const dimensions = new Map(analyticsDimensions.value.map(item => [item.review_id, item]))
  const query = queueQuery.value.trim().toLowerCase()
  return reviews.value.slice(0, 500).map(review => {
    const dimension = dimensions.get(review.review_id)
    return {
      ...review,
      gate_status: analyticsError.value ? 'unknown' : dimension?.status || 'unknown',
      gate_status_stale: Boolean(analyticsError.value && dimension?.status),
      reviewer_ids: dimension?.reviewer_ids || [],
      provider_ids: dimension?.provider_ids || [],
      next_action: analyticsError.value ? null : dimension?.next_action || null,
    }
  }).filter(item =>
    (queueStatus.value === 'all' || item.gate_status === queueStatus.value) &&
    (!queueReviewer.value || item.reviewer_ids.includes(queueReviewer.value)) &&
    (!queueProvider.value || item.provider_ids.includes(queueProvider.value)) &&
    (!query || [item.review_id, item.snapshot_id, item.created_at, item.gate_status, ...item.reviewer_ids, ...item.provider_ids].join(' ').toLowerCase().includes(query)),
  )
})
const queueReviewers = computed(() => queueReviewerOptions.value)
const queueProviders = computed(() => queueProviderOptions.value)
const analyticsOptions = key => [...new Set(analyticsDimensions.value.flatMap(item => item[key] || []))].sort()
function repositoryStorageKeyFor(namespace) {
  return repositoryStorageKey ? `vee.${namespace}.v1:${repositoryStorageKey}` : null
}
function readQueueViews() {
  try {
    const key = repositoryStorageKeyFor('review-queue.views')
    if (!key) return []
    const stored = JSON.parse(window.localStorage.getItem(key) || '{"schema_version":1,"views":[]}')
    if (stored?.schema_version !== 1 || !Array.isArray(stored.views)) return []
    return stored.views.slice(0, 25).filter(view => view && typeof view.id === 'string' && typeof view.name === 'string' && view.name.trim() && ['all', 'pass', 'block', 'incomplete', 'ungated', 'unknown'].includes(view.status) && typeof view.reviewer === 'string' && typeof view.provider === 'string' && typeof view.query === 'string')
  } catch {
    queueViewMessage.value = 'Saved queue views are unavailable in this browser profile.'
    return []
  }
}
function persistQueueViews() {
  try {
    const key = repositoryStorageKeyFor('review-queue.views')
    if (!key) return false
    window.localStorage.setItem(key, JSON.stringify({ schema_version: 1, views: queueSavedViews.value }))
    queueViewMessage.value = ''
    return true
  } catch {
    queueViewMessage.value = 'Could not save this view in browser storage.'
    return false
  }
}
function saveQueueView() {
  const name = queueViewName.value.trim()
  if (!name || name.length > 60) { queueViewMessage.value = 'Enter a view name from 1 to 60 characters.'; return }
  if (queueSavedViews.value.length >= 25) { queueViewMessage.value = 'Remove a saved view before adding another (limit: 25).'; return }
  const view = { id: globalThis.crypto?.randomUUID?.() || `queue-${Date.now()}`, name, status: queueStatus.value, reviewer: queueReviewer.value, provider: queueProvider.value, query: queueQuery.value }
  queueSavedViews.value = [...queueSavedViews.value, view]
  queueSavedViewId.value = view.id
  queueViewName.value = ''
  if (persistQueueViews()) queueViewMessage.value = `Saved “${name}”.`
}
function applyQueueView() {
  const view = queueSavedViews.value.find(item => item.id === queueSavedViewId.value)
  if (!view) return
  queueStatus.value = view.status
  queueReviewer.value = view.reviewer
  queueProvider.value = view.provider
  queueQuery.value = view.query
  queueViewMessage.value = `Loaded “${view.name}”.`
}
function deleteQueueView() {
  const previousViews = queueSavedViews.value
  const previousSelection = queueSavedViewId.value
  queueSavedViews.value = queueSavedViews.value.filter(item => item.id !== queueSavedViewId.value)
  queueSavedViewId.value = ''
  if (persistQueueViews()) {
    queueViewMessage.value = 'Deleted the saved queue view.'
  } else {
    queueSavedViews.value = previousViews
    queueSavedViewId.value = previousSelection
  }
}
function clearQueueFilters() {
  queueStatus.value = 'all'
  queueReviewer.value = ''
  queueProvider.value = ''
  queueQuery.value = ''
}
const filteredAnalyticsReviews = computed(() => analyticsDimensions.value.filter(item =>
  (!analyticsReviewer.value || item.reviewer_ids.includes(analyticsReviewer.value)) &&
  (!analyticsProvider.value || item.provider_ids.includes(analyticsProvider.value)) &&
  (!analyticsCategory.value || item.finding_categories.includes(analyticsCategory.value)) &&
  (!analyticsRule.value || item.finding_rule_ids.includes(analyticsRule.value)),
))
const analyticsRangeReviews = computed(() => filteredAnalyticsReviews.value.filter(item => {
  if (analyticsRange.value !== 'custom') return true
  if (analyticsDateFrom.value && item.day < analyticsDateFrom.value) return false
  if (analyticsDateTo.value && item.day > analyticsDateTo.value) return false
  return true
}))
const invalidAnalyticsDateRange = computed(() => analyticsRange.value === 'custom' && analyticsDateFrom.value && analyticsDateTo.value && analyticsDateFrom.value > analyticsDateTo.value)
const analyticsDays = computed(() => {
  const grouped = new Map()
  if (invalidAnalyticsDateRange.value) return []
  for (const review of analyticsRangeReviews.value) {
    const day = grouped.get(review.day) || { day: review.day, pass: 0, block: 0, incomplete: 0, ungated: 0 }
    day[review.status] = (day[review.status] || 0) + 1
    grouped.set(review.day, day)
  }
  const values = [...grouped.values()].sort((left, right) => left.day.localeCompare(right.day))
  const maximum = Math.max(1, ...values.map(day => day.pass + day.block + day.incomplete + day.ungated))
  return values.map(day => ({
    ...day,
    passHeight: (day.pass / maximum) * 132,
    blockHeight: (day.block / maximum) * 132,
    incompleteHeight: (day.incomplete / maximum) * 132,
    ungatedHeight: (day.ungated / maximum) * 132,
    total: day.pass + day.block + day.incomplete + day.ungated,
  }))
})
const chartDays = computed(() => {
  const visible = analyticsRange.value === 'custom' ? analyticsDays.value : analyticsDays.value.slice(-analyticsWindow.value)
  const maximum = Math.max(1, ...visible.map(day => day.total))
  return visible.map(day => ({
    ...day,
    passHeight: day.pass / maximum * 132,
    blockHeight: day.block / maximum * 132,
    incompleteHeight: day.incomplete / maximum * 132,
    ungatedHeight: day.ungated / maximum * 132,
  }))
})
const analyticsDayReviews = computed(() => selectedAnalyticsDay.value
  ? reviews.value.filter(review => chartDays.value.some(day => day.day === selectedAnalyticsDay.value) && analyticsRangeReviews.value.some(item => item.review_id === review.review_id && item.day === selectedAnalyticsDay.value)).map(review => {
    const dimension = analyticsRangeReviews.value.find(item => item.review_id === review.review_id && item.day === selectedAnalyticsDay.value)
    return { ...review, gate_status: dimension?.status || 'unknown' }
  })
  : [])
const analyticsSeverityFindings = computed(() => selectedAnalyticsSeverity.value
  ? (analytics.value?.finding_drilldown || []).filter(finding => finding.severity === selectedAnalyticsSeverity.value)
  : [])
const severityBars = computed(() => {
  const entries = Object.entries(analytics.value?.findings_by_severity || {})
  const maximum = Math.max(1, ...entries.map(([, value]) => value))
  const order = ['critical', 'high', 'medium', 'low', 'info']
  return entries
    .map(([severity, count]) => ({ severity, count, width: `${(count / maximum) * 100}%` }))
    .sort((left, right) => order.indexOf(left.severity) - order.indexOf(right.severity))
})
const ruleBars = computed(() => {
  const entries = Object.entries(analytics.value?.findings_by_rule || {})
  const maximum = Math.max(1, ...entries.map(([, value]) => value))
  return entries
    .map(([ruleId, count]) => ({ ruleId, count, width: `${(count / maximum) * 100}%` }))
    .sort((left, right) => right.count - left.count || left.ruleId.localeCompare(right.ruleId))
})
const providerLatencyBars = computed(() => {
  const entries = analytics.value?.provider_latency || []
  const maximum = Math.max(1, ...entries.map(item => item.p95_duration_ms || 0))
  return [...entries].sort((a, b) => (b.p95_duration_ms || 0) - (a.p95_duration_ms || 0) || a.provider_id.localeCompare(b.provider_id)).map(item => ({
    ...item,
    p50_width: `${((item.median_duration_ms || 0) / maximum) * 100}%`,
    p95_width: `${((item.p95_duration_ms || 0) / maximum) * 100}%`,
  }))
})
const providerCostBars = computed(() => {
  const totals = new Map()
  for (const day of providerCostHistoryDays.value) {
    for (const item of day.providers) {
      const total = totals.get(item.provider_id) || { provider_id: item.provider_id, estimated_usd: 0, priced_runs: 0, unpriced_runs: 0 }
      total.estimated_usd += item.estimated_usd
      total.priced_runs += item.priced_runs
      total.unpriced_runs += item.unpriced_runs
      totals.set(item.provider_id, total)
    }
  }
  return [...totals.values()].map(item => ({ ...item, estimated_usd: item.priced_runs ? item.estimated_usd : null }))
    .sort((a, b) => (b.estimated_usd || 0) - (a.estimated_usd || 0) || a.provider_id.localeCompare(b.provider_id))
})
const providerCostHistoryDays = computed(() => {
  if (invalidAnalyticsDateRange.value) return []
  const grouped = new Map()
  for (const point of analytics.value?.provider_cost_history || []) {
    if (analyticsProvider.value && point.provider_id !== analyticsProvider.value) continue
    if (analyticsRange.value === 'custom' && ((analyticsDateFrom.value && point.day < analyticsDateFrom.value) || (analyticsDateTo.value && point.day > analyticsDateTo.value))) continue
    const rows = grouped.get(point.day) || []
    rows.push(point)
    grouped.set(point.day, rows)
  }
  const ordered = [...grouped.entries()].sort(([a], [b]) => a.localeCompare(b))
  const visible = analyticsRange.value === 'custom' ? ordered : ordered.slice(-analyticsWindow.value)
  const maximum = Math.max(0.000001, ...visible.flatMap(([, rows]) => rows.map(row => row.estimated_usd || 0)))
  return visible.map(([day, rows]) => ({ day, providers: rows.sort((a, b) => a.provider_id.localeCompare(b.provider_id)).map(row => ({ ...row, height: Math.max(3, row.estimated_usd / maximum * 96) })) }))
})
const providerCostWindow = computed(() => analyticsRange.value === 'custom'
  ? 'custom_date_range'
  : `latest_${providerCostHistoryDays.value.length}_dates_with_provider_usage`)
const verificationProfiles = computed(() => [...new Set((analytics.value?.verification_runs || []).map(run => run.profile_id))].sort())
const filteredVerificationRuns = computed(() => (analytics.value?.verification_runs || []).filter(run => {
  if (verificationProfile.value && run.profile_id !== verificationProfile.value) return false
  const day = run.created_at.slice(0, 10)
  if (analyticsRange.value === 'custom') {
    if (invalidAnalyticsDateRange.value) return false
    if (analyticsDateFrom.value && day < analyticsDateFrom.value) return false
    if (analyticsDateTo.value && day > analyticsDateTo.value) return false
  }
  return true
}))
const providerLatencyHistoryDays = computed(() => {
  if (invalidAnalyticsDateRange.value) return []
  const grouped = new Map()
  for (const point of analytics.value?.provider_latency_history || []) {
    if (analyticsProvider.value && point.provider_id !== analyticsProvider.value) continue
    if (analyticsRange.value === 'custom' && ((analyticsDateFrom.value && point.day < analyticsDateFrom.value) || (analyticsDateTo.value && point.day > analyticsDateTo.value))) continue
    if (point.p95_duration_ms == null) continue
    const providers = grouped.get(point.day) || []
    providers.push(point)
    grouped.set(point.day, providers)
  }
  const ordered = [...grouped.entries()].sort(([left], [right]) => left.localeCompare(right))
  const visible = analyticsRange.value === 'custom' ? ordered : ordered.slice(-analyticsWindow.value)
  const maximum = Math.max(1, ...visible.flatMap(([, providers]) => providers.map(item => item.p95_duration_ms || 0)))
  return visible.map(([day, providers]) => ({ day, providers: providers.sort((a, b) => a.provider_id.localeCompare(b.provider_id)).map(item => ({ ...item, height: Math.max(3, (item.p95_duration_ms / maximum) * 96) })) }))
})
const verificationDays = computed(() => {
  const grouped = new Map()
  for (const run of filteredVerificationRuns.value) {
    const day = run.created_at.slice(0, 10)
    const entry = grouped.get(day) || { day, passed: 0, failed: 0, timed_out: 0, total: 0 }
    const outcome = verificationOutcome(run)
    if (Object.hasOwn(entry, outcome)) entry[outcome]++
    entry.total++
    grouped.set(day, entry)
  }
  const values = [...grouped.values()].sort((left, right) => left.day.localeCompare(right.day))
  const maximum = Math.max(1, ...values.map(day => day.total))
  return values.map(day => ({
    ...day,
    passedHeight: day.passed / maximum * 132,
    failedHeight: day.failed / maximum * 132,
    timedOutHeight: day.timed_out / maximum * 132,
  }))
})
const verificationChartDays = computed(() => {
  const visible = analyticsRange.value === 'custom' ? verificationDays.value : verificationDays.value.slice(-analyticsWindow.value)
  const maximum = Math.max(1, ...visible.map(day => day.total))
  return visible.map(day => ({
    ...day,
    passedHeight: day.passed / maximum * 132,
    failedHeight: day.failed / maximum * 132,
    timedOutHeight: day.timed_out / maximum * 132,
  }))
})
const verificationVisibleRuns = computed(() => {
  const visibleDates = new Set(verificationChartDays.value.map(day => day.day))
  return filteredVerificationRuns.value.filter(run => visibleDates.has(run.created_at.slice(0, 10)))
})
const verificationDayRuns = computed(() => verificationChartDays.value.some(day => day.day === selectedVerificationDay.value)
  ? filteredVerificationRuns.value.filter(run => run.created_at.slice(0, 10) === selectedVerificationDay.value)
  : [])

async function api(path, options = {}) {
  const tokenKey = 'vee.network-ui.token.v1'
  const send = token => fetch(path, {
    ...options,
    headers: {
      'content-type': 'application/json',
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...options.headers,
    },
  })
  let token = null
  try { token = window.sessionStorage.getItem(tokenKey) } catch {}
  let response = await send(token)
  if (response.status === 401) {
    const supplied = window.prompt('Enter the Vee network UI access token shown in the Vee terminal.')
    if (!supplied?.trim()) throw new Error('Vee network UI access token is required.')
    token = supplied.trim()
    try { window.sessionStorage.setItem(tokenKey, token) } catch {}
    response = await send(token)
    if (response.status === 401) {
      try { window.sessionStorage.removeItem(tokenKey) } catch {}
    }
  }
  const body = await response.json()
  if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`)
  return body
}
async function refreshReviews(keep = true) {
  const requestId = ++historyRequestId
  let history
  try {
    history = await api('/api/reviews')
  } catch (cause) {
    if (requestId === historyRequestId) error.value = `Review history could not be refreshed: ${cause.message}`
    throw cause
  }
  if (requestId !== historyRequestId) return
  reviews.value = history
  const selectedReviewId = keep && selected.value ? selected.value.review.review_id : (!selected.value && reviews.value.length ? reviews.value[0].review_id : null)
  if (selectedReviewId) await openReview(selectedReviewId, false)
  loadAnalytics().catch(() => {})
}
async function loadAnalytics() {
  const requestId = ++analyticsRequestId
  analyticsLoading.value = true
  let next
  try { next = await api('/api/analytics') }
  catch (cause) {
    if (requestId === analyticsRequestId) {
      analyticsLoading.value = false
      analyticsError.value = `Analytics could not be refreshed: ${cause.message}. ${analytics.value ? 'Showing the last saved report.' : 'Try again to load the report.'}`
    }
    return
  }
  if (requestId !== analyticsRequestId) return
  analyticsLoading.value = false
  analytics.value = next
  analyticsError.value = ''
  queueReviewerOptions.value = [...new Set((next.review_dimensions || []).flatMap(item => item.reviewer_ids || []))].sort()
  queueProviderOptions.value = [...new Set((next.review_dimensions || []).flatMap(item => item.provider_ids || []))].sort()
}
function exportAnalytics(format) {
  if (!analytics.value) return
  const metrics = [
    ...chartDays.value.flatMap(day => ['pass', 'block', 'incomplete', 'ungated'].map(label => ({
      metric: 'review_gate_outcomes', period: day.day, label, count: day[label],
    }))),
    ...verificationChartDays.value.flatMap(day => ['passed', 'failed', 'timed_out'].map(label => ({
      metric: 'verification_runs', period: day.day, label, count: day[label],
    }))),
    ...severityBars.value.map(item => ({ metric: 'current_finding_severity', period: '', label: item.severity, count: item.count })),
    ...Object.entries(analytics.value.findings_by_rule || {}).map(([label, count]) => ({ metric: 'current_findings_by_rule', period: '', label, count })),
    ...Object.entries(analytics.value.explicit_feedback_by_label || {}).map(([label, count]) => ({ metric: 'explicit_human_feedback', period: '', label, count })),
    ...(analytics.value.provider_latency || []).flatMap(item => [
      { metric: 'provider_latency_ms', period: 'latest_2000_reviews', label: `${item.provider_id}:p50`, count: item.median_duration_ms ?? '' },
      { metric: 'provider_latency_ms', period: 'latest_2000_reviews', label: `${item.provider_id}:p95`, count: item.p95_duration_ms ?? '' },
      { metric: 'provider_latency_runs', period: 'latest_2000_reviews', label: `${item.provider_id}:measured`, count: item.measured_runs },
      { metric: 'provider_latency_runs', period: 'latest_2000_reviews', label: `${item.provider_id}:unmeasured`, count: item.unmeasured_runs },
      { metric: 'provider_latency_runs', period: 'latest_2000_reviews', label: `${item.provider_id}:failed`, count: item.failed_runs },
    ]),
    ...providerLatencyHistoryDays.value.flatMap(day => day.providers.flatMap(item => [
      { metric: 'provider_latency_daily_ms', period: day.day, label: `${item.provider_id}:p50`, count: item.median_duration_ms ?? '' },
      { metric: 'provider_latency_daily_ms', period: day.day, label: `${item.provider_id}:p95`, count: item.p95_duration_ms ?? '' },
      { metric: 'provider_latency_daily_runs', period: day.day, label: item.provider_id, count: item.measured_runs },
    ])),
    ...providerCostBars.value.flatMap(item => [
      { metric: 'provider_estimated_cost_usd', period: providerCostWindow.value, label: `${item.provider_id}:estimated_total`, count: item.estimated_usd ?? '' },
      { metric: 'provider_cost_runs', period: providerCostWindow.value, label: `${item.provider_id}:priced`, count: item.priced_runs },
      { metric: 'provider_cost_runs', period: providerCostWindow.value, label: `${item.provider_id}:unpriced`, count: item.unpriced_runs },
    ]),
    ...providerCostHistoryDays.value.flatMap(day => day.providers.map(item => ({ metric: 'provider_estimated_cost_daily_usd', period: day.day, label: item.provider_id, count: item.estimated_usd }))),
  ]
  const report = {
    schema_version: 1,
    source_schema_version: analytics.value.schema_version,
    scope: 'repository_local',
    filters: { reviewer_id: analyticsReviewer.value || null, provider_id: analyticsProvider.value || null, finding_category: analyticsCategory.value || null, rule_id: analyticsRule.value || null, verification_profile_id: verificationProfile.value || null },
    gate_trend_window: analyticsRange.value === 'custom' ? 'custom_date_range' : `latest_${chartDays.value.length}_dates_with_saved_reviews`,
    date_from: analyticsRange.value === 'custom' ? analyticsDateFrom.value || null : null,
    date_to: analyticsRange.value === 'custom' ? analyticsDateTo.value || null : null,
    gate_trend_review_count: chartDays.value.reduce((sum, day) => sum + day.total, 0),
    history_complete: analytics.value.history_complete,
    dimensions_complete: analytics.value.dimensions_complete,
    metric_scope_notes: [
      'Gate outcome rows use the selected reviewer, provider, and finding-category filters over the latest 500 saved reviews.',
      'Severity, rule-attributed finding, and explicit feedback rows are repository-wide current-record totals and are not narrowed by review filters.',
      'Rule attribution is reviewer-reported and linked only to an active, in-scope human-approved rule; it is not verified causation.',
    ],
    finding_drilldown_complete: analytics.value.finding_drilldown_complete,
    findings_by_rule_complete: analytics.value.findings_by_rule_complete,
    verification_run_count: analytics.value.verification_run_count,
    verification_history_complete: analytics.value.verification_history_complete,
    verification_filter: { profile_id: verificationProfile.value || null },
    verification_trend_window: analyticsRange.value === 'custom' ? 'custom_date_range' : `latest_${verificationChartDays.value.length}_dates_with_verification_runs`,
    verification_run_count_in_visible_range: verificationVisibleRuns.value.length,
    verification_note: 'Verification counts are observed run events, not a success rate or a denominator for all tests.',
    feedback_note: analytics.value.feedback_note,
    provider_latency: analytics.value.provider_latency,
    provider_latency_history_complete: analytics.value.provider_latency_history_complete,
    provider_latency_reviews: analytics.value.provider_latency_reviews,
    provider_latency_history: providerLatencyHistoryDays.value.flatMap(day => day.providers.map(({ height, ...item }) => ({ ...item, day: day.day }))),
    provider_latency_note: analytics.value.provider_latency_note,
    provider_costs: providerCostBars.value,
    provider_cost_window: providerCostWindow.value,
    provider_cost_history_complete: analytics.value.provider_cost_history_complete,
    provider_cost_reviews: analytics.value.provider_cost_reviews,
    provider_cost_history: providerCostHistoryDays.value.flatMap(day => day.providers.map(({ height, ...item }) => ({ ...item, day: day.day }))),
    provider_cost_note: analytics.value.provider_cost_note,
    metrics,
  }
  const content = format === 'json'
    ? JSON.stringify(report, null, 2)
    : ['metric,period,label,count,metric_scope,reviewer_filter,provider_filter,category_filter,rule_filter,verification_profile_filter,date_from,date_to', ...metrics.map(row => [
      row.metric, row.period, row.label, row.count,
      row.metric === 'review_gate_outcomes' ? 'filtered_gate_trend' : row.metric === 'verification_runs' ? 'filtered_verification_trend' : row.metric.startsWith('provider_estimated_cost') || row.metric === 'provider_cost_runs' ? 'provider_usage_estimate' : 'repository_current_state',
      analyticsReviewer.value, analyticsProvider.value, analyticsCategory.value,
      analyticsRule.value,
      verificationProfile.value,
      analyticsRange.value === 'custom' ? analyticsDateFrom.value : '',
      analyticsRange.value === 'custom' ? analyticsDateTo.value : '',
    ].map(value => {
      const text = String(value)
      const safe = /^[\s\u0000-\u001f]*[=+\-@]/.test(text) ? `'${text}` : text
      return `"${safe.replaceAll('"', '""')}"`
    }).join(','))].join('\n') + '\n'
  const mime = format === 'json' ? 'application/json' : 'text/csv'
  const url = URL.createObjectURL(new Blob([content], { type: `${mime};charset=utf-8` }))
  const link = document.createElement('a')
  link.href = url
  link.download = `vee-local-analytics.${format}`
  link.click()
  window.setTimeout(() => URL.revokeObjectURL(url), 1000)
}
function readSavedAnalyticsViews() {
  try {
    const key = repositoryStorageKeyFor('analytics.views')
    if (!key) return []
    const stored = JSON.parse(window.localStorage.getItem(key) || '{"schema_version":1,"views":[]}')
    if (stored?.schema_version !== 1 || !Array.isArray(stored.views)) return []
    return stored.views.slice(0, 25).filter(view =>
      view && typeof view.id === 'string' && typeof view.name === 'string' && view.name.trim() &&
      ['recent', 'custom'].includes(view.range) && [7, 14].includes(view.window) &&
      typeof view.date_from === 'string' && typeof view.date_to === 'string' &&
      typeof view.reviewer === 'string' && typeof view.provider === 'string' && typeof view.category === 'string',
    )
  } catch {
    analyticsViewMessage.value = 'Saved views are unavailable in this browser profile.'
    return []
  }
}
function persistSavedAnalyticsViews() {
  try {
    const key = repositoryStorageKeyFor('analytics.views')
    if (!key) return false
    window.localStorage.setItem(key, JSON.stringify({ schema_version: 1, views: savedAnalyticsViews.value }))
    analyticsViewMessage.value = ''
    return true
  } catch {
    analyticsViewMessage.value = 'Could not save this view in browser storage.'
    return false
  }
}
function saveAnalyticsView() {
  const name = analyticsViewName.value.trim()
  if (!name || name.length > 60) {
    analyticsViewMessage.value = 'Enter a view name from 1 to 60 characters.'
    return
  }
  if (savedAnalyticsViews.value.length >= 25) {
    analyticsViewMessage.value = 'Remove a saved view before adding another (limit: 25).'
    return
  }
  const view = {
    id: globalThis.crypto?.randomUUID?.() || `view-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    name,
    range: analyticsRange.value,
    window: analyticsWindow.value,
    date_from: analyticsDateFrom.value,
    date_to: analyticsDateTo.value,
    reviewer: analyticsReviewer.value,
    provider: analyticsProvider.value,
    category: analyticsCategory.value,
    rule: analyticsRule.value,
    verification_profile: verificationProfile.value,
  }
  savedAnalyticsViews.value = [...savedAnalyticsViews.value, view]
  selectedAnalyticsViewId.value = view.id
  analyticsViewName.value = ''
  persistSavedAnalyticsViews()
  if (!analyticsViewMessage.value) analyticsViewMessage.value = `Saved “${name}”.`
}
function applySavedAnalyticsView() {
  const view = savedAnalyticsViews.value.find(item => item.id === selectedAnalyticsViewId.value)
  if (!view) return
  analyticsRange.value = view.range
  analyticsWindow.value = view.window
  analyticsDateFrom.value = view.date_from
  analyticsDateTo.value = view.date_to
  analyticsReviewer.value = view.reviewer
  analyticsProvider.value = view.provider
  analyticsCategory.value = view.category
  analyticsRule.value = view.rule || ''
  verificationProfile.value = view.verification_profile || ''
  selectedAnalyticsDay.value = ''
  selectedAnalyticsSeverity.value = ''
  analyticsViewMessage.value = `Loaded “${view.name}”.`
}
function deleteSavedAnalyticsView() {
  if (!selectedAnalyticsViewId.value) return
  const previousViews = savedAnalyticsViews.value
  const previousSelection = selectedAnalyticsViewId.value
  savedAnalyticsViews.value = savedAnalyticsViews.value.filter(view => view.id !== selectedAnalyticsViewId.value)
  selectedAnalyticsViewId.value = ''
  if (!persistSavedAnalyticsViews()) {
    savedAnalyticsViews.value = previousViews
    selectedAnalyticsViewId.value = previousSelection
  } else {
    analyticsViewMessage.value = 'Deleted the saved Insights view.'
  }
}
async function openReview(id, showError = true, allowWhileLoading = false) {
  if (loading.value && !allowWhileLoading) return
  const requestId = ++detailRequestId
  if (selected.value?.review?.review_id !== id) { selected.value = null; closeFinding() }
  detailLoaded.value = false
  detailError.value = false
  try {
    const detail = await api(`/api/reviews/${encodeURIComponent(id)}`)
    if (requestId !== detailRequestId) return
    selected.value = detail; detailLoaded.value = true
    // Keep an open drawer on the saved record, e.g. after a disposition change.
    if (drawerRecord.value) {
      const fresh = (detail.findings || []).find(record => record.finding.id === drawerRecord.value.finding.id)
      if (fresh) drawerRecord.value = fresh
      else closeFinding()
    }
  } catch (e) {
    if (requestId !== detailRequestId) return
    detailError.value = true
    if (showError) error.value = e.message
  }
}
// Elapsed time of the running review; the previous review stays visible meanwhile.
const reviewStartedAt = ref(0)
const clock = ref(0)
let reviewClock = null
const reviewElapsed = computed(() => {
  const seconds = Math.max(0, Math.floor((clock.value - reviewStartedAt.value) / 1000))
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`
})
// Live reviewer progress of the running review, polled once a second.
// Each run sends its own token, so the page follows its own run and not a
// review another tab or API client started on the same server.
const reviewProgress = ref(null)
let progressToken = ''
let progressRequest = null
const newProgressToken = () => globalThis.crypto?.randomUUID?.() || `run-${Date.now()}-${Math.random().toString(36).slice(2)}`
function pollReviewProgress() {
  if (progressRequest || !progressToken) return
  const token = progressToken
  progressRequest = api('/api/reviews/progress')
    .then(report => {
      // A response for an earlier run, or one arriving after this run ended, is stale.
      if (!loading.value || token !== progressToken) return
      reviewProgress.value = (report.reviews || []).find(review => review.progress_token === token) || null
    })
    .catch(() => {})
    .finally(() => { progressRequest = null })
}
const reviewerState = reviewer => reviewer.finished < reviewer.runs ? 'running' : reviewer.failed ? 'failed' : 'done'
const reviewerStateIcon = { running: '◌', failed: '✖', done: '✓' }
const progressSummary = computed(() => {
  const reviewers = reviewProgress.value?.reviewers || []
  if (!reviewers.length) return reviewProgress.value ? 'Preparing review context…' : ''
  const done = reviewers.filter(reviewer => reviewerState(reviewer) !== 'running').length
  return `${done} of ${reviewers.length} reviewers finished`
})
const stopReviewClock = () => { clearInterval(reviewClock); reviewClock = null; reviewProgress.value = null; progressToken = '' }
onBeforeUnmount(stopReviewClock)
async function startReview() {
  historyRequestId++
  detailRequestId++
  loading.value = true; error.value = ''; closeFinding()
  reviewStartedAt.value = clock.value = Date.now()
  progressToken = newProgressToken()
  reviewClock = setInterval(() => { clock.value = Date.now(); pollReviewProgress() }, 1000)
  try {
    const request = { scope: scope.value, reviewer_ids: [], progress_token: progressToken }
    if (scope.value === 'base' && base.value.trim()) request.base = base.value.trim()
    const started = await api('/api/reviews', { method: 'POST', body: JSON.stringify(request) })
    const reviewId = started.review_id
    selected.value = {
      review: started,
      findings: (started.findings || []).map(finding => ({ finding, status: 'open', occurrences: [] })),
      evidence: started.evidence || [],
      impact: null,
    }
    await openReview(reviewId, true, true)
    try { await refreshReviews(false) }
    catch (e) { error.value = `Review started, but history could not be refreshed: ${e.message}` }
  } catch (e) { error.value = e.message }
  finally { loading.value = false; stopReviewClock() }
}
async function loadConfig() {
  try { config.value = await api('/api/config'); configText.value = JSON.stringify(config.value.config, null, 2) }
  catch (e) { error.value = e.message }
}
async function saveConfig() {
  saving.value = true; error.value = ''
  try {
    const value = JSON.parse(configText.value)
    config.value = await api('/api/config', { method: 'PUT', body: JSON.stringify({ config: value }) })
    configText.value = JSON.stringify(config.value.config, null, 2)
  } catch (e) { error.value = e.message }
  finally { saving.value = false }
}
async function updateFindingStatus(record) {
  const id = record.finding.id
  const reviewId = selected.value?.review?.review_id
  if (!reviewId) return
  const draft = dispositionDrafts.value[id] || { status: record.status, reason: '' }
  savingFinding.value = id; findingMessage.value = ''; error.value = ''
  try {
    await api(`/api/findings/${encodeURIComponent(id)}/status`, {
      method: 'POST',
      body: JSON.stringify({ status: draft.status, reason: draft.reason }),
    })
    findingMessage.value = `Saved disposition for ${id}. This does not create a policy waiver.`
    closeDisposition(id)
    if (selected.value?.review?.review_id === reviewId) await openReview(reviewId, false)
  } catch (e) { error.value = e.message }
  finally { savingFinding.value = '' }
}
// Move focus into the form when it opens and back to its trigger when it closes.
const focusLabelled = label => nextTick(() => document.querySelector(`[aria-label="${CSS.escape(label)}"]`)?.focus())
function openDisposition(id) {
  editingDisposition.value = id
  focusLabelled(`Disposition for ${id}`)
}
function closeDisposition(id) {
  if (editingDisposition.value === id) editingDisposition.value = ''
  delete dispositionDrafts.value[id]
  focusLabelled(`Set disposition for ${id}`)
}
// A one-line label for a finding: the first sentence of its rationale, bounded.
const findingTitle = finding => {
  const text = String(finding?.rationale || finding?.category || 'Finding').trim()
  const sentence = (text.match(/^[\s\S]*?[.!?](\s|$)/)?.[0] || text).trim()
  return sentence.length > 120 ? `${sentence.slice(0, 117)}…` : sentence
}
const drawerSourceLines = computed(() => {
  const context = drawerView.value?.task?.source_context
  if (!context) return []
  // The backend renders each line as `{n:>6} | {text}`; keep its numbers.
  return context.content.split('\n').filter(line => line !== '').map((line, index) => {
    const match = line.match(/^\s*(\d+) \| ?(.*)$/)
    const number = match ? Number(match[1]) : context.start_line + index
    return { number, text: match ? match[2] : line, flagged: number === drawerRecord.value?.finding?.line }
  })
})
// Identifies the latest drawer request, so a slower earlier response is dropped.
let drawerRequest = 0
const drawerCloseButton = ref(null)
let drawerOpener = null
async function openFinding(record) {
  const request = ++drawerRequest
  drawerOpener = document.activeElement
  drawerRecord.value = record; drawerView.value = null; drawerError.value = ''; drawerMessage.value = ''
  // After the state change, so the callback runs once the drawer is rendered.
  nextTick(() => drawerCloseButton.value?.focus())
  try {
    const view = await api(`/api/findings/${encodeURIComponent(record.finding.id)}/task`)
    if (request === drawerRequest) drawerView.value = view
  } catch (e) { if (request === drawerRequest) drawerError.value = e.message }
}
function closeFinding() {
  const wasOpen = Boolean(drawerRecord.value)
  drawerRequest += 1; drawerRecord.value = null; drawerView.value = null
  // Return focus to the control that opened the drawer, if it is still on the page.
  if (wasOpen && drawerOpener?.isConnected) drawerOpener.focus()
  drawerOpener = null
}
async function copyWorkPackage() {
  try {
    await navigator.clipboard.writeText(JSON.stringify(drawerView.value.task, null, 2))
    drawerMessage.value = 'Work package copied.'
  } catch { drawerMessage.value = 'Copy failed: the browser did not allow clipboard access.' }
}
onMounted(async () => {
  try {
    const health = await api('/api/health')
    repositoryStorageKey = health.repository
    savedAnalyticsViews.value = readSavedAnalyticsViews()
    queueSavedViews.value = readQueueViews()
    await Promise.all([refreshReviews(false), loadConfig()])
  }
  catch (e) { error.value = e.message }
  finally { initializing.value = false }
})
</script>

<template>
  <div class="shell" :class="{ 'drawer-open': drawerRecord }">
    <aside class="rail">
      <div class="brand"><span class="brand-mark">V</span><div><strong>vee</strong><small>LOCAL CODE ASSURANCE</small></div></div>
      <div class="rail-label">WORKSPACE</div>
      <button class="nav-item" :class="{ active: ['overview', 'findings', 'impact', 'reviewers'].includes(activeTab) }" @click="activeTab = 'overview'">◈ <span>Reviews</span></button>
      <button class="nav-item" :class="{ active: activeTab === 'queue' }" @click="activeTab = 'queue'">☷ <span>Review queue</span></button>
      <button class="nav-item" :class="{ active: activeTab === 'analytics' }" @click="activeTab = 'analytics'">▥ <span>Insights</span></button>
      <button class="nav-item" :class="{ active: activeTab === 'settings' }" @click="activeTab = 'settings'">⚙ <span>Configuration</span></button>
      <div class="rail-label history-label">HISTORY <span>{{ reviews.length }}</span></div>
      <div class="review-history" aria-label="Saved review history">
        <button v-for="item in reviews" :key="item.review_id" class="review-link" :class="{ chosen: selected?.review?.review_id === item.review_id }" :aria-label="`${item.review_id}, gate ${reviewStatus(item)}, ${item.created_at}`" :disabled="loading" @click="activeTab = 'overview'; openReview(item.review_id)">
          <span class="dot" :class="statusTone(reviewStatus(item))" :title="`Gate: ${reviewStatus(item)}`"></span><span class="review-link-text" :title="item.review_id"><b>{{ formatTime(item.created_at) }}</b><small>{{ reviewStatus(item) }} · {{ item.review_id.replace(/^rev_/, '').slice(0, 8) }}</small></span>
        </button>
        <div v-if="!reviews.length" class="empty-history">No reviews yet</div>
      </div>
      <div class="local-badge"><span></span> LOCAL REPOSITORY</div>
    </aside>

    <main class="main">
      <header class="topbar"><div><div class="eyebrow">VEE / INVESTIGATION</div><h1>{{ activeTab === 'settings' ? 'Review configuration' : activeTab === 'analytics' ? 'Review insights' : activeTab === 'queue' ? 'Review queue' : 'Change review' }}</h1></div><div class="top-meta"><span class="live-dot"></span> Running locally</div></header>
      <div v-if="error" class="alert"><span>{{ error }}</span><button @click="error = ''">Dismiss</button></div>

      <section v-if="activeTab === 'queue'" class="queue-view">
        <div class="section-head"><div><h2>Saved review triage</h2><p>Repository-local reviews, ordered newest first. Gate state comes from the latest saved decision in the retained history window.</p></div><button class="text-button" @click="refreshReviews(false)">Refresh ↻</button></div>
        <p v-if="analyticsError" class="hint" role="alert">{{ analyticsError }} Gate labels below are unavailable because they may be out of date. <button class="text-button" @click="loadAnalytics">Try again ↻</button></p>
        <div class="queue-filters" aria-label="Review queue filters">
          <label>Gate status<select v-model="queueStatus" aria-label="Filter queue by gate status"><option value="all">All statuses</option><option value="block">Blocked</option><option value="incomplete">Incomplete</option><option value="pass">Passed</option><option value="ungated">No gate</option><option value="unknown">Status unavailable</option></select></label>
          <label>Reviewer<select v-model="queueReviewer" aria-label="Filter queue by reviewer"><option value="">All reviewers</option><option v-for="id in queueReviewers" :key="id" :value="id">{{ id }}</option></select></label>
          <label>Provider<select v-model="queueProvider" aria-label="Filter queue by provider"><option value="">All providers</option><option v-for="id in queueProviders" :key="id" :value="id">{{ id }}</option></select></label>
          <label class="queue-search">Search<input v-model="queueQuery" aria-label="Search review queue" placeholder="Review, snapshot, reviewer…"></label>
          <button class="text-button" @click="clearQueueFilters">Clear filters</button>
        </div>
        <details class="saved-views-toggle" :open="queueSavedViews.length > 0"><summary>Saved views<span v-if="queueSavedViews.length"> · {{ queueSavedViews.length }}</span></summary>
        <div class="queue-saved-views" aria-label="Saved review queue views">
          <label>Saved view<select v-model="queueSavedViewId" aria-label="Choose saved queue view"><option value="">Choose a saved view</option><option v-for="view in queueSavedViews" :key="view.id" :value="view.id">{{ view.name }}</option></select></label>
          <button class="text-button" :disabled="!queueSavedViewId" @click="applyQueueView">Load view</button>
          <button class="text-button" :disabled="!queueSavedViewId" @click="deleteQueueView">Delete view</button>
          <label>Save current filters<input v-model="queueViewName" aria-label="New queue view name" maxlength="60" placeholder="e.g. Blocked security reviews"></label>
          <button class="text-button" :disabled="!queueViewName.trim()" @click="saveQueueView">Save view</button>
          <small v-if="queueViewMessage" role="status">{{ queueViewMessage }}</small>
          <small v-else>Saved in this browser profile for this local Vee instance.</small>
        </div>
        </details>
        <p class="queue-scope hint">Showing {{ queueItems.length }} matching reviews from the latest {{ Math.min(reviews.length, 500) }} saved records<template v-if="reviews.length > 500">; older records are omitted</template>.<template v-if="queueItems.some(item => item.gate_status === 'unknown')"> “Status unavailable” means Vee could not load the review's retained analytics dimensions; it does not mean ungated.</template></p>
        <div v-if="queueItems.length" class="queue-list">
          <article v-for="item in queueItems" :key="item.review_id" class="queue-card">
            <div class="queue-card-main"><span class="status-pill" :class="statusTone(item.gate_status)">{{ item.gate_status_stale ? 'possibly outdated' : item.gate_status === 'unknown' ? 'status unavailable' : item.gate_status === 'ungated' ? 'no gate' : item.gate_status }}</span><div><strong>{{ item.review_id }}</strong><small>{{ item.created_at }} · snapshot {{ item.snapshot_id }}</small><small v-if="item.status !== item.gate_status && !['unknown', 'ungated'].includes(item.gate_status)">Reviewed as {{ item.status }}; gate re-evaluated since</small><small v-if="item.next_action" class="next-action" :data-kind="item.next_action.kind">Next: {{ item.next_action.summary }}</small></div></div>
            <div class="queue-tags"><span v-for="id in item.reviewer_ids" :key="`reviewer:${id}`">{{ id }}</span><span v-for="id in item.provider_ids" :key="`provider:${id}`" class="provider-tag">{{ id }}</span><span v-if="!item.reviewer_ids.length && !item.provider_ids.length" class="queue-no-tags">No reviewer dimensions available</span></div>
            <button class="text-button" :disabled="loading" @click="activeTab = 'overview'; openReview(item.review_id)">Open review →</button>
          </article>
        </div>
        <div v-else class="queue-empty"><strong>{{ reviews.length ? 'No reviews match these filters' : 'No saved reviews yet' }}</strong><small>{{ reviews.length ? 'Clear or adjust the filters to see repository history.' : 'Run a review to start building the local queue.' }}</small></div>
      </section>

      <section v-else-if="activeTab === 'analytics'" class="analytics-view">
        <div class="section-head"><div><h2>Local review analytics</h2><p>Trends from saved reviews in this repository.</p></div><div class="analytics-actions"><button class="text-button" @click="exportAnalytics('json')">Export JSON</button><button class="text-button" @click="exportAnalytics('csv')">Export CSV</button><button class="text-button" @click="loadAnalytics">Refresh ↻</button></div></div>
        <p v-if="analyticsError" class="hint" role="alert">{{ analyticsError }} <button class="text-button" @click="loadAnalytics">Try again ↻</button></p>
        <div v-if="analyticsLoading && !analytics" class="analytics-loading" role="status"><span class="spinner" aria-hidden="true"></span>Computing insights from saved reviews…</div>
        <div v-if="analytics" class="analytics-filters" aria-label="Analytics filters">
          <label>Reviewer<select v-model="analyticsReviewer" aria-label="Filter by reviewer"><option value="">All reviewers</option><option v-for="id in analyticsOptions('reviewer_ids')" :key="id" :value="id">{{ id }}</option></select></label>
          <label>Provider<select v-model="analyticsProvider" aria-label="Filter by provider"><option value="">All providers</option><option v-for="id in analyticsOptions('provider_ids')" :key="id" :value="id">{{ id }}</option></select></label>
          <label>Finding category<select v-model="analyticsCategory" aria-label="Filter by finding category"><option value="">All categories</option><option v-for="id in analyticsOptions('finding_categories')" :key="id" :value="id">{{ id }}</option></select></label>
          <label>Approved rule<select v-model="analyticsRule" aria-label="Filter by approved rule"><option value="">All rules</option><option v-for="id in analyticsOptions('finding_rule_ids')" :key="id" :value="id">{{ id }}</option></select></label>
          <button class="text-button" @click="analyticsReviewer = ''; analyticsProvider = ''; analyticsCategory = ''; analyticsRule = ''">Clear filters</button>
        </div>
        <details v-if="analytics" class="saved-views-toggle" :open="savedAnalyticsViews.length > 0"><summary>Saved views<span v-if="savedAnalyticsViews.length"> · {{ savedAnalyticsViews.length }}</span></summary>
        <div class="analytics-saved-views" aria-label="Saved Insights views">
          <label>Saved view<select v-model="selectedAnalyticsViewId" aria-label="Choose saved Insights view"><option value="">Choose a saved view</option><option v-for="view in savedAnalyticsViews" :key="view.id" :value="view.id">{{ view.name }}</option></select></label>
          <button class="text-button" :disabled="!selectedAnalyticsViewId" @click="applySavedAnalyticsView">Load view</button>
          <button class="text-button" :disabled="!selectedAnalyticsViewId" @click="deleteSavedAnalyticsView">Delete view</button>
          <label>Save current filters<input v-model="analyticsViewName" aria-label="New Insights view name" maxlength="60" placeholder="e.g. Security reviews"></label>
          <button class="text-button" :disabled="!analyticsViewName.trim()" @click="saveAnalyticsView">Save view</button>
          <small v-if="analyticsViewMessage" role="status">{{ analyticsViewMessage }}</small>
          <small v-else>Saved in this browser profile for this local Vee instance.</small>
        </div>
        </details>
        <div v-if="analytics" class="analytics-kpis">
          <div class="summary-card"><div class="card-label">FILTERED REVIEWS</div><strong class="metric">{{ chartDays.reduce((total, day) => total + day.total, 0) }}</strong><small>in the visible window from {{ analyticsDimensions.length }} saved reviews</small></div>
          <div class="summary-card"><div class="card-label">GATE PASS</div><strong class="metric good">{{ chartDays.reduce((total, day) => total + day.pass, 0) }}</strong><small>in the visible filtered timeline</small></div>
          <div class="summary-card"><div class="card-label">FINDINGS</div><strong class="metric">{{ Object.values(analytics.findings_by_severity).reduce((a, b) => a + b, 0) }}</strong><small>current unique finding records</small></div>
        </div>
        <div v-if="analytics" class="analytics-grid">
          <section class="panel chart-panel"><div class="panel-head"><div><h3>Gate outcomes over time</h3><p>Daily saved reviews, grouped by their latest recorded gate.</p></div><div class="chart-controls"><span class="chart-unit">REVIEWS / DAY</span><select v-model="analyticsRange" aria-label="Chart date range"><option value="recent">Recent dates</option><option value="custom">Custom range</option></select><select v-if="analyticsRange === 'recent'" v-model.number="analyticsWindow" aria-label="Recent date count"><option :value="7">7 dates</option><option :value="14">14 dates</option></select></div></div>
            <div v-if="analyticsRange === 'custom'" class="analytics-date-range"><label>From<input v-model="analyticsDateFrom" aria-label="Start date" type="date"></label><label>To<input v-model="analyticsDateTo" aria-label="End date" type="date"></label><button class="text-button" @click="analyticsDateFrom = ''; analyticsDateTo = ''">Clear dates</button></div>
            <p v-if="invalidAnalyticsDateRange" class="hint" role="alert">Start date must be on or before end date.</p>
            <div v-if="chartDays.length" class="timeline-chart" role="img" aria-label="Stacked bar chart of daily gate outcomes">
              <div class="chart-scale"><span v-for="(label, index) in scaleLabels(Math.max(1, ...chartDays.map(day => day.total)))" :key="index">{{ label }}</span></div>
              <div class="chart-bars"> <button v-for="day in chartDays" :key="day.day" class="day-column" :class="{ chosen: selectedAnalyticsDay === day.day }" :aria-label="`Show reviews for ${day.day}: ${day.pass} pass, ${day.block} block, ${day.incomplete} incomplete, ${day.ungated} without a gate`" :aria-pressed="selectedAnalyticsDay === day.day" :title="`${day.day}: ${day.pass} pass, ${day.block} block, ${day.incomplete} incomplete, ${day.ungated} without a gate`" @click="selectedAnalyticsDay = selectedAnalyticsDay === day.day ? '' : day.day"><span class="stacked-bar"><i class="bar-pass" :style="{ height: `${day.passHeight}px` }"></i><i class="bar-block" :style="{ height: `${day.blockHeight}px` }"></i><i class="bar-incomplete" :style="{ height: `${day.incompleteHeight}px` }"></i><i class="bar-ungated" :style="{ height: `${day.ungatedHeight}px` }"></i></span><small>{{ day.day.slice(5) }}</small></button></div>
            </div>
            <div v-else class="chart-empty">Run a review to start building a local trend.</div>
            <div class="chart-legend"><span><i class="bar-pass"></i>Pass</span><span><i class="bar-block"></i>Block</span><span><i class="bar-incomplete"></i>Incomplete</span><span><i class="bar-ungated"></i>No gate</span></div>
            <details class="chart-about"><summary>About this chart</summary><p class="hint"><template v-if="analyticsRange === 'custom'">Chart shows saved review dates in the selected custom range within available history; gate counts use the latest decision per review.</template><template v-else>Chart shows the {{ analyticsWindow }} latest dates with matching saved reviews; gate counts use the latest decision per review.</template> Reviews without a saved gate decision are shown as “No gate.” Finding severity and feedback panels summarize current repository-wide records. Filterable history is capped at the most recent 500 reviews<template v-if="!analytics.history_complete"> and older reviews are omitted</template>.<template v-if="!analytics.dimensions_complete"> Some saved review records lack readable reviewer/category dimensions and are excluded when a filter is selected.</template></p></details>
            <div v-if="selectedAnalyticsDay" class="analytics-drilldown" aria-live="polite"><div class="drilldown-head"><strong>Reviews on {{ selectedAnalyticsDay }}</strong><button class="text-button" @click="selectedAnalyticsDay = ''">Clear</button></div><button v-for="review in analyticsDayReviews" :key="review.review_id" class="drilldown-review" :disabled="loading" @click="activeTab = 'overview'; openReview(review.review_id)"><span class="dot" :class="statusTone(review.gate_status)"></span><span><b>{{ review.review_id }}</b><small>{{ review.created_at }} · Gate: {{ review.gate_status === 'ungated' ? 'no gate' : review.gate_status === 'unknown' ? 'status unavailable' : review.gate_status }} · Review: {{ review.status || 'unknown status' }}</small></span><span aria-hidden="true">→</span></button><p v-if="!analyticsDayReviews.length" class="hint">No matching review summaries are available for this chart date.</p><small v-if="!analytics.history_complete" class="hint">The chart is based on the latest 500 reviews, so this list can contain additional reviews for the same date.</small></div>
          </section>
          <section class="panel chart-panel"><div class="panel-head"><div><h3>Verification outcomes</h3><p>Saved verification run events, grouped by completion date.</p></div><label class="chart-controls">Profile<select v-model="verificationProfile" aria-label="Filter verification profile"><option value="">All profiles</option><option v-for="profile in verificationProfiles" :key="profile" :value="profile">{{ profile }}</option></select></label></div>
            <div v-if="verificationChartDays.length" class="timeline-chart" role="img" aria-label="Stacked bar chart of daily verification outcomes">
              <div class="chart-scale"><span v-for="(label, index) in scaleLabels(Math.max(1, ...verificationChartDays.map(day => day.total)))" :key="index">{{ label }}</span></div>
              <div class="chart-bars"><button v-for="day in verificationChartDays" :key="day.day" class="day-column" :class="{ chosen: selectedVerificationDay === day.day }" :aria-label="`Show verification runs for ${day.day}: ${day.passed} passed, ${day.failed} failed, ${day.timed_out} timed out`" :aria-pressed="selectedVerificationDay === day.day" :title="`${day.day}: ${day.passed} passed, ${day.failed} failed, ${day.timed_out} timed out`" @click="selectedVerificationDay = selectedVerificationDay === day.day ? '' : day.day"><span class="stacked-bar"><i class="bar-pass" :style="{ height: `${day.passedHeight}px` }"></i><i class="bar-block" :style="{ height: `${day.failedHeight}px` }"></i><i class="bar-incomplete" :style="{ height: `${day.timedOutHeight}px` }"></i></span><small>{{ day.day.slice(5) }}</small></button></div>
            </div>
            <div v-else class="chart-empty">No verification runs in this range.</div>
            <div class="chart-legend"><span><i class="bar-pass"></i>Passed</span><span><i class="bar-block"></i>Failed</span><span><i class="bar-incomplete"></i>Timed out</span></div>
            <details class="chart-about"><summary>About this chart</summary><p class="hint">Showing {{ verificationVisibleRuns.length }} retained runs matching this profile and visible dates; {{ analytics.verification_run_count }} runs exist in total. These are run counts, not pass rates. Analyzer runs with no findings on the changed lines count as passed, as the gate treats them. The chart uses the latest {{ analytics.verification_runs.length }} records<template v-if="!analytics.verification_history_complete">; older runs are omitted</template>.</p></details>
            <div v-if="selectedVerificationDay" class="analytics-drilldown" aria-live="polite"><div class="drilldown-head"><strong>Verification runs on {{ selectedVerificationDay }} · {{ verificationDayRuns.length }}</strong><button class="text-button" @click="selectedVerificationDay = ''">Clear</button></div><article v-for="run in verificationDayRuns" :key="run.run_id" class="drilldown-finding"><div><strong>{{ run.profile_id }} · {{ verificationLabel(run) }}</strong><small>{{ run.run_id }} · {{ run.created_at }}</small><small>Snapshot {{ run.snapshot_id }}</small></div><button v-if="reviews.some(review => review.snapshot_id === run.snapshot_id)" class="text-button" @click="activeTab = 'overview'; openReview(reviews.find(review => review.snapshot_id === run.snapshot_id).review_id)">Open matching review →</button></article><p v-if="!verificationDayRuns.length" class="hint">No verification runs match this date and profile.</p><small v-if="!analytics.verification_history_complete" class="hint">This drill-down is limited to the latest 500 verification runs.</small></div>
          </section>
          <section class="panel chart-panel provider-latency-panel"><div class="panel-head"><div><h3>Provider latency</h3><p>Measured adapter time across retained reviews.</p></div><span class="chart-unit">MILLISECONDS</span></div>
            <div v-if="providerLatencyBars.length" class="provider-latency-chart" role="img" aria-label="Provider adapter latency comparison showing median and 95th percentile">
              <div v-for="item in providerLatencyBars" :key="item.provider_id" class="provider-latency-row" :aria-label="`${item.provider_id}: median ${item.median_duration_ms ?? 'unavailable'} milliseconds, p95 ${item.p95_duration_ms ?? 'unavailable'} milliseconds; ${item.measured_runs} measured, ${item.unmeasured_runs} unmeasured, ${item.failed_runs} failed`">
                <div class="provider-latency-label"><strong>{{ item.provider_id }}</strong><span>p50 {{ item.median_duration_ms ?? '—' }} ms · p95 {{ item.p95_duration_ms ?? '—' }} ms</span></div>
                <div class="provider-latency-track"><i class="latency-p95" :style="{ width: item.p95_width }"></i><i class="latency-p50" :style="{ width: item.p50_width }"></i></div>
                <small>{{ item.measured_runs }} measured · {{ item.unmeasured_runs }} unmeasured · {{ item.failed_runs }} failed</small>
              </div>
            </div>
            <div v-else class="chart-empty">No provider timing data in retained reviews.</div>
            <div class="chart-legend"><span><i class="latency-p50-key"></i>p50</span><span><i class="latency-p95-key"></i>p95</span></div>
            <details class="chart-about"><summary>About this chart</summary><p class="hint">{{ analytics.provider_latency_note }}<template v-if="!analytics.provider_latency_history_complete"> Older or unreadable review records were omitted.</template></p></details>
            <div class="provider-history-head"><strong>Daily p95 history</strong><span>{{ analytics.provider_latency_reviews }} reviews inspected</span></div>
            <div v-if="providerLatencyHistoryDays.length" class="provider-history-chart" role="img" aria-label="Daily provider p95 latency over retained reviews">
              <div v-for="day in providerLatencyHistoryDays" :key="day.day" class="provider-history-day"><div class="provider-history-bars"><i v-for="item in day.providers" :key="item.provider_id" :style="{ height: `${item.height}px` }" :title="`${day.day} · ${item.provider_id}: p50 ${item.median_duration_ms} ms, p95 ${item.p95_duration_ms} ms, ${item.measured_runs} measured`"></i></div><small>{{ day.day.slice(5) }}</small></div>
            </div>
            <div v-else class="chart-empty compact">No daily latency samples in this range and provider filter.</div>
            <div class="chart-legend"><span><i class="latency-history-key"></i>p95 by day</span></div>
            <details class="chart-about"><summary>About this chart</summary><p class="hint">Daily history follows the selected date range and provider filter. Recent view shows the {{ analyticsWindow }} latest dates with measurements; custom range includes all available matching dates. History is bounded to 2,000 reviews.</p></details>
          </section>
          <section class="panel chart-panel provider-cost-panel"><div class="panel-head"><div><h3>Estimated provider cost</h3><p>Configured token rates applied to recorded usage.</p></div></div>
            <div v-if="providerCostBars.length" class="provider-latency-chart">
              <div v-for="item in providerCostBars" :key="item.provider_id" class="provider-latency-row" :aria-label="`${item.provider_id}: estimated ${item.estimated_usd == null ? 'unavailable' : item.estimated_usd.toFixed(6)} US dollars; ${item.priced_runs} priced, ${item.unpriced_runs} unpriced runs`">
                <div class="provider-latency-label"><strong>{{ item.provider_id }}</strong><span>{{ item.estimated_usd == null ? '—' : `$${item.estimated_usd.toFixed(6)}` }}</span></div><small>{{ item.priced_runs }} priced · {{ item.unpriced_runs }} unpriced</small>
              </div>
            </div><div v-else class="chart-empty">No provider token usage with a matching configured model rate.</div>
            <div class="provider-history-head"><strong>Daily estimated cost</strong><span>{{ providerCostWindow.replaceAll('_', ' ') }}</span></div>
            <div v-if="providerCostHistoryDays.length" class="provider-history-chart" role="img" aria-label="Daily estimated provider cost over retained reviews">
              <div v-for="day in providerCostHistoryDays" :key="day.day" class="provider-history-day"><div class="provider-history-bars"><i v-for="item in day.providers" :key="item.provider_id" class="cost-history-bar" :style="{ height: `${item.height}px` }" :title="`${day.day} · ${item.provider_id}: $${item.estimated_usd.toFixed(6)}, ${item.priced_runs} priced, ${item.unpriced_runs} unpriced`"></i></div><small>{{ day.day.slice(5) }}</small></div>
            </div><div v-else class="chart-empty compact">No priced usage in this range and provider filter.</div>
            <details class="chart-about"><summary>About this chart</summary><p class="hint">Totals and daily history follow the selected date range and provider filter; recent view uses the {{ analyticsWindow }} latest dates with provider usage. {{ analytics.provider_cost_note }}<template v-if="!analytics.provider_cost_history_complete"> Older or unreadable review records were omitted.</template></p></details>
          </section>
          <section class="panel chart-panel"><div class="panel-head"><div><h3>Finding severity</h3><p>Current unique findings by severity.</p></div></div>
            <div v-if="severityBars.length" class="severity-chart"><button v-for="item in severityBars" :key="item.severity" class="severity-meter severity-select" :class="{ chosen: selectedAnalyticsSeverity === item.severity }" :aria-pressed="selectedAnalyticsSeverity === item.severity" :aria-label="`Show ${item.count} ${item.severity} findings`" @click="selectedAnalyticsSeverity = selectedAnalyticsSeverity === item.severity ? '' : item.severity"><div><span>{{ item.severity }}</span><b>{{ item.count }}</b></div><div class="meter-track"><i :class="`severity-${item.severity}`" :style="{ width: item.width }"></i></div></button></div>
            <div v-else class="chart-empty">No saved findings yet.</div>
            <div v-if="selectedAnalyticsSeverity" class="analytics-drilldown" aria-live="polite"><div class="drilldown-head"><strong>{{ selectedAnalyticsSeverity }} findings · {{ analyticsSeverityFindings.length }} of {{ analytics.finding_drilldown_total }}</strong><button class="text-button" @click="selectedAnalyticsSeverity = ''">Clear</button></div><article v-for="finding in analyticsSeverityFindings" :key="finding.finding_id" class="drilldown-finding"><div><span class="severity" :class="statusTone(finding.severity)">{{ finding.severity }}</span><strong>{{ finding.category }}</strong><small>{{ finding.finding_id }} · {{ finding.status }} · {{ finding.last_seen }}</small><p>{{ finding.rationale }}</p><small>{{ finding.path || 'No location' }}<template v-if="finding.line">:{{ finding.line }}</template></small><small v-for="attribution in finding.rule_attributions" :key="`${attribution.rule_id}:${attribution.approval_id}:${attribution.reviewer_id}`">Reviewer reported rule {{ attribution.rule_id }} via approval {{ attribution.approval_id }} ({{ attribution.reviewer_id }})</small></div><button v-if="finding.last_review_id" class="text-button" :disabled="loading" @click="activeTab = 'overview'; openReview(finding.last_review_id)">Open review →</button></article><p v-if="!analyticsSeverityFindings.length" class="hint">No findings in the bounded drill-down for this severity.</p><small v-if="!analytics.finding_drilldown_complete" class="hint">Showing the latest {{ analyticsSeverityFindings.length }} findings from {{ analytics.finding_drilldown_total }} total. Counts above include all findings.</small></div>
            <div class="rule-chart"><div class="panel-head"><div><h3>Findings by approved rule</h3><p>Current unique findings with reviewer-reported attribution.</p></div></div><div v-if="ruleBars.length" class="severity-chart"><button v-for="item in ruleBars" :key="item.ruleId" class="severity-meter severity-select" :class="{ chosen: analyticsRule === item.ruleId }" :aria-pressed="analyticsRule === item.ruleId" :aria-label="`Filter by rule ${item.ruleId}: ${item.count} findings`" @click="analyticsRule = analyticsRule === item.ruleId ? '' : item.ruleId"><div><span>{{ item.ruleId }}</span><b>{{ item.count }}</b></div><div class="meter-track"><i :style="{ width: item.width }"></i></div></button></div><div v-else class="chart-empty">No findings have approved-rule attribution.</div><small class="hint">Counts cover all current unique findings. Rule links are reviewer-reported, checked against the active in-scope approval set, and do not establish causation. Rule filtering on gate trends applies to the latest 500 saved reviews.</small></div>
            <div class="feedback-box"><strong>Explicit review feedback</strong><p>{{ analytics.feedback_note }}</p><div v-if="Object.keys(analytics.explicit_feedback_by_label).length" class="feedback-labels"><span v-for="(count, label) in analytics.explicit_feedback_by_label" :key="label">{{ label.replace('_', ' ') }} <b>{{ count }}</b></span></div><small v-else>No human feedback labels recorded yet.</small></div>
          </section>
        </div>
      </section>
      <section v-else-if="activeTab === 'settings'" class="settings-view">
        <div class="section-head"><div><h2>Repository configuration</h2><p>Reviewers, providers, and policy for this checkout.</p></div><button class="primary" :disabled="saving" @click="saveConfig">{{ saving ? 'Saving…' : 'Save configuration' }}</button></div>
        <div v-if="config" class="config-facts"><div><small>PROVIDERS</small><strong>{{ config.provider_ids.join(', ') || 'None configured' }}</strong></div><div><small>REVIEWERS</small><strong>{{ config.reviewer_ids.join(', ') || 'None configured' }}</strong></div><div><small>POLICY</small><strong>{{ config.config.policy?.on_incomplete || 'block' }} on incomplete</strong></div></div>
        <textarea v-model="configText" spellcheck="false" class="config-editor" aria-label="Repository config JSON"></textarea>
        <p class="hint">Edits are validated before writing to <code>.vee.yaml</code>. Protected local policy remains enforced.</p>
      </section>

      <template v-else>
        <section class="launch-card" :class="{ running: loading }">
          <div class="launch-copy"><div class="launch-icon">⌁</div><div><strong>{{ loading ? `Reviewing ${scopeLabels[scope]}…` : 'Start a local review' }}</strong><small role="status">{{ loading ? (selected ? 'Reviewers run in parallel. The previous review stays visible until this one finishes.' : 'Reviewers run in parallel; this can take a few minutes.') : 'Capture changes and evaluate the repository policy.' }}</small><small v-if="loading" class="review-elapsed" aria-hidden="true">{{ reviewElapsed }} elapsed</small><small v-if="loading && progressSummary" class="review-progress-summary" role="status">{{ progressSummary }}</small><ul v-if="loading && reviewProgress?.reviewers?.length" class="reviewer-progress" aria-label="Reviewer progress"><li v-for="reviewer in reviewProgress.reviewers" :key="reviewer.reviewer_id" :class="reviewerState(reviewer)"><span aria-hidden="true">{{ reviewerStateIcon[reviewerState(reviewer)] }}</span> {{ reviewer.reviewer_id }}<span class="reviewer-progress-detail">{{ reviewerState(reviewer) === 'running' ? (reviewer.runs > 1 ? `running · ${reviewer.finished}/${reviewer.runs} runs` : 'running') : reviewerState(reviewer) === 'failed' ? `failed${reviewer.runs > 1 ? ` · ${reviewer.failed}/${reviewer.runs} runs` : ''}` : reviewer.cached === reviewer.runs ? 'cached' : 'done' }}</span></li></ul></div></div>
          <div class="launch-controls"><select v-model="scope" aria-label="Change scope"><option value="base">Branch changes</option><option value="staged">Staged changes</option><option value="working_tree">Working tree</option></select><input v-if="scope === 'base'" v-model="base" aria-label="Base branch" placeholder="Base ref"/><button class="primary" :class="{ quiet: selected }" :disabled="loading || initializing" @click="startReview">{{ initializing ? 'Loading…' : loading ? 'Reviewing…' : 'Run review' }} <span>→</span></button></div>
        </section>

        <template v-if="selected">
          <div v-if="!detailLoaded && !detailError" class="alert">Loading saved review details…</div>
          <div v-else-if="detailError" class="alert">Saved details could not be refreshed. Showing the last available review details; they may be out of date.</div>
          <template v-if="detailLoaded || detailError">
          <section class="summary-row">
            <div class="summary-card gate-card"><div class="card-label">GATE DECISION</div><div class="gate-line"><span class="status-pill" :class="statusTone(selected.review.status)">{{ selected.review.status }}</span><strong>{{ selected.review.status === 'pass' ? 'Policy satisfied' : selected.review.status === 'block' ? 'Action required' : 'Analysis incomplete' }}</strong></div><small :title="`${selected.review.review_id} · ${selected.review.snapshot_id}`">{{ scopeName(selected.review.change_set?.scope) }} · snapshot {{ shortHash(selected.review.snapshot_id) }}</small></div>
            <div class="summary-card"><div class="card-label">FINDINGS</div><strong class="metric">{{ findings.length }}</strong><small>reported in this review</small></div>
            <div v-if="risk" class="summary-card risk-card" aria-label="Change risk"><div class="card-label">CHANGE RISK</div><div class="gate-line"><span class="status-pill" :class="riskTone(risk.tier)">{{ risk.tier }}</span></div><small :title="riskTitle">{{ riskSummary }}</small></div><div class="summary-card"><div class="card-label">AFFECTED FILES</div><strong class="metric">{{ impactedFiles }}</strong><small>{{ impactPaths.length }} {{ impactPaths.length === 1 ? 'reference' : 'references' }} · {{ selected.impact?.coverage_complete ? 'coverage complete' : 'coverage has limitations' }}</small></div>
          </section>
          <section v-if="selected.review.unreviewed_paths?.length" class="alert" role="note" aria-label="Not reviewed"><strong>No reviewer received {{ selected.review.unreviewed_paths.length }} changed file{{ selected.review.unreviewed_paths.length === 1 ? '' : 's' }}.</strong> No reviewer's include rules matched them<template v-if="!selected.review.analysis_complete">, so the analysis is incomplete</template>. Add or widen a reviewer, or set <code>policy.on_unreviewed: allow</code>.<ul class="unreviewed-list"><li v-for="path in selected.review.unreviewed_paths" :key="path"><code>{{ path }}</code></li></ul></section>
          <p v-if="supersession" class="alert supersession-note" role="note">A later review of the same base, {{ supersession.review_id }}, exists ({{ supersession.created_at }}). {{ supersession.outdated_finding_ids.length }} of this review's findings were not reported again there and are marked Outdated. This is display only; it does not change gates or dispositions. <button class="text-button" @click="openReview(supersession.review_id)">Open later review →</button></p>
          <nav class="tabs"><button :class="{ selected: activeTab === 'overview' }" @click="activeTab = 'overview'">Overview</button><button :class="{ selected: activeTab === 'findings' }" @click="activeTab = 'findings'">Findings <span>{{ findings.length }}</span></button><button :class="{ selected: activeTab === 'impact' }" @click="activeTab = 'impact'">Impact <span :title="`${impactPaths.length} references`">{{ impactedFiles }}</span></button><button :class="{ selected: activeTab === 'reviewers' }" @click="activeTab = 'reviewers'">Reviewers <span>{{ selected.review.reviewer_outcomes?.length || 0 }}</span></button></nav>
          <section v-if="activeTab === 'overview'" class="content-grid">
            <div class="panel"><div class="panel-head"><div><h3>Findings</h3><p>Evidence-backed issues from the selected snapshot.</p></div><button class="text-button" @click="activeTab = 'findings'">View all →</button></div><div v-if="!findings.length" class="empty-state"><span>✓</span><strong>No findings reported</strong><small v-if="selected.review.analysis_complete && selected.review.reviewer_outcomes?.length">Reviewers completed without actionable findings.</small><small v-else-if="!selected.review.analysis_complete">Analysis did not complete; findings may be missing.</small><small v-else>No reviewers ran for this review.</small></div><article v-for="record in findings.slice(0, 5)" :key="record.finding.id" class="finding-row"><span class="severity" :class="statusTone(record.finding.severity)">{{ record.finding.severity }}</span><div><strong>{{ record.finding.category }}</strong><p>{{ record.finding.rationale }}</p><small>{{ record.finding.path || 'No location' }}<template v-if="record.finding.line">:{{ record.finding.line }}</template></small></div></article></div>
            <div class="panel"><div class="panel-head"><div><h3>Review details</h3><p>Snapshot-bound run information.</p></div></div><dl class="details"><dt>Snapshot</dt><dd>{{ selected.review.snapshot_id }}</dd><dt>Config digest</dt><dd>{{ selected.review.effective_config_digest }}</dd><dt>Analysis</dt><dd>{{ selected.review.analysis_complete ? 'Complete' : 'Incomplete' }}</dd><dt>Scope</dt><dd>{{ selected.review.change_set?.scope }}</dd></dl><div class="reason" v-for="reason in selected.review.reasons" :key="reason">{{ reason }}</div></div>
          </section>
          <section v-else-if="activeTab === 'findings'" class="panel full-panel"><div class="panel-head"><div><h3>Findings</h3><p>{{ findings.length }} findings · status and provenance from Vee’s saved review.</p></div></div><p v-if="findingMessage" class="hint" role="status">{{ findingMessage }}</p><div v-if="!findings.length" class="empty-state"><span>✓</span><strong>{{ selected.review.analysis_complete ? 'No findings reported' : 'Findings may be incomplete' }}</strong><small v-if="!selected.review.analysis_complete">Analysis did not complete; findings may be missing.</small><small v-else-if="selected.review.reviewer_outcomes?.length">Reviewers completed without actionable findings.</small><small v-else>No reviewers ran for this review.</small></div><article v-for="record in findings" :key="record.finding.id" class="finding-row"><span class="severity" :class="statusTone(record.finding.severity)">{{ record.finding.severity }}</span><div class="finding-content"><div><div class="finding-title"><strong>{{ findingTitle(record.finding) }}</strong><span class="provenance">{{ record.finding.category }} · {{ record.finding.provenance }}</span><span v-if="isOutdated(record)" class="provenance outdated" :title="`Not reported by ${supersession.review_id}, a later review of the same base`">Outdated</span><span v-if="record.finding.advisory" class="provenance">advisory</span><span v-if="record.finding.sample_agreement" class="provenance">{{ record.finding.sample_agreement.reported }}/{{ record.finding.sample_agreement.samples }} runs</span><button class="text-button" :aria-label="`Open details for ${record.finding.id}`" @click="openFinding(record)">Details</button></div><p v-if="String(record.finding.rationale || '').trim() !== findingTitle(record.finding)">{{ record.finding.rationale }}</p><small>{{ record.finding.path || 'No location' }}<template v-if="record.finding.line">:{{ record.finding.line }}</template> · confidence {{ record.finding.confidence ?? 'unknown' }}</small><small class="disposition-meta">Disposition: {{ record.status }}<template v-if="record.status_reason"> · {{ record.status_reason }}</template></small></div><div v-if="editingDisposition === record.finding.id" class="disposition-controls"><select :aria-label="`Disposition for ${record.finding.id}`" :value="dispositionDrafts[record.finding.id]?.status || record.status" @change="dispositionDrafts[record.finding.id] = { ...dispositionDrafts[record.finding.id], status: $event.target.value, reason: dispositionDrafts[record.finding.id]?.reason || '' }"><option value="open">Open</option><option value="verified">Verified</option><option value="refuted">Refuted</option><option value="resolved">Resolved</option></select><input :aria-label="`Reason for ${record.finding.id}`" :value="dispositionDrafts[record.finding.id]?.reason || ''" placeholder="Reason required" @input="dispositionDrafts[record.finding.id] = { ...dispositionDrafts[record.finding.id], status: dispositionDrafts[record.finding.id]?.status || record.status, reason: $event.target.value }"/><button class="text-button" :disabled="savingFinding === record.finding.id" @click="updateFindingStatus(record)">{{ savingFinding === record.finding.id ? 'Saving…' : 'Save disposition' }}</button><button class="text-button" :disabled="savingFinding === record.finding.id" @click="closeDisposition(record.finding.id)">Cancel</button></div><div v-else class="disposition-controls"><button class="text-button" :aria-label="`Set disposition for ${record.finding.id}`" @click="openDisposition(record.finding.id)">Set disposition</button></div></div></article><p class="hint">Disposition records are audit metadata and do not waive gate findings. Use the scoped waiver workflow for policy exceptions.</p></section>
          <section v-else-if="activeTab === 'impact'" class="panel full-panel"><div class="panel-head"><div><h3>Change impact</h3><p>Relationships include evidence and certainty labels; this is not a complete call graph.</p></div><span class="coverage" :class="selected.impact?.coverage_complete ? 'good' : 'warn'">{{ selected.impact?.coverage_complete ? 'COVERAGE COMPLETE' : 'LIMITED COVERAGE' }}</span></div><div v-if="!impactPaths.length" class="empty-state"><strong>No impact paths found</strong><small>Changed symbols: {{ selected.impact?.changed_symbols?.join(', ') || 'none identified' }}</small></div><article v-for="(path, index) in impactPaths" :key="index" class="impact-row"><span class="impact-index">{{ String(index + 1).padStart(2, '0') }}</span><div><strong>{{ path.affected_path }} <span class="arrow">→</span> {{ path.source_path }}</strong><small v-if="path.co_change">changed together in {{ path.co_change.together }} of {{ path.co_change.source_commits }} commits · {{ path.relationship }} · {{ path.certainty }}</small><small v-else>{{ path.symbol }} · {{ path.relationship }} · {{ path.certainty }} · line {{ path.evidence_line }}</small></div></article><div v-for="limitation in selected.impact?.limitations" :key="limitation" class="reason">{{ limitation }}</div></section>
          <section v-else class="panel full-panel"><div class="panel-head"><div><h3>Reviewer outcomes</h3><p>Each required reviewer must complete for the gate to pass.</p></div></div><article v-for="outcome in selected.review.reviewer_outcomes" :key="outcome.reviewer_id" class="reviewer-row"><span class="reviewer-avatar">{{ outcome.reviewer_id.slice(0, 1).toUpperCase() }}</span><div><strong>{{ outcome.reviewer_id }}</strong><small>{{ outcome.provider_id }} · {{ outcome.provider_kind }}<template v-if="outcome.provider_version"> · {{ outcome.provider_version }}</template></small></div><span class="status-pill" :class="statusTone(outcome.status)">{{ outcome.status }}</span></article><div v-if="!selected.review.reviewer_outcomes?.length" class="empty-state"><strong>No reviewers ran</strong></div></section>
          </template>
        </template>
        <div v-else-if="detailError" class="alert">The selected review could not be loaded. Its gate result is unavailable.</div>
        <section v-else class="welcome"><div class="welcome-art">V</div><h2>Make the change understandable.</h2><p>Run a review to inspect findings, evidence, reviewer outcomes, and likely impact paths for this checkout.</p></section>
      </template>
    </main>
    <aside v-if="drawerRecord" class="finding-drawer" role="dialog" aria-modal="false" aria-label="Finding details" @keydown.esc="closeFinding">
      <div class="drawer-head">
        <div>
          <span class="severity" :class="statusTone(drawerRecord.finding.severity)">{{ drawerRecord.finding.severity }}</span>
          <h3>{{ findingTitle(drawerRecord.finding) }}</h3>
          <small>{{ drawerRecord.finding.category }} · {{ drawerRecord.status }} · confidence {{ drawerRecord.finding.confidence ?? 'unknown' }} · {{ drawerRecord.finding.id }}</small>
        </div>
        <button ref="drawerCloseButton" class="text-button" aria-label="Close finding details" @click="closeFinding">✕</button>
      </div>
      <p v-if="String(drawerRecord.finding.rationale || '').trim() !== findingTitle(drawerRecord.finding)" class="drawer-rationale">{{ drawerRecord.finding.rationale }}</p>
      <p v-if="drawerError" class="alert">{{ drawerError }}</p>
      <p v-else-if="!drawerView" class="hint">Loading snapshot context…</p>
      <template v-else>
        <p v-if="!drawerView.task.snapshot_current" class="alert">This snapshot no longer matches the working tree.<template v-if="drawerView.task.source_context"> The source below is the reviewed snapshot, not the current file.</template><template v-else> The reviewed source is no longer available.</template></p>
        <section class="drawer-section">
          <h4>Code reference</h4>
          <small>{{ drawerRecord.finding.path || 'No location' }}<template v-if="drawerRecord.finding.line">:{{ drawerRecord.finding.line }}</template><template v-else-if="drawerRecord.finding.path"> · no line given; showing the start of the file</template></small>
          <pre v-if="drawerSourceLines.length" class="source-excerpt"><code><span v-for="line in drawerSourceLines" :key="line.number" class="source-line" :class="{ flagged: line.flagged }"><span class="line-number">{{ line.number }}</span>{{ line.text }}
</span></code></pre>
          <small v-if="drawerView.task.context_note" class="hint">{{ drawerView.task.context_note }}</small>
        </section>
        <section class="drawer-section">
          <h4>Evidence</h4>
          <p class="hint">Model findings are inferences from the reviewed source; evidence below records where Vee anchored them and how each item was obtained.</p>
          <article v-for="item in drawerView.task.evidence" :key="item.id" class="evidence-item">
            <strong>{{ item.source_path }}<template v-if="item.start_line">:{{ item.start_line }}<template v-if="item.end_line && item.end_line !== item.start_line">–{{ item.end_line }}</template></template><template v-else> · whole file</template></strong>
            <small>{{ item.classification }} · {{ item.provenance }} · {{ item.verification }}</small>
          </article>
          <p v-if="!drawerView.task.evidence.length" class="hint">No evidence records are attached to this finding.</p>
        </section>
        <section class="drawer-section">
          <h4>Verification runs</h4>
          <article v-for="run in drawerView.verification_runs" :key="run.run_id" class="evidence-item">
            <strong>{{ run.profile_id }} · {{ String(run.status).replace('_', ' ') }}</strong>
            <small>{{ run.run_id }} · snapshot {{ run.snapshot_id }}</small>
          </article>
          <p v-if="!drawerView.verification_runs.length" class="hint">No trusted verification has run against this finding.</p>
        </section>
        <section class="drawer-section">
          <h4>Hand off</h4>
          <p class="hint">The work package is bound to snapshot {{ drawerView.task.snapshot_id }}; an agent can check it is still current before editing.</p>
          <button class="primary" @click="copyWorkPackage">Copy work package</button>
          <p v-if="drawerMessage" class="hint" role="status">{{ drawerMessage }}</p>
        </section>
      </template>
    </aside>
  </div>
</template>
