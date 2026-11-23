import { test, expect } from '@playwright/test'
import { readFile } from 'node:fs/promises'

// Saved views sit behind a disclosure that starts open only when views exist.
async function openSavedViews(page) {
  const toggle = page.locator('details.saved-views-toggle')
  if (!(await toggle.evaluate(element => element.open))) await toggle.locator('summary').click()
}

const latest = {
  review_id: 'rev_latest', snapshot_id: 'sha256:latest', status: 'block',
  created_at: '2026-11-14 09:00:00',
}
const prior = {
  review_id: 'rev_prior', snapshot_id: 'sha256:prior', status: 'pass',
  created_at: '2026-11-13 12:00:00',
}
const findingRecord = {
  finding: {
    id: 'FIND-001', fingerprint: 'sha256:finding', category: 'correctness',
    severity: 'high', confidence: 92, rationale: 'The changed branch skips validation.',
    path: 'src/lib.rs', line: 42, provenance: 'model_inference',
  },
  status: 'open', occurrences: [],
}
const detail = (summary = latest) => ({
  review: {
    ...summary, schema_version: 2, analysis_complete: true,
    effective_config_digest: 'sha256:config',
    change_set: { scope: 'base_and_worktree', files: [] },
    findings: [findingRecord.finding],
    reviewer_outcomes: [
      { reviewer_id: 'correctness', provider_id: 'codex', provider_kind: 'codex_cli', provider_version: 'codex-cli 1.2.3', status: 'completed' },
      { reviewer_id: 'security', provider_id: 'claude', provider_kind: 'claude_cli', provider_version: 'claude 2.0', status: 'completed' },
    ],
    reasons: [],
  },
  findings: [findingRecord],
  impact: {
    schema_version: 4, snapshot_id: summary.snapshot_id, coverage_complete: false,
    changed_paths: ['src/lib.rs'], changed_symbols: ['validate'],
    paths: [
      { affected_path: 'src/handler.rs', source_path: 'src/lib.rs', symbol: 'validate', relationship: 'resolved_symbol_reference', certainty: 'resolved_semantic', evidence_line: 18 },
      { affected_path: 'schemas/api.json', source_path: 'src/lib.rs', symbol: '', relationship: 'co_change', certainty: 'historical', evidence_line: 0, co_change: { together: 4, source_commits: 6 } },
    ],
    limitations: ['Dynamic dispatch is not modeled.'],
  },
})
const config = {
  version: 1,
  providers: { codex: { kind: 'codex_cli', executable: 'codex' } },
  reviewers: { correctness: { provider: 'codex', instructions_file: '.vee/reviewers/correctness.md' } },
  policy: { required_reviewers: ['correctness'], block_severities: ['high'], on_incomplete: 'block' },
}

const findingTask = {
  schema_version: 1,
  task: {
    schema_version: 2, task_id: 'task_find001', review_id: 'rev_latest', snapshot_id: 'sha256:latest',
    snapshot_current: false, finding: findingRecord,
    source_context: { path: 'src/lib.rs', start_line: 40, end_line: 44, classification: 'untrusted_repository_source',
      // The backend numbers each line itself: `{n:>6} | {text}\n` (finding_task.rs).
      content: '    40 | fn handle(input: &str) {\n    41 |     if input.is_empty() {\n    42 |         return process(input);\n    43 |     }\n    44 | }\n' },
    context_note: null, impact_paths: [], impact_coverage_complete: true,
    evidence: [{ id: 'ev_1', kind: 'source', classification: 'observed', provenance: 'source_snapshot', source_path: 'src/lib.rs', start_line: 42, end_line: 42, verification: 'unverified', content_digest: 'sha256:abc' }],
    applicable_standards: [], standards_note: null, ownership: null, ownership_note: null,
    instructions: 'Fix the finding against the exact snapshot.',
  },
  verification_runs: [{ run_id: 'verify_2', profile_id: 'unit', status: 'failed', snapshot_id: 'sha256:latest', created_at: '2026-11-14 13:00:00' }],
}

// Lets a test adjust the mocked analytics response before the page loads it.
let patchAnalytics = body => body

test.beforeEach(async ({ page }) => {
  patchAnalytics = body => body
  let latestSummary = latest
  let latestDetail = detail(latest)
  await page.route('**/api/**', async route => {
    const request = route.request()
    const url = new URL(request.url())
    const method = request.method()
    let body
    if (url.pathname === '/api/health') body = { status: 'ok', repository: '/repo' }
    else if (url.pathname === '/api/analytics') body = {
      schema_version: 9,
      review_count: 2,
      history_complete: true,
      dimensions_complete: true,
      reviews_by_day: [
        { day: '2026-11-13', pass: 1, block: 0, incomplete: 0, ungated: 0 },
        { day: '2026-11-14', pass: 0, block: 1, incomplete: 0, ungated: 0 },
      ],
      review_dimensions: [
        { review_id: 'rev_prior', day: '2026-11-13', status: 'block', summary_status: 'pass', reviewer_ids: ['correctness'], provider_ids: ['codex'], finding_categories: [], finding_rule_ids: [], next_action: { kind: 'rerun_reviewers', summary: 'Rerun reviewers: correctness (failed).' } },
        { review_id: 'rev_latest', day: '2026-11-14', status: 'block', reviewer_ids: ['security'], provider_ids: ['claude'], finding_categories: ['correctness'], finding_rule_ids: ['RULE-001'], next_action: { kind: 'fix_findings', summary: 'Fix 1 blocking finding.' } },
      ],
      findings_by_severity: { high: 1, medium: 2 },
      findings_by_rule: { 'RULE-001': 1 },
      findings_by_rule_complete: true,
      finding_drilldown_total: 1,
      finding_drilldown_complete: true,
      finding_drilldown: [{ finding_id: 'FIND-001', category: 'correctness', severity: 'high', rationale: 'The changed branch skips validation.', path: 'src/lib.rs', line: 42, status: 'open', last_review_id: 'rev_latest', last_seen: '2026-11-14 09:00:00', rule_attributions: [{ rule_id: 'RULE-001', approval_id: 'approval-1', reviewer_id: 'security' }] }],
      explicit_feedback_by_label: { confirmed: 1 },
      feedback_note: 'Counts reflect explicit human labels only; they are not calibrated acceptance or accuracy rates.',
      verification_run_count: 3,
      verification_history_complete: true,
      provider_latency: [{ provider_id: 'codex', measured_runs: 2, unmeasured_runs: 1, failed_runs: 0, median_duration_ms: 240, p95_duration_ms: 610 }, { provider_id: 'claude', measured_runs: 1, unmeasured_runs: 0, failed_runs: 1, median_duration_ms: 890, p95_duration_ms: 890 }],
      provider_latency_history_complete: true,
      provider_latency_note: 'Measured adapter duration over retained reviews.',
      provider_latency_reviews: 2,
      provider_costs: [{ provider_id: 'codex', estimated_usd: 0.0045, priced_runs: 2, unpriced_runs: 1 }, { provider_id: 'claude', estimated_usd: null, priced_runs: 0, unpriced_runs: 1 }],
      provider_cost_history_complete: true,
      provider_cost_note: 'Estimates apply currently configured rates to retained token usage.',
      provider_cost_reviews: 2,
      provider_cost_history: [{ day: '2026-11-14', provider_id: 'codex', estimated_usd: 0.0045, priced_runs: 2, unpriced_runs: 1 }],
      provider_latency_history: [
        { day: '2026-11-14', provider_id: 'zero-duration', measured_runs: 1, median_duration_ms: 0, p95_duration_ms: 0 },
        { day: '2026-11-13', provider_id: 'codex', measured_runs: 1, median_duration_ms: 200, p95_duration_ms: 200 },
        { day: '2026-11-14', provider_id: 'codex', measured_runs: 1, median_duration_ms: 610, p95_duration_ms: 610 },
        { day: '2026-11-14', provider_id: 'claude', measured_runs: 1, median_duration_ms: 890, p95_duration_ms: 890 },
      ],
      verification_runs: [
        { run_id: 'verify_1', snapshot_id: 'sha256:prior', profile_id: 'unit', status: 'passed', created_at: '2026-11-13 13:00:00' },
        { run_id: 'verify_2', snapshot_id: 'sha256:latest', profile_id: 'unit', status: 'failed', created_at: '2026-11-14 13:00:00' },
        { run_id: 'verify_3', snapshot_id: 'sha256:latest', profile_id: 'integration', status: 'timed_out', created_at: '2026-11-14 14:00:00' },
      ],
    }
    else if (url.pathname === '/api/config' && method === 'GET') body = { config, provider_ids: ['codex'], reviewer_ids: ['correctness'] }
    else if (url.pathname === '/api/config' && method === 'PUT') {
      const submitted = request.postDataJSON().config
      body = { config: submitted, provider_ids: Object.keys(submitted.providers || {}), reviewer_ids: Object.keys(submitted.reviewers || {}) }
    }
    else if (url.pathname === '/api/reviews' && method === 'GET') body = [latestSummary, prior]
    else if (url.pathname === '/api/reviews' && method === 'POST') {
      latestSummary = { review_id: 'rev_started', snapshot_id: 'sha256:new', status: 'pass', created_at: '2026-11-14 09:05:00' }
      latestDetail = detail(latestSummary)
      body = latestDetail.review
    }
    else if (url.pathname === '/api/findings/FIND-001/status' && method === 'POST') {
      const update = request.postDataJSON()
      latestDetail.findings = [{ ...latestDetail.findings[0], status: update.status, status_reason: update.reason }]
      body = { schema_version: 1, finding_id: 'FIND-001', ...update, note: 'Lifecycle status is audit metadata. Use the waiver workflow for a scoped gate exception.' }
    }
    else if (url.pathname === '/api/reviews/progress') body = { schema_version: 1, reviews: [] }
    else if (url.pathname === '/api/findings/FIND-001/task') body = findingTask
    else if (url.pathname === '/api/reviews/rev_latest') body = latestDetail
    else if (url.pathname === '/api/reviews/rev_prior') body = { ...detail(prior), superseded_by: { review_id: 'rev_latest', created_at: '2026-11-14 09:00:00', outdated_finding_ids: ['FIND-001'] } }
    else if (url.pathname === '/api/reviews/rev_started') body = latestDetail
    else body = { error: `Unexpected API path ${url.pathname}` }
    if (url.pathname === '/api/analytics') body = patchAnalytics(body)
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })
  })
})

test('insights view renders local review trends and labels feedback counts', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: /Insights/ }).click()
  await expect(page.getByRole('heading', { name: 'Review insights' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Gate outcomes over time' })).toBeVisible()
  await expect(page.getByRole('img', { name: 'Stacked bar chart of daily gate outcomes' })).toBeVisible()
  await page.getByLabel('Recent date count').selectOption('7')
  // Explanations start collapsed so the charts lead.
  const about = page.locator('.chart-about').first()
  await expect(about.getByText(/Chart shows the 7 latest dates/)).toBeHidden()
  await about.getByText('About this chart').click()
  await expect(about.getByText(/Chart shows the 7 latest dates/)).toBeVisible()
  await expect(page.getByText('confirmed')).toBeVisible()
  await expect(page.getByText(/not calibrated acceptance or accuracy rates/)).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Findings by approved rule' })).toBeVisible()
  await expect(page.getByRole('button', { name: /Filter by rule RULE-001: 1 findings/ })).toBeVisible()
  await page.getByRole('button', { name: /Show 1 high findings/ }).click()
  await expect(page.getByText(/Reviewer reported rule RULE-001 via approval approval-1/)).toBeVisible()
})

test('saved review details and retry remain available when analytics fails', async ({ page }) => {
  await page.route('**/api/analytics', route => route.fulfill({
    status: 503,
    contentType: 'application/json',
    body: JSON.stringify({ error: 'Analytics unavailable' }),
  }))
  await page.goto('/')
  await page.getByRole('button', { name: /rev_latest/ }).click()
  await expect(page.getByRole('button', { name: /Findings/ })).toBeVisible()
  await page.getByRole('button', { name: /Findings/ }).click()
  await expect(page.getByRole('heading', { name: 'Findings' })).toBeVisible()
  await expect(page.getByText('The changed branch skips validation.')).toBeVisible()
  await page.getByRole('button', { name: /Insights/ }).click()
  await expect(page.getByRole('alert')).toContainText('Analytics could not be refreshed')
  await expect(page.getByRole('button', { name: /Try again/ })).toBeVisible()
  await page.getByRole('button', { name: /Review queue/ }).click()
  await expect(page.getByRole('alert')).toContainText('Gate labels below are unavailable')
  await expect(page.locator('.queue-card .status-pill').first()).toHaveText('status unavailable')
})

test('initial saved review opens without waiting for analytics', async ({ page }) => {
  await page.route('**/api/analytics', async route => {
    await new Promise(resolve => setTimeout(resolve, 5000))
    await route.continue()
  })
  await page.goto('/')
  const savedReview = page.getByRole('button', { name: /rev_latest/ })
  await expect(savedReview).toBeVisible({ timeout: 3000 })
  await savedReview.click()
  await page.getByRole('button', { name: /Findings/ }).click()
  await expect(page.getByText('The changed branch skips validation.')).toBeVisible({ timeout: 3000 })
})

test('an analyzer run with no findings on changed lines charts as passed, as the gate treats it', async ({ page }) => {
  patchAnalytics = body => ({
    ...body,
    verification_runs: body.verification_runs.map(run =>
      run.run_id === 'verify_2' ? { ...run, profile_id: 'nox', analyzer_findings_on_changed_lines: 0 } : run),
  })
  await page.goto('/')
  await page.getByRole('button', { name: /Insights/ }).click()
  await page.getByLabel('Filter verification profile').selectOption('nox')
  await page.getByRole('button', { name: /Show verification runs for 2026-11-14: 1 passed, 0 failed, 0 timed out/ }).click()
  await expect(page.locator('.analytics-drilldown')).toContainText('nox · clean on changed lines')
})

test('verification chart filters by profile and date and drills into snapshot context', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: /Insights/ }).click()
  await expect(page.getByRole('heading', { name: 'Verification outcomes' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Provider latency' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Estimated provider cost' })).toBeVisible()
  await expect(page.locator('.provider-cost-panel')).toContainText('$0.004500')
  await expect(page.locator('.provider-cost-panel')).toContainText('1 unpriced')
  await expect(page.getByRole('img', { name: /Provider adapter latency comparison/ })).toBeVisible()
  await expect(page.locator('.provider-latency-panel .provider-latency-row')).toHaveCount(2)
  await expect(page.locator('.provider-latency-panel')).toContainText('p95 890 ms')
  await expect(page.getByRole('img', { name: 'Stacked bar chart of daily verification outcomes' })).toBeVisible()
  await page.getByLabel('Filter verification profile').selectOption('unit')
  await page.getByLabel('Chart date range').selectOption('custom')
  await page.getByLabel('Start date').fill('2026-11-14')
  await page.getByLabel('End date').fill('2026-11-14')
  await expect(page.getByRole('button', { name: /Show verification runs for 2026-11-14: 0 passed, 1 failed, 0 timed out/ })).toBeVisible()
  await page.getByRole('button', { name: /Show verification runs for 2026-11-14/ }).click()
  await expect(page.getByText(/verify_2 · 2026-11-14/)).toBeVisible()
  await expect(page.getByRole('button', { name: 'Open matching review →' })).toBeVisible()
  const downloadEvent = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Export JSON' }).click()
  const download = await downloadEvent
  const report = JSON.parse(await readFile(await download.path(), 'utf8'))
  expect(report.source_schema_version).toBe(9)
  expect(report.verification_run_count).toBe(3)
  expect(report.verification_history_complete).toBe(true)
  expect(report.verification_filter.profile_id).toBe('unit')
  expect(report.metrics).toContainEqual({ metric: 'verification_runs', period: '2026-11-14', label: 'failed', count: 1 })
  expect(report.metrics.some(metric => metric.metric === 'verification_runs' && metric.period === '2026-11-13')).toBe(false)
  expect(report.verification_note).toContain('not a success rate')
  expect(report.provider_latency).toHaveLength(2)
  expect(report.provider_costs).toHaveLength(1)
  expect(report.provider_cost_history).toHaveLength(1)
  expect(report.provider_cost_window).toBe('custom_date_range')
  expect(report.provider_costs[0]).toMatchObject({ provider_id: 'codex', estimated_usd: 0.0045, priced_runs: 2, unpriced_runs: 1 })
  expect(report.metrics).toContainEqual({ metric: 'provider_estimated_cost_usd', period: 'custom_date_range', label: 'codex:estimated_total', count: 0.0045 })
  expect(report.metrics).toContainEqual({ metric: 'provider_estimated_cost_daily_usd', period: '2026-11-14', label: 'codex', count: 0.0045 })
  expect(report.provider_latency_reviews).toBe(2)
  expect(report.provider_latency_history).toHaveLength(3)
  expect(report.provider_latency_history.every(item => item.day === '2026-11-14')).toBe(true)
  expect(report.metrics).toContainEqual({ metric: 'provider_latency_daily_ms', period: '2026-11-14', label: 'zero-duration:p95', count: 0 })
  expect(report.metrics).toContainEqual({ metric: 'provider_latency_ms', period: 'latest_2000_reviews', label: 'codex:p95', count: 610 })
  expect(report.metrics).toContainEqual({ metric: 'provider_latency_daily_ms', period: '2026-11-14', label: 'claude:p95', count: 890 })
  const csvDownloadEvent = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Export CSV' }).click()
  const csvDownload = await csvDownloadEvent
  const csv = await readFile(await csvDownload.path(), 'utf8')
  expect(csv).toContain('"verification_runs","2026-11-14","failed","1","filtered_verification_trend","","","","","unit","2026-11-14","2026-11-14"')
})

test('analytics filters gate trends by reviewer, provider, and finding category', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: /Insights/ }).click()
  await page.getByLabel('Filter by reviewer').selectOption('security')
  await page.getByLabel('Filter by provider').selectOption('claude')
  await page.getByLabel('Filter by finding category').selectOption('correctness')
  await page.getByLabel('Filter verification profile').selectOption('unit')
  await page.getByLabel('Filter verification profile').selectOption('unit')
  await page.getByLabel('Filter verification profile').selectOption('unit')
  await expect(page.locator('.analytics-kpis .summary-card').first()).toContainText('1')
  await expect(page.getByText('Reviews on 2026-11-13')).toHaveCount(0)
  await page.getByRole('button', { name: /Show reviews for 2026-11-14/ }).click()
  const drilldown = page.locator('.analytics-drilldown')
  await expect(drilldown.getByRole('button', { name: /rev_latest/ })).toBeVisible()
  await page.getByRole('button', { name: 'Clear filters' }).click()
  await expect(page.getByRole('button', { name: /Show reviews for 2026-11-13/ })).toBeVisible()
})

test('approved rule filter narrows review trends and is retained in exports', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: /Insights/ }).click()
  await page.getByLabel('Filter by approved rule').selectOption('RULE-001')
  await expect(page.locator('.analytics-kpis .summary-card').first()).toContainText('1')
  await expect(page.getByRole('button', { name: /Show reviews for 2026-11-13/ })).toHaveCount(0)
  await expect(page.getByRole('button', { name: /Show reviews for 2026-11-14/ })).toBeVisible()

  const downloadEvent = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Export JSON' }).click()
  const download = await downloadEvent
  const report = JSON.parse(await readFile(await download.path(), 'utf8'))
  expect(report.filters.rule_id).toBe('RULE-001')
  expect(report.metrics).toContainEqual({ metric: 'current_findings_by_rule', period: '', label: 'RULE-001', count: 1 })
})

test('saved Insights views restore filters and date range across reloads', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: /Insights/ }).click()
  await page.getByLabel('Filter by reviewer').selectOption('security')
  await page.getByLabel('Filter by provider').selectOption('claude')
  await page.getByLabel('Filter by finding category').selectOption('correctness')
  await page.getByLabel('Filter verification profile').selectOption('unit')
  await page.getByLabel('Chart date range').selectOption('custom')
  await page.getByLabel('Start date').fill('2026-11-14')
  await page.getByLabel('End date').fill('2026-11-14')
  await openSavedViews(page)
  await page.getByLabel('New Insights view name').fill('Security on latest day')
  await page.getByRole('button', { name: 'Save view' }).click()
  await expect(page.getByRole('status')).toHaveText('Saved “Security on latest day”.')

  await page.getByLabel('Filter by reviewer').selectOption('')
  await page.getByLabel('Filter by provider').selectOption('')
  await page.getByLabel('Filter by finding category').selectOption('')
  await page.getByLabel('Filter verification profile').selectOption('')
  await page.getByLabel('Chart date range').selectOption('recent')
  await page.getByLabel('Choose saved Insights view').selectOption({ label: 'Security on latest day' })
  await page.getByRole('button', { name: 'Load view' }).click()
  await expect(page.getByLabel('Filter by reviewer')).toHaveValue('security')
  await expect(page.getByLabel('Filter by provider')).toHaveValue('claude')
  await expect(page.getByLabel('Filter by finding category')).toHaveValue('correctness')
  await expect(page.getByLabel('Filter verification profile')).toHaveValue('unit')
  await expect(page.getByLabel('Chart date range')).toHaveValue('custom')
  await expect(page.getByLabel('Start date')).toHaveValue('2026-11-14')
  await expect(page.locator('.analytics-kpis .summary-card').first()).toContainText('1')

  await page.reload()
  await page.getByRole('button', { name: /Insights/ }).click()
  await expect(page.getByLabel('Choose saved Insights view')).toContainText('Security on latest day')
  await page.getByLabel('Choose saved Insights view').selectOption({ label: 'Security on latest day' })
  await page.getByRole('button', { name: 'Load view' }).click()
  await expect(page.getByLabel('Filter by reviewer')).toHaveValue('security')
  await expect(page.getByLabel('Filter verification profile')).toHaveValue('unit')
  await page.getByRole('button', { name: 'Delete view' }).click()
  await expect(page.getByLabel('Choose saved Insights view')).not.toContainText('Security on latest day')
})

test('analytics export preserves the visible trend window and explicit count denominators', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: /Insights/ }).click()
  await page.getByLabel('Recent date count').selectOption('7')
  const downloadEvent = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Export JSON' }).click()
  const download = await downloadEvent
  expect(download.suggestedFilename()).toBe('vee-local-analytics.json')
  const path = await download.path()
  const report = JSON.parse(await readFile(path, 'utf8'))
  expect(report).toMatchObject({
    schema_version: 1,
    source_schema_version: 9,
    scope: 'repository_local',
    gate_trend_window: 'latest_2_dates_with_saved_reviews',
    history_complete: true,
    filters: { reviewer_id: null, provider_id: null, finding_category: null, rule_id: null, verification_profile_id: null },
    gate_trend_review_count: 2,
  })
  expect(report.metrics).toContainEqual({ metric: 'review_gate_outcomes', period: '2026-11-13', label: 'block', count: 1 })
  expect(report.metrics).toContainEqual({ metric: 'review_gate_outcomes', period: '2026-11-14', label: 'block', count: 1 })
  expect(report.metrics).toContainEqual({ metric: 'explicit_human_feedback', period: '', label: 'confirmed', count: 1 })
  expect(report.feedback_note).toContain('not calibrated')

  const csvDownloadEvent = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Export CSV' }).click()
  const csvDownload = await csvDownloadEvent
  expect(csvDownload.suggestedFilename()).toBe('vee-local-analytics.csv')
  const csvPath = await csvDownload.path()
  const csv = await readFile(csvPath, 'utf8')
  expect(csv).toContain('metric,period,label,count,metric_scope,reviewer_filter,provider_filter,category_filter,rule_filter,verification_profile_filter,date_from,date_to')
  expect(csv).toContain('"review_gate_outcomes","2026-11-13","pass","0","filtered_gate_trend","","","",""')
  expect(csv).toContain('"review_gate_outcomes","2026-11-13","block","1","filtered_gate_trend","","","",""')
  expect(csv).toContain('"review_gate_outcomes","2026-11-14","block","1","filtered_gate_trend","","","",""')
  expect(csv).toContain('"verification_runs","2026-11-13","passed","1","filtered_verification_trend","","","",""')
  expect(csv).toContain('"explicit_human_feedback","","confirmed","1","repository_current_state","","","",""')
})

test('analytics CSV export neutralizes spreadsheet formulas in filter text', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: /Insights/ }).click()
  await page.getByLabel('Filter by finding category').selectOption('correctness')
  const downloadEvent = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Export CSV' }).click()
  const download = await downloadEvent
  const csv = await readFile(await download.path(), 'utf8')
  expect(csv).toContain('"correctness"')
})

test('custom analytics date range filters the chart, drill-down, and exports', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: /Insights/ }).click()
  await page.getByLabel('Chart date range').selectOption('custom')
  await page.getByLabel('Start date').fill('2026-11-14')
  await page.getByLabel('End date').fill('2026-11-14')
  await expect(page.getByRole('button', { name: /Show reviews for 2026-11-14/ })).toBeVisible()
  await expect(page.getByRole('button', { name: /Show reviews for 2026-11-13/ })).toHaveCount(0)
  await expect(page.locator('.analytics-kpis .summary-card').first()).toContainText('1')
  await page.getByRole('button', { name: /Show reviews for 2026-11-14/ }).click()
  await expect(page.locator('.analytics-drilldown').getByRole('button', { name: /rev_latest/ })).toBeVisible()

  const downloadEvent = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Export JSON' }).click()
  const download = await downloadEvent
  const report = JSON.parse(await readFile(await download.path(), 'utf8'))
  expect(report).toMatchObject({
    gate_trend_window: 'custom_date_range',
    date_from: '2026-11-14',
    date_to: '2026-11-14',
    gate_trend_review_count: 1,
  })
  expect(report.metrics).toContainEqual({ metric: 'review_gate_outcomes', period: '2026-11-14', label: 'block', count: 1 })
  expect(report.metrics.some(metric => metric.period === '2026-11-13')).toBe(false)

  await page.getByLabel('Start date').fill('2026-11-13')
  await page.getByLabel('End date').fill('2026-11-13')
  await expect(page.locator('.analytics-drilldown .drilldown-review')).toHaveCount(0)
  await expect(page.locator('.analytics-drilldown')).not.toContainText('rev_latest')
  await page.getByLabel('Start date').fill('2026-11-15')
  await expect(page.getByRole('alert')).toHaveText('Start date must be on or before end date.')
  await expect(page.getByRole('button', { name: /Show reviews for 2026-11-14/ })).toHaveCount(0)
})

test('recent date window limits the filtered review KPI to visible chart dates', async ({ page }) => {
  const days = Array.from({ length: 8 }, (_, index) => `2026-11-${String(index + 1).padStart(2, '0')}`)
  const dimensions = [
    ...Array.from({ length: 11 }, (_, index) => ({ review_id: `rev_old_${index}`, day: days[0], status: 'pass' })),
    ...days.slice(1).map((day, index) => ({ review_id: `rev_recent_${index}`, day, status: 'pass' })),
  ].map(item => ({ ...item, reviewer_ids: [], provider_ids: [], finding_categories: [], finding_rule_ids: [] }))
  await page.route('**/api/analytics', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      schema_version: 6,
      review_count: dimensions.length,
      history_complete: true,
      dimensions_complete: true,
      reviews_by_day: days.map((day, index) => ({ day, pass: index === 0 ? 11 : 1, block: 0, incomplete: 0, ungated: 0 })),
      review_dimensions: dimensions,
      findings_by_severity: {},
      findings_by_rule: {},
      findings_by_rule_complete: true,
      finding_drilldown: [],
      finding_drilldown_total: 0,
      finding_drilldown_complete: true,
      explicit_feedback_by_label: {},
      feedback_note: 'Fixture feedback note.',
      verification_run_count: 0,
      verification_history_complete: true,
      verification_runs: [],
    }),
  }))
  await page.goto('/')
  await page.getByRole('button', { name: /Insights/ }).click()
  await page.getByLabel('Recent date count').selectOption('7')
  const filteredReviews = page.locator('.analytics-kpis .summary-card').first()
  await expect(filteredReviews.locator('.metric')).toHaveText('7')
  await page.getByLabel('Recent date count').selectOption('14')
  await expect(filteredReviews.locator('.metric')).toHaveText('18')
})

test('gate chart drills into saved reviews for the selected day', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: /Insights/ }).click()
  await page.getByRole('button', { name: /Show reviews for 2026-11-13/ }).click()
  await expect(page.getByText('Reviews on 2026-11-13')).toBeVisible()
  const drilldown = page.locator('.analytics-drilldown')
  await expect(drilldown.getByRole('button', { name: /rev_prior/ })).toBeVisible()
  await drilldown.getByRole('button', { name: /rev_prior/ }).click()
  await expect(page.getByText('Policy satisfied')).toBeVisible()
  await expect(page.getByText('sha256:prior', { exact: true })).toBeVisible()
})

test('severity chart drills into findings and opens their latest review', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: /Insights/ }).click()
  await page.getByRole('button', { name: 'Show 1 high findings' }).click()
  const drilldown = page.locator('.analytics-drilldown')
  await expect(drilldown.getByText('The changed branch skips validation.')).toBeVisible()
  await expect(drilldown.getByText('src/lib.rs:42')).toBeVisible()
  await drilldown.getByRole('button', { name: 'Open review →' }).click()
  await expect(page.getByText('Action required')).toBeVisible()
  await expect(page.getByText('sha256:latest', { exact: true })).toBeVisible()
})

test('history selection opens a saved review and its gate details', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: /Insights/ }).click()
  await expect(page.locator('.analytics-view')).toBeVisible()
  await page.getByRole('button', { name: /rev_prior/ }).click()
  await expect(page.locator('.analytics-view')).toHaveCount(0)
  await expect(page.getByText('Policy satisfied')).toBeVisible()
  await expect(page.getByText('sha256:prior', { exact: true })).toBeVisible()
})

test('review queue filters saved gate decisions and opens the matching review', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: /Review queue/ }).click()
  await expect(page.locator('.queue-view')).toBeVisible()
  await expect(page.locator('.queue-card')).toHaveCount(2)
  await expect(page.locator('.queue-card').first()).toContainText('block')
  await expect(page.locator('.queue-card').first()).toContainText('sha256:latest')
  await expect(page.getByLabel('Filter queue by reviewer')).toContainText('correctness')

  await page.getByLabel('Filter queue by reviewer').selectOption('security')
  await page.getByLabel('Filter queue by reviewer').selectOption('correctness')
  await expect(page.locator('.queue-card')).toHaveCount(1)
  await expect(page.locator('.queue-card').first()).toContainText('rev_prior')
  await page.getByLabel('Filter queue by reviewer').selectOption('security')
  await page.getByLabel('Filter queue by provider').selectOption('claude')
  await expect(page.locator('.queue-card')).toHaveCount(1)
  await expect(page.locator('.queue-card').first()).toContainText('rev_latest')
  await expect(page.locator('.queue-card').first()).toContainText('security')
  await expect(page.locator('.queue-card').first()).toContainText('claude')

  await openSavedViews(page)

  await page.getByLabel('New queue view name').fill('Blocked security')
  await page.getByRole('button', { name: 'Save view' }).click()
  await expect(page.getByRole('status')).toHaveText('Saved “Blocked security”.')
  await page.getByRole('button', { name: 'Clear filters' }).click()
  await expect(page.locator('.queue-card')).toHaveCount(2)
  await page.getByLabel('Choose saved queue view').selectOption({ label: 'Blocked security' })
  await page.getByRole('button', { name: 'Load view' }).click()
  await expect(page.locator('.queue-card')).toHaveCount(1)
  await page.getByRole('button', { name: 'Open review →' }).click()
  await expect(page.getByText('Action required')).toBeVisible()
  await expect(page.getByText('sha256:latest', { exact: true })).toBeVisible()
})

test('queue view save reports browser storage failure instead of claiming success', async ({ page }) => {
  await page.addInitScript(() => {
    const originalSetItem = Storage.prototype.setItem
    Storage.prototype.setItem = function (key, value) {
      if (key.startsWith('vee.review-queue.views.v1:')) throw new DOMException('storage full', 'QuotaExceededError')
      return originalSetItem.call(this, key, value)
    }
  })
  await page.goto('/')
  await page.getByRole('button', { name: /Review queue/ }).click()
  await openSavedViews(page)
  await page.getByLabel('New queue view name').fill('Do not claim saved')
  await page.getByRole('button', { name: 'Save view' }).click()
  await expect(page.getByRole('status')).toHaveText('Could not save this view in browser storage.')
  await expect(page.getByRole('status')).not.toContainText('Saved “Do not claim saved”.')
})

test('queue view delete restores the view when browser storage fails', async ({ page }) => {
  await page.addInitScript(() => {
    const originalSetItem = Storage.prototype.setItem
    Storage.prototype.setItem = function (key, value) {
      if (key.startsWith('vee.review-queue.views.v1:')) throw new DOMException('storage full', 'QuotaExceededError')
      return originalSetItem.call(this, key, value)
    }
  })
  await page.goto('/')
  await page.getByRole('button', { name: /Review queue/ }).click()
  await openSavedViews(page)
  await page.getByLabel('New queue view name').fill('Keep on failed delete')
  await page.getByRole('button', { name: 'Save view' }).click()
  await expect(page.getByRole('status')).toHaveText('Could not save this view in browser storage.')
  await page.getByLabel('Choose saved queue view').selectOption({ label: 'Keep on failed delete' })
  await page.getByRole('button', { name: 'Delete view' }).click()
  await expect(page.getByRole('status')).toHaveText('Could not save this view in browser storage.')
  await expect(page.getByLabel('Choose saved queue view')).toContainText('Keep on failed delete')
})

test('Insights drilldown uses the latest gate status shown in the chart', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: /Insights/ }).click()
  await page.getByRole('button', { name: /Show reviews for 2026-11-13/ }).click()
  const drilldown = page.locator('.analytics-drilldown')
  const review = drilldown.locator('.drilldown-review').filter({ hasText: 'rev_prior' })
  await expect(review).toContainText('Gate: block')
  await expect(review).toContainText('Review: pass')
})

test('Insights saved view deletion restores the view when browser storage fails', async ({ page }) => {
  await page.addInitScript(() => {
    const originalSetItem = Storage.prototype.setItem
    Storage.prototype.setItem = function (key, value) {
      if (key.startsWith('vee.analytics.views.v1:')) throw new DOMException('storage full', 'QuotaExceededError')
      return originalSetItem.call(this, key, value)
    }
  })
  await page.goto('/')
  await page.getByRole('button', { name: /Insights/ }).click()
  await openSavedViews(page)
  await page.getByLabel('New Insights view name').fill('Keep insights view')
  await page.getByRole('button', { name: 'Save view' }).click()
  await page.getByLabel('Choose saved Insights view').selectOption({ label: 'Keep insights view' })
  await page.getByRole('button', { name: 'Delete view' }).click()
  await expect(page.getByRole('status')).toHaveText('Could not save this view in browser storage.')
  await expect(page.getByLabel('Choose saved Insights view')).toContainText('Keep insights view')
})


test('saved queue view keys include the active repository identity', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: /Review queue/ }).click()
  await openSavedViews(page)
  await page.getByLabel('New queue view name').fill('Repo one only')
  await page.getByRole('button', { name: 'Save view' }).click()
  const keys = await page.evaluate(() => Object.keys(localStorage))
  expect(keys).toContain('vee.review-queue.views.v1:/repo')
})


test('findings view renders severity, location, rationale, and provenance', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: /Findings/ }).click()
  await expect(page.getByText('The changed branch skips validation.')).toBeVisible()
  await expect(page.getByText('src/lib.rs:42')).toBeVisible()
  await expect(page.getByText('model_inference')).toBeVisible()
})

test('finding disposition records a reason and refreshes lifecycle metadata', async ({ page }) => {
  let submitted
  page.on('request', request => {
    if (request.url().endsWith('/api/findings/FIND-001/status')) submitted = request.postDataJSON()
  })
  await page.goto('/')
  await page.getByRole('button', { name: /Findings/ }).click()
  await page.getByRole('button', { name: 'Set disposition for FIND-001' }).click()
  await page.getByLabel('Disposition for FIND-001', { exact: true }).selectOption('resolved')
  await page.getByLabel('Reason for FIND-001').fill('Fixed and confirmed with the targeted test.')
  await page.getByRole('button', { name: 'Save disposition' }).click()
  await expect(page.getByText('Saved disposition for FIND-001. This does not create a policy waiver.')).toBeVisible()
  await expect(page.getByText(/Disposition: resolved/)).toBeVisible()
  expect(submitted).toEqual({ status: 'resolved', reason: 'Fixed and confirmed with the targeted test.' })
})

test('disposition form opens on demand and cancel returns focus', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: /Findings/ }).click()
  await expect(page.getByLabel('Disposition for FIND-001', { exact: true })).toHaveCount(0)
  const trigger = page.getByRole('button', { name: 'Set disposition for FIND-001' })
  await trigger.click()
  await expect(page.getByLabel('Disposition for FIND-001', { exact: true })).toBeFocused()
  await page.getByLabel('Reason for FIND-001').fill('Draft that is discarded')
  await page.getByRole('button', { name: 'Cancel' }).click()
  await expect(page.getByLabel('Disposition for FIND-001', { exact: true })).toHaveCount(0)
  await expect(trigger).toBeFocused()
  await trigger.click()
  await expect(page.getByLabel('Reason for FIND-001')).toHaveValue('')
})

test('impact view renders relationship certainty and limitations', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: /Impact/ }).click()
  await expect(page.getByText(/src\/handler.rs/)).toBeVisible()
  await expect(page.getByText(/resolved_semantic/)).toBeVisible()
  await expect(page.getByText('Dynamic dispatch is not modeled.')).toBeVisible()
  await expect(page.getByText(/changed together in 4 of 6 commits/)).toBeVisible()
  await expect(page.getByText(/line 0/)).toHaveCount(0)
})

test('reviewer view shows provider identity, version, and outcome', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: /Reviewers/ }).click()
  await expect(page.getByText('codex-cli 1.2.3')).toBeVisible()
  await expect(page.getByText('claude 2.0')).toBeVisible()
  await expect(page.getByText('completed').first()).toBeVisible()
})

test('configuration editor saves validated JSON configuration', async ({ page }) => {
  let submitted
  page.on('request', request => {
    if (request.url().endsWith('/api/config') && request.method() === 'PUT') submitted = request.postDataJSON().config
  })
  await page.goto('/')
  await page.getByRole('button', { name: /Configuration/ }).click()
  const editor = page.getByRole('textbox', { name: 'Repository config JSON' })
  const edited = { ...config, reviewers: { correctness: config.reviewers.correctness, security: { provider: 'codex', instructions_file: '.vee/reviewers/security.md' } } }
  await editor.fill(JSON.stringify(edited, null, 2))
  await page.getByRole('button', { name: 'Save configuration' }).click()
  await expect(page.getByText('correctness, security')).toBeVisible()
  expect(submitted.reviewers.security.provider).toBe('codex')
})

test('review launcher submits selected scope and opens the new review', async ({ page }) => {
  await page.goto('/')
  await page.getByLabel('Change scope').selectOption('working_tree')
  await page.getByRole('button', { name: /Run review/ }).click()
  await expect(page.getByText('Policy satisfied')).toBeVisible()
  await expect(page.getByRole('button', { name: /rev_started/ })).toBeVisible()
})

test('saved-review and Insights drilldown links are disabled while a new review is starting', async ({ page }) => {
  let releaseReview
  let reviewRequested
  const reviewGate = new Promise(resolve => { releaseReview = resolve })
  const requestSeen = new Promise(resolve => { reviewRequested = resolve })
  await page.route('**/api/reviews', async route => {
    if (route.request().method() === 'POST') {
      reviewRequested()
      await reviewGate
    }
    await route.fallback()
  })
  await page.goto('/')
  const priorReview = page.getByRole('button', { name: /rev_prior/ })
  await page.getByLabel('Change scope').selectOption('working_tree')
  await page.getByRole('button', { name: /Run review/ }).click()
  await requestSeen
  await page.getByRole('button', { name: /Insights/ }).click()
  await page.getByRole('button', { name: /Show reviews for 2026-11-14/ }).click()
  const dayReview = page.locator('.drilldown-review').filter({ hasText: 'rev_latest' })
  await expect(dayReview).toBeVisible()
  await page.getByRole('button', { name: /Show 1 high findings/ }).click()
  const findingReview = page.locator('.drilldown-finding').getByRole('button', { name: 'Open review →' })
  await expect(findingReview).toBeVisible()
  await expect(priorReview).toBeDisabled()
  await expect(dayReview).toBeDisabled()
  await expect(findingReview).toBeDisabled()
  releaseReview()
  await expect(page.getByRole('button', { name: /rev_started/ })).toBeVisible()
})

test('a running review shows each reviewer as it finishes', async ({ page }) => {
  let releaseReview
  let reviewRequested
  const reviewGate = new Promise(resolve => { releaseReview = resolve })
  const requestSeen = new Promise(resolve => { reviewRequested = resolve })
  let reviewers = []
  let token
  await page.route('**/api/reviews', async route => {
    if (route.request().method() === 'POST') {
      token = route.request().postDataJSON().progress_token
      reviewRequested()
      await reviewGate
    }
    await route.fallback()
  })
  // Another review (another tab) runs too; the page must follow only its own.
  const other = { progress_token: 'another-tab', phase: 'reviewing', elapsed_ms: 9000, reviewers: [{ reviewer_id: 'other-reviewer', runs: 1, finished: 1, failed: 0, cached: 0 }] }
  await page.route('**/api/reviews/progress', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ schema_version: 1, reviews: [{ progress_token: token, phase: reviewers.length ? 'reviewing' : 'preparing', elapsed_ms: 1000, reviewers }, other] }),
  }))
  await page.goto('/')
  await page.getByRole('button', { name: /Run review/ }).click()
  await requestSeen
  await expect(page.getByRole('status').filter({ hasText: 'Preparing review context…' })).toBeVisible()
  reviewers = [
    { reviewer_id: 'correctness', runs: 3, finished: 3, failed: 0, cached: 0 },
    { reviewer_id: 'security', runs: 1, finished: 0, failed: 0, cached: 0 },
    { reviewer_id: 'style', runs: 1, finished: 1, failed: 1, cached: 0 },
  ]
  const progress = page.getByRole('list', { name: 'Reviewer progress' })
  await expect(page.getByRole('status').filter({ hasText: '2 of 3 reviewers finished' })).toBeVisible()
  await expect(progress.getByRole('listitem').filter({ hasText: 'correctness' })).toContainText('done')
  await expect(progress.getByRole('listitem').filter({ hasText: 'security' })).toContainText('running')
  await expect(progress.getByRole('listitem').filter({ hasText: 'style' })).toContainText('failed')
  await expect(progress.getByText('other-reviewer')).toHaveCount(0)
  expect(token).toMatch(/^[A-Za-z0-9_-]{1,64}$/)
  releaseReview()
  await expect(page.getByText('Policy satisfied')).toBeVisible()
  await expect(progress).toBeHidden()
})

test('a running review keeps the previous review visible and shows elapsed time', async ({ page }) => {
  let releaseReview
  let reviewRequested
  const reviewGate = new Promise(resolve => { releaseReview = resolve })
  const requestSeen = new Promise(resolve => { reviewRequested = resolve })
  await page.route('**/api/reviews', async route => {
    if (route.request().method() === 'POST') {
      reviewRequested()
      await reviewGate
    }
    await route.fallback()
  })
  await page.goto('/')
  await expect(page.getByText('Action required')).toBeVisible()
  await page.getByLabel('Change scope').selectOption('working_tree')
  await page.getByRole('button', { name: /Run review/ }).click()
  await requestSeen
  await expect(page.getByText('Reviewing working tree…')).toBeVisible()
  await expect(page.getByRole('status').filter({ hasText: 'The previous review stays visible' })).toBeVisible()
  await expect(page.locator('.review-elapsed')).toContainText(/0:0\d elapsed/)
  await expect(page.getByText('Action required')).toBeVisible()
  releaseReview()
  await expect(page.getByText('Policy satisfied')).toBeVisible()
  await expect(page.locator('.review-elapsed')).toBeHidden()
})

test('launch controls show keyboard focus', async ({ page }) => {
  await page.goto('/')
  const scope = page.getByLabel('Change scope')
  await scope.focus()
  await expect(scope).toHaveCSS('outline-style', 'solid')
  await page.keyboard.press('Tab')
  await expect(page.getByLabel('Base branch')).toBeFocused()
  await expect(page.getByLabel('Base branch')).toHaveCSS('outline-style', 'solid')
})

test('review launcher waits for initial history before starting a new review', async ({ page }) => {
  let releaseHistory
  let historyRequested
  const historyGate = new Promise(resolve => { releaseHistory = resolve })
  const requestSeen = new Promise(resolve => { historyRequested = resolve })
  await page.route('**/api/reviews', async route => {
    if (route.request().method() === 'GET') {
      historyRequested()
      await historyGate
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([latest, prior]),
      })
      return
    }
    await route.fallback()
  })

  await page.goto('/')
  await requestSeen
  await expect(page.getByRole('button', { name: /Loading/ })).toBeDisabled()
  releaseHistory()
  await expect(page.getByRole('button', { name: /Run review/ })).toBeEnabled()
  await page.getByLabel('Change scope').selectOption('working_tree')
  await page.getByRole('button', { name: /Run review/ }).click()
  await expect(page.getByText('Policy satisfied')).toBeVisible()

  await expect(page.getByText('sha256:new', { exact: true })).toBeVisible()
  await expect(page.getByText('Action required')).toHaveCount(0)
})

test('review details remain visible when the post-review history refresh fails', async ({ page }) => {
  let reviewStarted = false
  let failedHistoryRefresh = false
  await page.route('**/api/reviews', async route => {
    const request = route.request()
    if (request.method() === 'POST') reviewStarted = true
    if (request.method() === 'GET' && reviewStarted && !failedHistoryRefresh) {
      failedHistoryRefresh = true
      await route.abort()
      return
    }
    await route.fallback()
  })

  await page.goto('/')
  await page.getByLabel('Change scope').selectOption('working_tree')
  await page.getByRole('button', { name: /Run review/ }).click()
  await expect(page.getByText('Policy satisfied')).toBeVisible()
  await expect(page.getByText('The changed branch skips validation.')).toBeVisible()
  await expect(page.getByText(/history could not be refreshed/)).toBeVisible()
})

test('review result remains visible when saved detail retrieval fails', async ({ page }) => {
  await page.route('**/api/reviews/rev_started', route => route.abort())
  await page.goto('/')
  await page.getByLabel('Change scope').selectOption('working_tree')
  await page.getByRole('button', { name: /Run review/ }).click()
  await expect(page.getByText(/Saved details could not be refreshed/)).toBeVisible()
  await expect(page.getByText('Policy satisfied')).toBeVisible()
  await expect(page.getByText('The changed branch skips validation.')).toBeVisible()
})

test('failed refresh labels retained history details as potentially outdated', async ({ page }) => {
  let detailRequests = 0
  await page.route('**/api/reviews/rev_latest', async route => {
    detailRequests += 1
    if (detailRequests > 1) return route.abort()
    await route.fallback()
  })
  await page.goto('/')
  await expect(page.getByText('Action required')).toBeVisible()
  await page.getByRole('button', { name: /rev_latest/ }).click()
  await expect(page.getByText(/Showing the last available review details; they may be out of date/)).toBeVisible()
  await expect(page.getByText('Action required')).toBeVisible()
})

test('failed history selection never shows another review result as its own', async ({ page }) => {
  await page.route('**/api/reviews/rev_prior', route => route.abort())
  await page.goto('/')
  await expect(page.getByText('Action required')).toBeVisible()
  await page.getByRole('button', { name: /rev_prior/ }).click()
  await expect(page.getByText('The selected review could not be loaded.')).toBeVisible()
  await expect(page.getByText('Action required')).toHaveCount(0)
})

test('finding drawer shows title, snapshot source, evidence, verification, and copies the work package', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  await page.goto('/')
  await page.getByRole('button', { name: /Findings/ }).click()
  await page.getByRole('button', { name: 'Open details for FIND-001' }).click()
  const drawer = page.getByRole('dialog', { name: 'Finding details' })
  await expect(drawer.getByRole('heading', { name: 'The changed branch skips validation.' })).toBeVisible()
  await expect(drawer.locator('.drawer-section small').first()).toHaveText('src/lib.rs:42')
  const highlighted = drawer.locator('.source-line.flagged')
  await expect(highlighted).toHaveCount(1)
  await expect(highlighted).toContainText('42')
  await expect(highlighted).toContainText('return process(input);')
  await expect(drawer.locator('.source-line')).toHaveCount(5)
  await expect(highlighted.locator('.line-number')).toHaveText('42')
  await expect(highlighted).not.toContainText('| ')
  await expect(drawer.getByText(/This snapshot no longer matches the working tree/)).toBeVisible()
  await expect(drawer.locator('.evidence-item strong').first()).toHaveText('src/lib.rs:42')
  await expect(drawer.getByText(/observed · source_snapshot/)).toBeVisible()
  await expect(drawer.getByText(/unit · failed/)).toBeVisible()
  await drawer.getByRole('button', { name: 'Copy work package' }).click()
  await expect(drawer.getByRole('status')).toHaveText('Work package copied.')
  const copied = JSON.parse(await page.evaluate(() => navigator.clipboard.readText()))
  expect(copied.task_id).toBe('task_find001')
  await drawer.getByRole('button', { name: 'Close finding details' }).click()
  await expect(drawer).toBeHidden()
})

test('the drawer code panel is readable on the dark theme', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: /Findings/ }).click()
  await page.getByRole('button', { name: 'Open details for FIND-001' }).click()
  const excerpt = page.locator('.source-excerpt')
  await expect(excerpt).toBeVisible()
  const [background, color] = await excerpt.evaluate(element => {
    const style = getComputedStyle(element)
    return [style.backgroundColor, style.color]
  })
  const luminance = rgb => {
    const [r, g, b] = rgb.match(/\d+/g).slice(0, 3).map(Number).map(value => {
      const channel = value / 255
      return channel <= 0.03928 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4
    })
    return 0.2126 * r + 0.7152 * g + 0.0722 * b
  }
  const [light, dark] = [luminance(color), luminance(background)].sort((a, b) => b - a)
  expect((light + 0.05) / (dark + 0.05)).toBeGreaterThan(7)
})

test('an older review marks findings the later review of the same base no longer reported', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: /Insights/ }).click()
  await page.getByRole('button', { name: /rev_prior/ }).click()
  await expect(page.getByText(/A later review of the same base, rev_latest, exists/)).toBeVisible()
  await page.getByRole('button', { name: /Findings/ }).click()
  const badge = page.locator('.finding-row').getByText('Outdated', { exact: true })
  await expect(badge).toBeVisible()
  await expect(badge).toHaveAttribute('title', /Not reported by rev_latest/)
})

test('the latest review shows no outdated marker', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: /Findings/ }).click()
  await expect(page.locator('.finding-row').first()).toBeVisible()
  await expect(page.getByText('Outdated', { exact: true })).toHaveCount(0)
})

test('queue cards show each review\'s next action from its gate', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: /Review queue/ }).click()
  const latest = page.locator('.queue-card').filter({ hasText: 'rev_latest' })
  await expect(latest.locator('.next-action')).toHaveText('Next: Fix 1 blocking finding.')
  await expect(latest.locator('.next-action')).toHaveAttribute('data-kind', 'fix_findings')
  const prior = page.locator('.queue-card').filter({ hasText: 'rev_prior' })
  await expect(prior.locator('.next-action')).toHaveText('Next: Rerun reviewers: correctness (failed).')
})

test('a slow response for an earlier finding never fills the drawer of a later one', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  let calls = 0
  let releaseFirst
  const firstHeld = new Promise(resolve => { releaseFirst = resolve })
  let firstSent
  const firstDone = new Promise(resolve => { firstSent = resolve })
  await page.route('**/api/findings/FIND-001/task', async route => {
    calls += 1
    if (calls === 1) {
      await firstHeld
      const stale = { ...findingTask, task: { ...findingTask.task, task_id: 'task_stale' } }
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(stale) })
      firstSent()
    } else {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(findingTask) })
    }
  })
  await page.goto('/')
  await page.getByRole('button', { name: /Findings/ }).click()
  const open = page.getByRole('button', { name: 'Open details for FIND-001' })
  const drawer = page.getByRole('dialog', { name: 'Finding details' })
  await open.click()
  await drawer.getByRole('button', { name: 'Close finding details' }).click()
  await open.click()
  await expect(drawer.getByRole('button', { name: 'Copy work package' })).toBeVisible()
  releaseFirst()
  await firstDone
  await page.waitForTimeout(200)
  await drawer.getByRole('button', { name: 'Copy work package' }).click()
  const copied = JSON.parse(await page.evaluate(() => navigator.clipboard.readText()))
  expect(copied.task_id).toBe('task_find001')
})

test('a review lists changed files no reviewer received', async ({ page }) => {
  await page.route('**/api/reviews/rev_latest', async route => {
    const body = detail(latest)
    body.review.unreviewed_paths = ['crates/core/lib.rs', 'schemas/new.json']
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })
  })
  await page.goto('/')
  const note = page.getByRole('note', { name: 'Not reviewed' })
  await expect(note).toContainText('No reviewer received 2 changed files')
  await expect(note.getByText('crates/core/lib.rs')).toBeVisible()
  await expect(note.getByText('schemas/new.json')).toBeVisible()
})

test('the finding drawer follows disposition saves and closes when another review opens', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: /Findings/ }).click()
  await page.getByRole('button', { name: 'Open details for FIND-001' }).click()
  const drawer = page.getByRole('dialog', { name: 'Finding details' })
  await expect(drawer).toContainText('correctness · open')
  await page.getByRole('button', { name: 'Set disposition for FIND-001' }).click()
  await page.getByLabel('Disposition for FIND-001', { exact: true }).selectOption('verified')
  await page.getByLabel('Reason for FIND-001').fill('Reproduced locally')
  await page.getByRole('button', { name: 'Save disposition' }).click()
  await expect(drawer).toContainText('correctness · verified')

  await page.getByRole('button', { name: /Insights/ }).click()
  await page.getByRole('button', { name: /rev_prior/ }).click()
  await expect(page.getByText('sha256:prior', { exact: true })).toBeVisible()
  await expect(drawer).toBeHidden()
})

test('opening a finding moves focus into the drawer and Escape closes it', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: /Findings/ }).click()
  const opener = page.getByRole('button', { name: 'Open details for FIND-001' })
  await opener.click()
  const drawer = page.getByRole('dialog', { name: 'Finding details' })
  await expect(drawer.getByRole('button', { name: 'Close finding details' })).toBeFocused()
  await page.keyboard.press('Escape')
  await expect(drawer).toBeHidden()
  await expect(opener).toBeFocused()
})

test('change risk card names the tier and the flagged factors', async ({ page }) => {
  await page.goto('/')
  await expect(page.getByLabel('Change risk')).toHaveCount(0)
  await page.route('**/api/reviews/rev_latest', route => route.fulfill({
    json: {
      ...detail(latest),
      risk: {
        schema_version: 1, snapshot_id: latest.snapshot_id, tier: 'elevated', limitations: [],
        factors: [
          { id: 'subsystems', label: 'Subsystems touched', value: 3, threshold: 3, flagged: true, detail: 'api, docs, store', basis: 'Mockus & Weiss 2000' },
          { id: 'files', label: 'Files changed', value: 3, threshold: 20, flagged: false, detail: '3 file(s)', basis: 'Kamei et al. 2013' },
        ],
      },
    },
  }))
  await page.reload()
  const card = page.getByLabel('Change risk')
  await expect(card).toContainText('elevated')
  await expect(card).toContainText('1 of 2 flagged: subsystems touched 3')
  await expect(card).not.toContainText('files changed')
  await expect(card.locator('small')).toHaveAttribute('title', /Basis: Mockus & Weiss 2000/)
})

test('finding drawer shows the changed hunk and the finding kind', async ({ page }) => {
  await page.route('**/api/findings/FIND-001/task', route => route.fulfill({ json: {
    ...findingTask,
    task: { ...findingTask.task, diff_hunk: {
      path: 'src/lib.rs', header: '@@ -41,3 +41,3 @@', truncated: false,
      lines: [
        { kind: 'context', line: 41, base_line: 41, text: '    if input.is_empty() {' },
        { kind: 'removed', line: null, base_line: 42, text: '        return Err(Empty);' },
        { kind: 'added', line: 42, base_line: null, text: '        return process(input);' },
      ],
    } },
  } }))
  await page.goto('/')
  await page.getByRole('button', { name: /Findings/ }).click()
  await page.getByRole('button', { name: 'Open details for FIND-001' }).click()
  const drawer = page.getByRole('dialog', { name: 'Finding details' })
  await expect(drawer.locator('.finding-kind')).toHaveText('defect')
  const change = drawer.getByRole('region', { name: 'Change' })
  await expect(change).toContainText('@@ -41,3 +41,3 @@')
  await expect(change.locator('.source-line.removed')).toContainText('return Err(Empty);')
  await expect(change.locator('.source-line.added.flagged')).toContainText('return process(input);')
})

test('finding drawer omits the change section when the flagged line is unchanged', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: /Findings/ }).click()
  await page.getByRole('button', { name: 'Open details for FIND-001' }).click()
  const drawer = page.getByRole('dialog', { name: 'Finding details' })
  await expect(drawer.getByText('Code reference')).toBeVisible()
  await expect(drawer.getByRole('region', { name: 'Change' })).toHaveCount(0)
})

test('impact lists code references before history-only co-change leads', async ({ page }) => {
  await page.route('**/api/reviews/rev_latest', route => route.fulfill({ json: {
    ...detail(latest),
    impact: { ...detail(latest).impact, paths: [
      { affected_path: 'schemas/api.json', source_path: 'src/lib.rs', symbol: '', relationship: 'co_change', certainty: 'historical', evidence_line: 0, co_change: { together: 4, source_commits: 6 } },
      { affected_path: 'src/handler.rs', source_path: 'src/lib.rs', symbol: 'validate', relationship: 'syntactic_symbol_reference', certainty: 'inferred_syntax', evidence_line: 18 },
    ] },
  } }))
  await page.goto('/')
  await page.getByRole('button', { name: /Impact/ }).click()
  await expect(page.locator('.impact-row').first()).toContainText('src/handler.rs')
  await expect(page.locator('.impact-row').nth(1)).toContainText('changed together in 4 of 6 commits')
})

test('overview findings use the finding title, not only its category', async ({ page }) => {
  await page.goto('/')
  await expect(page.locator('.content-grid .finding-row strong').first()).toHaveText('The changed branch skips validation.')
})

test('a review whose checkout has moved says why impact and risk are missing', async ({ page }) => {
  await page.route('**/api/reviews/rev_latest', route => route.fulfill({ json: { ...detail(latest), snapshot_current: false } }))
  await page.goto('/')
  await expect(page.getByRole('note').filter({ hasText: 'The checkout has changed since this review' })).toBeVisible()
  await expect(page.getByLabel('Change risk')).toHaveCount(0)
})

test('a current review shows no moved-checkout notice', async ({ page }) => {
  await page.route('**/api/reviews/rev_latest', route => route.fulfill({ json: { ...detail(latest), snapshot_current: true } }))
  await page.goto('/')
  await expect(page.getByRole('button', { name: 'Overview' })).toBeVisible()
  await expect(page.getByText('The checkout has changed since this review')).toHaveCount(0)
})
