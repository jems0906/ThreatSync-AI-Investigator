/* ─────────────────────────────────────────────────────────────────────────────
   ThreatSync AI Investigator — Frontend
   ─────────────────────────────────────────────────────────────────────────── */

const API_BASE = '';           // same origin
let selectedAlertId = null;
let activeWs        = null;
let investigationId = null;
let SERVICE_API_KEY = localStorage.getItem('threatsync.serviceApiKey') || '';
let ANALYST_API_KEY = localStorage.getItem('threatsync.analystApiKey') || '';

function serviceHeaders(extra = {}) {
  return SERVICE_API_KEY
    ? { ...extra, 'X-API-Key': SERVICE_API_KEY }
    : extra;
}

function analystHeaders(extra = {}) {
  return ANALYST_API_KEY
    ? { ...extra, 'X-Analyst-Key': ANALYST_API_KEY }
    : extra;
}

// ── Utility ───────────────────────────────────────────────────────────────────

function wsUrl(path) {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const authSuffix = SERVICE_API_KEY ? `${path.includes('?') ? '&' : '?'}api_key=${encodeURIComponent(SERVICE_API_KEY)}` : '';
  return `${proto}//${window.location.host}${path}${authSuffix}`;
}

function now() {
  return new Date().toLocaleTimeString('en-US', { hour12: false });
}

function sevClass(hint) {
  const h = (hint || '').toLowerCase();
  if (h === 'critical') return 'sev-critical';
  if (h === 'high')     return 'sev-high';
  if (h === 'medium')   return 'sev-medium';
  return 'sev-low';
}

function riskClass(risk) {
  const r = (risk || '').toLowerCase();
  if (r === 'critical') return 'risk-critical';
  if (r === 'high')     return 'risk-high';
  if (r === 'medium')   return 'risk-medium';
  return 'risk-low';
}

function statusBadgeHtml(status) {
  return `<span class="alert-status-badge status-${status}">${status}</span>`;
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function securityLabel() {
  if (SERVICE_API_KEY && ANALYST_API_KEY) return 'Auth mode: both keys loaded';
  if (SERVICE_API_KEY) return 'Auth mode: service key loaded';
  if (ANALYST_API_KEY) return 'Auth mode: analyst key loaded';
  return 'Auth mode: no keys loaded (open mode)';
}

function updateSecurityStatus() {
  const statusEl = document.getElementById('security-status');
  if (!statusEl) return;
  statusEl.textContent = securityLabel();
  updateInvestigateWarn();
}

function updateInvestigateWarn() {
  const warn = document.getElementById('investigate-auth-warn');
  if (!warn) return;
  if (!SERVICE_API_KEY) {
    warn.innerHTML =
      '&#9888; No service key loaded \u2014 if auth is enabled, investigation will be rejected. ' +
      '<a href="#security-panel" class="auth-warn-link">Open Security panel</a> to add one.';
    warn.classList.remove('hidden');
  } else {
    warn.classList.add('hidden');
  }
}

function setSecurityTestResult(text, state = '') {
  const resultEl = document.getElementById('security-test-result');
  if (!resultEl) return;
  resultEl.textContent = text;
  resultEl.classList.remove('ok', 'err');
  if (state) resultEl.classList.add(state);
}

function loadSecurityInputs() {
  const serviceInput = document.getElementById('service-api-key');
  const analystInput = document.getElementById('analyst-api-key');
  if (serviceInput) serviceInput.value = SERVICE_API_KEY;
  if (analystInput) analystInput.value = ANALYST_API_KEY;
  updateSecurityStatus();
}

function applySecurityFromInputs() {
  const serviceInput = document.getElementById('service-api-key');
  const analystInput = document.getElementById('analyst-api-key');

  SERVICE_API_KEY = (serviceInput?.value || '').trim();
  ANALYST_API_KEY = (analystInput?.value || '').trim();

  updateSecurityStatus();
  setSecurityTestResult('Auth test: not run');
  loadAlerts();
  loadApprovals();
}

function saveSecurityKeys() {
  applySecurityFromInputs();
  localStorage.setItem('threatsync.serviceApiKey', SERVICE_API_KEY);
  localStorage.setItem('threatsync.analystApiKey', ANALYST_API_KEY);
}

function clearSecurityKeys() {
  SERVICE_API_KEY = '';
  ANALYST_API_KEY = '';
  localStorage.removeItem('threatsync.serviceApiKey');
  localStorage.removeItem('threatsync.analystApiKey');
  loadSecurityInputs();
  setSecurityTestResult('Auth test: not run');
  loadAlerts();
  loadApprovals();
}

function toggleKeyInput(inputId, buttonId) {
  const input = document.getElementById(inputId);
  const btn = document.getElementById(buttonId);
  if (!input || !btn) return;

  const nowVisible = input.type === 'password';
  input.type = nowVisible ? 'text' : 'password';
  btn.textContent = nowVisible ? 'Hide' : 'Show';
}

async function testAuth() {
  setSecurityTestResult('Auth test: running...');
  try {
    const serviceResp = await fetch(`${API_BASE}/api/alerts?limit=1`, {
      headers: serviceHeaders(),
    });
    const analystResp = await fetch(`${API_BASE}/api/approvals/pending`, {
      headers: analystHeaders(),
    });

    const serviceOk = serviceResp.ok;
    const analystOk = analystResp.ok;

    if (serviceOk && analystOk) {
      setSecurityTestResult(
        `Auth test: success (service ${serviceResp.status}, analyst ${analystResp.status})`,
        'ok'
      );
      return;
    }

    setSecurityTestResult(
      `Auth test: failed (service ${serviceResp.status}, analyst ${analystResp.status})`,
      'err'
    );
  } catch (e) {
    setSecurityTestResult('Auth test: network or server error', 'err');
  }
}

// ── Health check ──────────────────────────────────────────────────────────────

async function checkHealth() {
  try {
    const r = await fetch(`${API_BASE}/health`);
    if (!r.ok) throw new Error();
    const data = await r.json();

    setPill('pill-api',   data.status === 'healthy');
    setPill('pill-redis', data.services?.redis    === 'connected');
    setPill('pill-rag',   data.services?.rag_pipeline === 'ready');
  } catch {
    setPill('pill-api', false);
  }
}

function setPill(id, ok) {
  const el = document.getElementById(id);
  if (!el) return;
  el.classList.toggle('ok',  ok);
  el.classList.toggle('err', !ok);
}

// ── Alerts ────────────────────────────────────────────────────────────────────

async function loadAlerts() {
  try {
    const r = await fetch(`${API_BASE}/api/alerts?limit=50`, {
      headers: serviceHeaders(),
    });
    if (!r.ok) return;
    const alerts = await r.json();

    const list = document.getElementById('alert-list');
    document.getElementById('alert-count-badge').textContent = alerts.length;

    if (!alerts.length) {
      list.innerHTML = `<div class="empty-state">
        <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <circle cx="12" cy="12" r="10"/>
          <line x1="12" y1="8" x2="12" y2="12"/>
          <line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
        <span>No alerts yet</span>
      </div>`;
      return;
    }

    list.innerHTML = alerts.map(a => `
      <div class="alert-card ${a.id === selectedAlertId ? 'active' : ''}"
           data-id="${a.id}" onclick="selectAlert(${a.id}, this)">
        <div class="alert-card-header">
          <div class="sev-dot ${sevClass(a.severity_hint)}"></div>
          <span class="alert-type">${escHtml(a.alert_type.replace(/_/g, ' '))}</span>
          ${statusBadgeHtml(a.status)}
        </div>
        <div class="alert-meta">
          ${a.user_id   ? `<span>👤 ${escHtml(a.user_id)}</span>` : ''}
          ${a.source_ip ? `<span>🌐 ${escHtml(a.source_ip)}</span>` : ''}
          ${a.hostname  ? `<span>💻 ${escHtml(a.hostname)}</span>` : ''}
          <span>🕐 ${new Date(a.occurred_at).toLocaleTimeString()}</span>
        </div>
      </div>
    `).join('');
  } catch (e) {
    console.error('loadAlerts:', e);
  }
}

function selectAlert(id, el) {
  // Update selected state
  document.querySelectorAll('.alert-card').forEach(c => c.classList.remove('active'));
  el.classList.add('active');
  selectedAlertId = id;

  document.getElementById('stream-title').textContent =
    `Alert #${id} — ready to investigate`;
  document.getElementById('btn-investigate').disabled = false;
  document.getElementById('result-area').innerHTML = '';
  clearStream();
  addStreamMsg('sys', 'alert', `Alert #${id} selected. Press Investigate to start.`);
  updateInvestigateWarn();
}

// ── Stream helpers ─────────────────────────────────────────────────────────────

function clearStream() {
  document.getElementById('stream-body').innerHTML = '';
}

let tokenBuffer = '';
let tokenLineEl = null;

function addStreamMsg(ts, phase, text) {
  tokenLineEl = null;
  tokenBuffer = '';
  const body = document.getElementById('stream-body');
  const div  = document.createElement('div');
  div.className = 'stream-msg';
  div.innerHTML = `
    <span class="ts">${ts}</span>
    <span class="phase">[${phase.toUpperCase()}]</span>
    <span class="text">${escHtml(text)}</span>`;
  body.appendChild(div);
  body.scrollTop = body.scrollHeight;
}

function appendToken(content) {
  const body = document.getElementById('stream-body');
  if (!tokenLineEl) {
    tokenLineEl = document.createElement('div');
    tokenLineEl.className = 'token-line';
    body.appendChild(tokenLineEl);
  }
  tokenBuffer += content;
  tokenLineEl.textContent = tokenBuffer;
  body.scrollTop = body.scrollHeight;
}

// ── WebSocket investigation ───────────────────────────────────────────────────

function startInvestigation() {
  if (!selectedAlertId) return;
  if (activeWs) { activeWs.close(); activeWs = null; }

  clearStream();
  document.getElementById('result-area').innerHTML = '';
  tokenBuffer  = '';
  tokenLineEl  = null;
  investigationId = null;

  const btn = document.getElementById('btn-investigate');
  btn.disabled   = true;
  btn.innerHTML  = '<span class="spinner"></span>';

  document.getElementById('stream-title').textContent =
    `Investigating Alert #${selectedAlertId}…`;

  const url = wsUrl(`/ws/investigations/${selectedAlertId}`);
  activeWs = new WebSocket(url);

  activeWs.onopen = () => {
    addStreamMsg(now(), 'ws', 'WebSocket connected — pipeline starting…');
  };

  activeWs.onmessage = (ev) => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch { return; }
    handleWsMessage(msg);
  };

  activeWs.onerror = () => {
    addStreamMsg(now(), 'error', 'WebSocket error — check server logs.');
    resetBtn();
  };

  activeWs.onclose = () => {
    addStreamMsg(now(), 'ws', 'Connection closed.');
    resetBtn();
    loadAlerts();        // refresh badge statuses
    loadApprovals();
  };
}

function handleWsMessage(msg) {
  switch (msg.type) {

    case 'status':
      addStreamMsg(now(), msg.phase || 'info', msg.message);
      break;

    case 'alert_data':
      addStreamMsg(now(), 'alert', `Type: ${msg.data.alert_type}  |  User: ${msg.data.user_id || 'n/a'}  |  IP: ${msg.data.source_ip || 'n/a'}`);
      break;

    case 'investigation_created':
      investigationId = msg.investigation_id;
      addStreamMsg(now(), 'db', `Investigation record created (ID: ${msg.investigation_id})`);
      break;

    case 'context_retrieved':
      addStreamMsg(now(), 'rag',
        `Retrieved — threat_intel: ${msg.data.threat_intel_docs} docs, ` +
        `user_activity: ${msg.data.user_activity_docs} docs, ` +
        `similar_alerts: ${msg.data.similar_alert_docs} docs`);
      break;

    case 'analysis_start':
      tokenBuffer = '';
      tokenLineEl = null;
      addStreamMsg(now(), 'llm', '── Streaming AI analysis ──────────────────────');
      break;

    case 'token':
      appendToken(msg.content);
      break;

    case 'analysis_complete':
      tokenLineEl  = null;
      tokenBuffer  = '';
      addStreamMsg(now(), 'llm', '── Analysis complete ──────────────────────────');
      renderResult(msg.data, msg.investigation_id);
      break;

    case 'approval_required':
      addStreamMsg(now(), 'ESCALATE',
        `⚠ Severity ${msg.severity_score.toFixed(1)}/10 — added to approval queue`);
      document.getElementById('stream-title').textContent =
        `Alert #${selectedAlertId} — ESCALATED for review`;
      break;

    case 'auto_resolved':
      addStreamMsg(now(), 'resolve',
        `Recommendation: ${msg.recommendation} — ${msg.message}`);
      document.getElementById('stream-title').textContent =
        `Alert #${selectedAlertId} — auto-resolved`;
      break;

    case 'error':
      addStreamMsg(now(), 'error', msg.message);
      break;
  }
}

function resetBtn() {
  const btn = document.getElementById('btn-investigate');
  btn.disabled  = false;
  btn.innerHTML = '&#9654; Investigate';
}

// ── Render structured result ───────────────────────────────────────────────────

function renderResult(data, invId) {
  const score    = (data.severity_score || 0).toFixed(1);
  const rClass   = riskClass(data.estimated_risk);
  const recClass = `rec-${data.recommendation || 'monitor'}`;

  const stepsHtml = (data.investigation_steps || []).map(s =>
    `<span class="tag step">Step ${s.step}: ${escHtml(s.action)}</span>`
  ).join('');

  const iocsHtml = (data.iocs || []).map(i =>
    `<span class="tag ioc">${escHtml(i)}</span>`
  ).join('');

  const mitreHtml = (data.mitre_tactics || []).map(t =>
    `<span class="tag mitre">${escHtml(t)}</span>`
  ).join('');

  const findingsHtml = (data.key_findings || []).map(f =>
    `<li style="margin-bottom:4px;font-size:12px;color:var(--text-primary)">${escHtml(f)}</li>`
  ).join('');

  document.getElementById('result-area').innerHTML = `
    <div class="result-card">
      <div class="result-header">
        <div class="severity-gauge">
          <div class="gauge-score ${rClass}">${score}</div>
          <div class="gauge-label">/ 10</div>
        </div>
        <div class="result-meta">
          <h4>${escHtml(data.threat_type || 'Unknown Threat')}</h4>
          <p>${escHtml(data.estimated_risk || '')} risk · ${Math.round((data.confidence || 0) * 100)}% confidence</p>
        </div>
        <span class="rec-badge ${recClass}">${escHtml(data.recommendation || '')}</span>
      </div>

      <div class="result-section">
        <h5>Summary</h5>
        <p style="font-size:12px;line-height:1.6;color:var(--text-primary)">${escHtml(data.summary || '')}</p>
      </div>

      ${findingsHtml ? `
      <div class="result-section">
        <h5>Key Findings</h5>
        <ul style="padding-left:16px">${findingsHtml}</ul>
      </div>` : ''}

      ${stepsHtml ? `
      <div class="result-section">
        <h5>Investigation Steps</h5>
        <div class="tag-list" style="flex-direction:column">${stepsHtml}</div>
      </div>` : ''}

      ${iocsHtml ? `
      <div class="result-section">
        <h5>IOCs</h5>
        <div class="tag-list">${iocsHtml}</div>
      </div>` : ''}

      ${mitreHtml ? `
      <div class="result-section">
        <h5>MITRE ATT&amp;CK Tactics</h5>
        <div class="tag-list">${mitreHtml}</div>
      </div>` : ''}
    </div>`;
}

// ── Approvals ─────────────────────────────────────────────────────────────────

async function loadApprovals() {
  try {
    const r = await fetch(`${API_BASE}/api/approvals/pending`, {
      headers: analystHeaders(),
    });
    if (!r.ok) return;
    const approvals = await r.json();

    const badge    = document.getElementById('approval-badge');
    const pillSpan = document.getElementById('pending-count');
    const list     = document.getElementById('approval-list');
    const pill     = document.getElementById('pill-approvals');

    badge.textContent    = approvals.length;
    pillSpan.textContent = approvals.length;
    badge.classList.toggle('active', approvals.length > 0);
    pill.classList.toggle('ok',  approvals.length > 0);
    pill.classList.toggle('err', false);

    if (!approvals.length) {
      list.innerHTML = `<div class="empty-state" id="approval-empty">
        <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <polyline points="20 6 9 17 4 12"/>
        </svg>
        <span>No pending approvals</span>
      </div>`;
      return;
    }

    // Fetch investigation details for each approval
    const cards = await Promise.all(approvals.map(async ap => {
      let inv = null;
      try {
        const ir = await fetch(`${API_BASE}/api/investigations/${ap.investigation_id}`, {
          headers: serviceHeaders(),
        });
        if (ir.ok) inv = await ir.json();
      } catch {}

      const score    = inv ? (inv.severity_score || 0).toFixed(1) : '?';
      const threat   = inv ? escHtml(inv.threat_type || 'Unknown') : 'Unknown';
      const summary  = inv ? escHtml((inv.summary || '').substring(0, 120)) + '…' : '';

      return `
        <div class="approval-card" id="ap-${ap.id}">
          <div class="approval-card-header">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--red)" stroke-width="2">
              <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
              <line x1="12" y1="9" x2="12" y2="13"/>
              <line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>
            <span class="title">${threat} — Score ${score}/10</span>
            <span style="font-size:11px;color:var(--text-muted)">Inv #${ap.investigation_id}</span>
          </div>
          <div class="approval-body">
            <p>${summary}</p>
            <div class="approval-actions">
              <button class="btn-approve" onclick="decide(${ap.investigation_id}, 'approve', ${ap.id})">
                ✓ Approve
              </button>
              <button class="btn-reject" onclick="decide(${ap.investigation_id}, 'reject', ${ap.id})">
                ✗ Reject
              </button>
            </div>
          </div>
        </div>`;
    }));

    list.innerHTML = cards.join('');
  } catch (e) {
    console.error('loadApprovals:', e);
  }
}

async function decide(investigationId, action, approvalCardId) {
  const analystId = 'analyst@company.com';   // in a real app this comes from auth
  try {
    const r = await fetch(
      `${API_BASE}/api/approvals/${investigationId}/${action}`,
      {
        method: 'POST',
        headers: analystHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ analyst_id: analystId, notes: `${action}d via dashboard` }),
      }
    );
    if (!r.ok) {
      const err = await r.json();
      alert(err.detail || 'Action failed');
      return;
    }
    // Animate out
    const card = document.getElementById(`ap-${approvalCardId}`);
    if (card) {
      card.style.transition = 'opacity .3s';
      card.style.opacity    = '0';
      setTimeout(() => loadApprovals(), 350);
    } else {
      loadApprovals();
    }
    loadAlerts();
  } catch (e) {
    console.error('decide:', e);
  }
}

// ── Init + polling ─────────────────────────────────────────────────────────────

document.getElementById('btn-investigate').addEventListener('click', startInvestigation);
document.getElementById('btn-refresh').addEventListener('click', loadAlerts);
document.getElementById('btn-auth-apply').addEventListener('click', applySecurityFromInputs);
document.getElementById('btn-auth-save').addEventListener('click', saveSecurityKeys);
document.getElementById('btn-auth-clear').addEventListener('click', clearSecurityKeys);
document.getElementById('btn-auth-test').addEventListener('click', testAuth);
document.getElementById('btn-toggle-service-key').addEventListener('click', () => {
  toggleKeyInput('service-api-key', 'btn-toggle-service-key');
});
document.getElementById('btn-toggle-analyst-key').addEventListener('click', () => {
  toggleKeyInput('analyst-api-key', 'btn-toggle-analyst-key');
});

async function init() {
  loadSecurityInputs();
  await checkHealth();
  await Promise.all([loadAlerts(), loadApprovals()]);

  // Poll every 8 s
  setInterval(() => {
    checkHealth();
    loadAlerts();
    loadApprovals();
  }, 8000);
}

init();
