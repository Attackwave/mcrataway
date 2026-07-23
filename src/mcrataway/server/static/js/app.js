/**
 * mcrataway Web Application Frontend App
 */

// Global State
const state = {
  activeTab: 'dashboard',
  currentJob: null,
  ws: null,
  scanProgress: 0,
  scannedFiles: 0,
  totalFiles: 0,
  findings: [],
  quarantineItems: [],
  rules: [],
  discoveredRoots: [],
  config: {},
  pickerPath: '',
  selectedPath: '',
  pickerItems: [],
  showPickerModal: false,
  selectedScanPaths: [],
};

// Initialize App
document.addEventListener('DOMContentLoaded', () => {
  init();
});

async function init() {
  renderApp();
  await loadInitialData();
  lucide.createIcons();
}

async function loadInitialData() {
  try {
    const [rootsRes, rulesRes, quarantineRes, configRes, healthRes] = await Promise.all([
      fetch('/system/roots').then(r => r.json()),
      fetch('/rules/').then(r => r.json()),
      fetch('/quarantine/').then(r => r.json()),
      fetch('/system/config').then(r => r.json()),
      fetch('/system/health').then(r => r.json()).catch(() => ({})),
    ]);

    state.discoveredRoots = rootsRes || [];
    state.rules = rulesRes || [];
    state.quarantineItems = quarantineRes || [];
    state.config = configRes || {};
    if (healthRes && healthRes.version) {
      state.version = healthRes.version;
    }

    renderApp();
  } catch (err) {
    showToast('Failed to load system data: ' + err.message, 'error');
  }
}

function showToast(message, type = 'info') {
  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.innerHTML = `<i data-lucide="${type === 'error' ? 'alert-circle' : 'check-circle'}" style="color:${type === 'error' ? '#ef4444' : '#10b981'}"></i> <span>${message}</span>`;
  document.body.appendChild(toast);
  lucide.createIcons();
  setTimeout(() => toast.remove(), 4000);
}

// Navigation & Router
function setTab(tabName) {
  state.activeTab = tabName;
  renderApp();
}

// Directory Browser Logic & Multi-Path Queue
function addPathToQueue(path) {
  if (!path) return;
  const cleanPath = path.replace(/\\/g, '/');
  if (!state.selectedScanPaths.includes(cleanPath)) {
    state.selectedScanPaths.push(cleanPath);
    showToast(`Added to scan queue: ${cleanPath.split('/').pop() || cleanPath}`, 'info');
    renderApp();
  }
}

function removePathFromQueue(path) {
  state.selectedScanPaths = state.selectedScanPaths.filter(p => p !== path);
  renderApp();
}

function clearQueue() {
  state.selectedScanPaths = [];
  renderApp();
}

async function openPickerModal(initialPath = '') {
  state.showPickerModal = true;
  state.selectedPath = initialPath;
  await fetchBrowsePath(initialPath);
}

function closePickerModal() {
  state.showPickerModal = false;
  state.selectedPath = '';
  renderApp();
}

async function fetchBrowsePath(path = '') {
  try {
    const res = await fetch(`/system/browse?path=${encodeURIComponent(path)}`);
    const data = await res.json();
    state.pickerPath = data.current_path;
    state.pickerItems = data.items || [];
    if (data.parent_path) {
      state.pickerItems.unshift({ name: '.. (Parent Directory)', path: data.parent_path, is_dir: true, is_parent: true });
    }
    renderApp();
  } catch (err) {
    showToast('Could not load directory', 'error');
  }
}

// Scanning Engine Execution
async function startScan(roots = null, autoDiscover = false) {
  if (autoDiscover && (!state.discoveredRoots || state.discoveredRoots.length === 0)) {
    showToast('No Minecraft installations auto-detected. Please select a directory manually.', 'info');
    openPickerModal();
    return;
  }

  try {
    let url = `/scan/?auto_discover=${autoDiscover}`;
    if (roots && roots.length > 0) {
      for (const r of roots) {
        url += `&roots=${encodeURIComponent(r)}`;
      }
    }

    const res = await fetch(url, { method: 'POST' });
    const data = await res.json();

    if (data.job_id) {
      state.currentJob = data;
      state.findings = [];
      state.scanProgress = 0;
      state.scannedFiles = 0;
      state.totalFiles = 0;
      state.activeTab = 'scanner';
      renderApp();
      connectWebSocket(data.job_id);
      showToast(`Malware scan started for ${roots ? roots.length : 'auto'} target(s)...`, 'info');
    }
  } catch (err) {
    showToast('Scan start failed: ' + err.message, 'error');
  }
}

function connectWebSocket(jobId) {
  if (state.ws) {
    state.ws.close();
  }

  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/scan/${jobId}/stream`;

  state.ws = new WebSocket(wsUrl);

  state.ws.onmessage = (event) => {
    const data = JSON.parse(event.data);

    if (data.type === 'progress') {
      state.scanProgress = data.percent;
      state.scannedFiles = data.scanned;
      state.totalFiles = data.total;
      renderApp();
    } else if (data.type === 'verdict') {
      state.findings.unshift(data.verdict);
      renderApp();
    } else if (data.type === 'done') {
      showToast('Scan completed!', 'success');
      state.currentJob.status = 'COMPLETED';
      loadInitialData();
    }
  };

  state.ws.onerror = () => {
    showToast('WebSocket connection disconnected', 'error');
  };
}

// Dynamic Rule Updates
async function triggerRuleUpdate() {
  try {
    showToast('Downloading latest threat signatures...', 'info');
    const res = await fetch('/system/update-rules', { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      showToast(`${data.downloaded_count} signature pack(s) successfully updated!`, 'success');
      await loadInitialData();
    }
  } catch (err) {
    showToast('Signature update failed: ' + err.message, 'error');
  }
}

// Save Config
async function saveConfig(event) {
  event.preventDefault();
  const formData = new FormData(event.target);
  const payload = {
    max_workers: parseInt(formData.get('max_workers'), 10),
    quarantine_malicious: formData.get('quarantine_malicious') === 'on',
    quarantine_suspicious: formData.get('quarantine_suspicious') === 'on',
  };

  try {
    const res = await fetch('/system/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (data.success) {
      showToast('Settings saved successfully', 'success');
      state.config = data.config;
      renderApp();
    }
  } catch (err) {
    showToast('Saving failed', 'error');
  }
}

// Restore Quarantined File
async function restoreFile(sha256) {
  try {
    const res = await fetch(`/quarantine/${sha256}`, { method: 'DELETE' });
    const data = await res.json();
    if (data.success) {
      showToast('File successfully restored', 'success');
      await loadInitialData();
    }
  } catch (err) {
    showToast('Restoration failed', 'error');
  }
}

// Render Functions
function renderApp() {
  const container = document.getElementById('app');
  container.innerHTML = `
    ${renderHeader()}
    <main>
      ${state.activeTab === 'dashboard' ? renderDashboard() : ''}
      ${state.activeTab === 'scanner' ? renderScanner() : ''}
      ${state.activeTab === 'quarantine' ? renderQuarantine() : ''}
      ${state.activeTab === 'rules' ? renderRules() : ''}
      ${state.activeTab === 'settings' ? renderSettings() : ''}
    </main>
    ${state.showPickerModal ? renderPickerModal() : ''}
  `;

  lucide.createIcons();
  attachEvents();
}

function renderHeader() {
  return `
    <header>
      <div class="brand">
        <div class="brand-icon">
          <i data-lucide="shield-alert" style="color:#fff; width:24px; height:24px;"></i>
        </div>
        <span>mcrataway</span>
        <span class="brand-version">v${state.version || '1.0.0'}</span>
      </div>

      <nav>
        <button class="nav-link ${state.activeTab === 'dashboard' ? 'active' : ''}" onclick="setTab('dashboard')">
          <i data-lucide="layout-dashboard"></i> Dashboard
        </button>
        <button class="nav-link ${state.activeTab === 'scanner' ? 'active' : ''}" onclick="setTab('scanner')">
          <i data-lucide="radar"></i> Scanner
        </button>
        <button class="nav-link ${state.activeTab === 'quarantine' ? 'active' : ''}" onclick="setTab('quarantine')">
          <i data-lucide="box"></i> Quarantine (${state.quarantineItems.length})
        </button>
        <button class="nav-link ${state.activeTab === 'rules' ? 'active' : ''}" onclick="setTab('rules')">
          <i data-lucide="file-code"></i> Rule Packs
        </button>
        <button class="nav-link ${state.activeTab === 'settings' ? 'active' : ''}" onclick="setTab('settings')">
          <i data-lucide="settings"></i> Settings
        </button>
      </nav>

      <div class="status-badge">
        <span class="status-dot"></span>
        <span>Scanner Engine Active</span>
      </div>
    </header>
  `;
}

function renderDashboard() {
  return `
    <div class="grid-3">
      <div class="card hero-card">
        <div>
          <div class="hero-title"><i data-lucide="zap" style="color:var(--primary)"></i> Auto-Scan Minecraft</div>
          <div class="hero-desc">Automatically scans all detected installations (.minecraft, PrismLauncher, CurseForge, MultiMC, ATLauncher).</div>
        </div>
        <button class="btn btn-primary" onclick="startScan(null, true)">
          <i data-lucide="play"></i> Start Auto-Scan
        </button>
      </div>

      <div class="card hero-card">
        <div>
          <div class="hero-title"><i data-lucide="folder-search" style="color:var(--success)"></i> Select Directories</div>
          <div class="hero-desc">Select and queue custom folders or .jar mod files on your disk to scan together.</div>
        </div>
        <button class="btn btn-secondary" onclick="openPickerModal()">
          <i data-lucide="folder-open"></i> Select Directories...
        </button>
      </div>

      <div class="card hero-card">
        <div>
          <div class="hero-title"><i data-lucide="refresh-cw" style="color:var(--warning)"></i> Signature Updates</div>
          <div class="hero-desc">Download the latest community rules and threat intelligence patterns.</div>
        </div>
        <button class="btn btn-secondary" onclick="triggerRuleUpdate()">
          <i data-lucide="download-cloud"></i> Update Signatures
        </button>
      </div>
    </div>

    <div class="grid-3">
      <div class="card stat-box">
        <span class="stat-label">Discovered Minecraft Roots</span>
        <span class="stat-value" style="color:var(--primary)">${state.discoveredRoots.length}</span>
      </div>
      <div class="card stat-box">
        <span class="stat-label">Quarantined Files</span>
        <span class="stat-value" style="color:var(--danger)">${state.quarantineItems.length}</span>
      </div>
      <div class="card stat-box">
        <span class="stat-label">Active Rule Packs</span>
        <span class="stat-value" style="color:var(--success)">${state.rules.length}</span>
      </div>
    </div>

    <div class="card">
      <h3 style="margin-bottom:16px; font-weight:600; display:flex; align-items:center; gap:8px;">
        <i data-lucide="folder"></i> Auto-Detected Folders
      </h3>
      <div class="browser-list">
        ${state.discoveredRoots.length === 0 ? '<div style="padding:12px; color:var(--text-muted);">No Minecraft folders found.</div>' : ''}
        ${state.discoveredRoots.map(root => `
          <div class="browser-item">
            <i data-lucide="folder-check" style="color:var(--primary)"></i>
            <span style="flex:1; font-family:var(--font-mono); font-size:0.85rem;">${root}</span>
            <div style="display:flex; gap:8px;">
              <button class="btn btn-sm btn-secondary" onclick="addPathToQueue('${root.replace(/\\/g, '/')}')"><i data-lucide="plus"></i> Queue</button>
              <button class="btn btn-sm btn-primary" onclick="startScan(['${root.replace(/\\/g, '/')}'])"><i data-lucide="play"></i> Scan Now</button>
            </div>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

function renderScanner() {
  const maliciousCount = state.findings.filter(f => f.verdict === 'MALICIOUS').length;
  const suspiciousCount = state.findings.filter(f => f.verdict === 'SUSPICIOUS').length;

  return `
    <div class="card" style="margin-bottom: 24px;">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <div>
          <h2 style="font-weight:600; display:flex; align-items:center; gap:10px;">
            <i data-lucide="radar" style="color:var(--primary)"></i> Live Malware Scanner
          </h2>
          <div style="color:var(--text-muted); font-size:0.9rem; margin-top:4px;">
            ${state.currentJob ? `Job ID: ${state.currentJob.job_id}` : 'Ready for new scan.'}
          </div>
        </div>
        <button class="btn btn-secondary" onclick="openPickerModal()">
          <i data-lucide="folder-plus"></i> Select Targets...
        </button>
      </div>

      ${state.currentJob ? `
        <div class="progress-container">
          <div style="display:flex; justify-content:space-between; margin-bottom:8px; font-size:0.9rem; font-weight:500;">
            <span>Progress: ${state.scannedFiles || 0} / ${state.totalFiles || '?'} files</span>
            <span>${(state.scanProgress || 0).toFixed(1)}%</span>
          </div>
          <div class="progress-bar-bg">
            <div class="progress-bar-fill" style="width: ${state.scanProgress || 0}%"></div>
          </div>
        </div>
      ` : ''}

      <div style="display:grid; grid-template-columns: repeat(3, 1fr); gap:16px; margin-top:20px;">
        <div class="card stat-box" style="background:rgba(239, 68, 68, 0.08); border-color:rgba(239, 68, 68, 0.2);">
          <span class="stat-label" style="color:#fca5a5;">Malicious</span>
          <span class="stat-value" style="color:#ef4444;">${maliciousCount}</span>
        </div>
        <div class="card stat-box" style="background:rgba(245, 158, 11, 0.08); border-color:rgba(245, 158, 11, 0.2);">
          <span class="stat-label" style="color:#fcd34d;">Suspicious</span>
          <span class="stat-value" style="color:#f59e0b;">${suspiciousCount}</span>
        </div>
        <div class="card stat-box" style="background:rgba(16, 185, 129, 0.08); border-color:rgba(16, 185, 129, 0.2);">
          <span class="stat-label" style="color:#6ee7b7;">Scanned Files</span>
          <span class="stat-value" style="color:#10b981;">${state.scannedFiles}</span>
        </div>
      </div>
    </div>

    <div class="card">
      <h3 style="margin-bottom:16px; font-weight:600; display:flex; align-items:center; gap:8px;">
        <i data-lucide="shield-alert"></i> Detected Threats & Findings
      </h3>
      <div class="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>Status</th>
              <th>File</th>
              <th>Findings & Detections</th>
              <th>SHA-256 Hash</th>
            </tr>
          </thead>
          <tbody>
            ${state.findings.length === 0 ? '<tr><td colspan="4" style="text-align:center; color:var(--text-muted); padding:32px;">No threats found in current scan.</td></tr>' : ''}
            ${state.findings.map(f => `
              <tr>
                <td>
                  <span class="badge badge-${f.verdict.toLowerCase()}">${f.verdict}</span>
                </td>
                <td style="font-family:var(--font-mono); font-size:0.85rem; max-width:300px; word-break:break-all;">
                  ${f.file_path}
                </td>
                <td>
                  ${f.findings.map(finding => `
                    <div style="margin-bottom:4px;">
                      <strong style="color:var(--warning)">[${finding.detector_id}]</strong> ${finding.description}
                      ${finding.matched_value ? `<div style="font-family:var(--font-mono); font-size:0.75rem; color:var(--text-muted); margin-top:2px;">Matched: ${finding.matched_value}</div>` : ''}
                    </div>
                  `).join('')}
                </td>
                <td style="font-family:var(--font-mono); font-size:0.75rem; color:var(--text-dim);">
                  ${f.sha256 ? f.sha256.substring(0, 16) + '...' : '-'}
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

function renderQuarantine() {
  return `
    <div class="card">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
        <div>
          <h2 style="font-weight:600; display:flex; align-items:center; gap:10px;">
            <i data-lucide="box" style="color:var(--danger)"></i> Quarantine Management
          </h2>
          <div style="color:var(--text-muted); font-size:0.9rem; margin-top:4px;">Isolated files have been safely moved to quarantine.</div>
        </div>
      </div>

      <div class="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>Original Path</th>
              <th>Verdict</th>
              <th>Date</th>
              <th>SHA-256 Hash</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            ${state.quarantineItems.length === 0 ? '<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:32px;">No files currently in quarantine.</td></tr>' : ''}
            ${state.quarantineItems.map(item => `
              <tr>
                <td style="font-family:var(--font-mono); font-size:0.85rem;">${item.original_path}</td>
                <td><span class="badge badge-${item.verdict.toLowerCase()}">${item.verdict}</span></td>
                <td style="font-size:0.85rem; color:var(--text-muted);">${new Date(item.timestamp).toLocaleString()}</td>
                <td style="font-family:var(--font-mono); font-size:0.75rem; color:var(--text-dim);">${item.sha256.substring(0, 16)}...</td>
                <td>
                  <button class="btn btn-sm btn-secondary" onclick="restoreFile('${item.sha256}')">
                    <i data-lucide="rotate-ccw"></i> Restore
                  </button>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

async function toggleRule(ruleId) {
  const disabled = state.config.disabled_rules || [];
  let updated;
  if (disabled.includes(ruleId)) {
    updated = disabled.filter(id => id !== ruleId);
    showToast(`Rule ${ruleId} enabled`, 'success');
  } else {
    updated = [...disabled, ruleId];
    showToast(`Rule ${ruleId} disabled`, 'info');
  }
  state.config.disabled_rules = updated;
  try {
    await fetch('/system/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ disabled_rules: updated }),
    });
  } catch (err) {
    showToast('Failed to save rule settings', 'error');
  }
  renderApp();
}

function renderRules() {
  const disabledList = state.config.disabled_rules || [];

  return `
    <div class="card">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
        <div>
          <h2 style="font-weight:600; display:flex; align-items:center; gap:10px;">
            <i data-lucide="file-code" style="color:var(--primary)"></i> Active Threat Rule Packs & Signatures
          </h2>
          <div style="color:var(--text-muted); font-size:0.9rem; margin-top:4px;">Click toggles to enable or disable individual detection rules.</div>
        </div>
        <button class="btn btn-primary" onclick="triggerRuleUpdate()">
          <i data-lucide="download-cloud"></i> Update Signatures
        </button>
      </div>

      <div class="grid-2">
        ${state.rules.map(pack => `
          <div class="card" style="background:rgba(255,255,255,0.02);">
            <div style="font-weight:600; font-size:1.1rem; margin-bottom:12px; color:var(--primary); display:flex; justify-content:space-between; align-items:center;">
              <span>Pack: ${pack.pack_id}</span>
              <span class="badge badge-clean" style="font-size:0.7rem;">${pack.rule_count} Rules</span>
            </div>
            <div style="display:flex; flex-direction:column; gap:8px;">
              ${pack.rules.map(r => {
                const isEnabled = !disabledList.includes(r.id);
                return `
                  <div style="padding:10px 12px; background:rgba(0,0,0,0.3); border-radius:8px; font-size:0.85rem; border:1px solid ${isEnabled ? 'rgba(99, 102, 241, 0.2)' : 'rgba(255,255,255,0.05)'}; opacity:${isEnabled ? '1' : '0.5'}; transition:all 0.2s;">
                    <div style="font-weight:600; color:var(--text-main); display:flex; justify-content:space-between; align-items:center;">
                      <label style="display:flex; align-items:center; gap:10px; cursor:pointer;">
                        <input type="checkbox" ${isEnabled ? 'checked' : ''} onchange="toggleRule('${r.id}')" style="accent-color:var(--primary); width:16px; height:16px;">
                        <span>${r.id} <span style="font-size:0.75rem; color:var(--text-muted);">(${r.family})</span></span>
                      </label>
                      <span class="badge badge-${r.severity === 'critical' || r.severity === 'high' ? 'malicious' : 'suspicious'}" style="font-size:0.65rem;">${r.severity}</span>
                    </div>
                    <div style="color:var(--text-muted); margin-top:6px; margin-left:26px; font-size:0.8rem;">${r.description}</div>
                  </div>
                `;
              }).join('')}
            </div>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

function renderSettings() {
  return `
    <div class="card" style="max-width:700px;">
      <h2 style="font-weight:600; margin-bottom:20px; display:flex; align-items:center; gap:10px;">
        <i data-lucide="settings" style="color:var(--primary)"></i> Scanner Settings
      </h2>

      <form onsubmit="saveConfig(event)">
        <div style="margin-bottom:20px;">
          <label style="display:block; font-weight:500; margin-bottom:8px;">Parallel Workers (max_workers)</label>
          <input type="number" name="max_workers" class="input-field" value="${state.config.max_workers || 4}" min="1" max="32" style="width:100px;">
          <div style="color:var(--text-dim); font-size:0.8rem; margin-top:4px;">Number of parallel threads for file scanning.</div>
        </div>

        <div style="margin-bottom:20px;">
          <label style="display:flex; align-items:center; gap:10px; cursor:pointer;">
            <input type="checkbox" name="quarantine_malicious" ${state.config.quarantine_malicious ? 'checked' : ''}>
            <span style="font-weight:500;">Automatically move malicious files to quarantine</span>
          </label>
        </div>

        <div style="margin-bottom:24px;">
          <label style="display:flex; align-items:center; gap:10px; cursor:pointer;">
            <input type="checkbox" name="quarantine_suspicious" ${state.config.quarantine_suspicious ? 'checked' : ''}>
            <span style="font-weight:500;">Also move suspicious files to quarantine</span>
          </label>
        </div>

        <button type="submit" class="btn btn-primary">
          <i data-lucide="save"></i> Save Settings
        </button>
      </form>
    </div>
  `;
}

// Render Directory Picker Modal
function renderPickerModal() {
  return `
    <div class="modal-overlay" onclick="closePickerModal()">
      <div class="modal-card" onclick="event.stopPropagation()">
        <div class="modal-header">
          <div class="modal-title">
            <i data-lucide="folder-search" style="color:var(--primary)"></i> Select Scan Targets
          </div>
          <button class="btn btn-sm btn-secondary" onclick="closePickerModal()"><i data-lucide="x"></i></button>
        </div>

        <div class="modal-body">
          <div class="path-bar" style="display:flex; gap:8px;">
            <input type="text" id="custom-path-input" class="input-field" style="flex:1;" value="${state.pickerPath}">
            <button class="btn btn-secondary" onclick="fetchBrowsePath(document.getElementById('custom-path-input').value)">
              <i data-lucide="corner-down-left"></i> Open
            </button>
            <button class="btn btn-primary" onclick="addPathToQueue(document.getElementById('custom-path-input').value)">
              <i data-lucide="plus"></i> Add Path
            </button>
          </div>

          <div class="browser-list" style="margin-top:12px;">
            ${state.pickerItems.map(item => `
              <div class="browser-item" style="display:flex; align-items:center; justify-content:space-between; gap:10px;">
                <div style="display:flex; align-items:center; gap:10px; flex:1; cursor:pointer; overflow:hidden;" onclick="fetchBrowsePath('${item.path.replace(/\\/g, '/')}')">
                  <i data-lucide="${item.is_dir ? 'folder' : 'file-archive'}" style="color:${item.is_dir ? 'var(--primary)' : 'var(--warning)'}"></i>
                  <span style="font-family:var(--font-mono); font-size:0.85rem; text-overflow:ellipsis; overflow:hidden; white-space:nowrap;">${item.name}</span>
                  ${item.is_archive ? '<span class="badge badge-suspicious">Mod Archive</span>' : ''}
                </div>
                ${!item.is_parent ? `
                  <button class="btn btn-sm btn-secondary" onclick="event.stopPropagation(); addPathToQueue('${item.path.replace(/\\/g, '/')}')">
                    <i data-lucide="plus"></i> Add
                  </button>
                ` : ''}
              </div>
            `).join('')}
          </div>

          ${state.selectedScanPaths.length > 0 ? `
            <div style="margin-top:16px; padding:12px; background:rgba(99, 102, 241, 0.08); border:1px solid rgba(99, 102, 241, 0.2); border-radius:8px;">
              <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                <span style="font-weight:600; font-size:0.85rem; color:var(--primary);">Queued Targets (${state.selectedScanPaths.length})</span>
                <button class="btn btn-sm btn-secondary" style="font-size:0.75rem;" onclick="clearQueue()">Clear All</button>
              </div>
              <div style="display:flex; flex-wrap:wrap; gap:6px; max-height:100px; overflow-y:auto;">
                ${state.selectedScanPaths.map(p => `
                  <span class="badge badge-clean" style="font-family:var(--font-mono); font-size:0.75rem; display:flex; align-items:center; gap:6px; background:rgba(255,255,255,0.08);">
                    ${p}
                    <i data-lucide="x" style="cursor:pointer; width:12px; height:12px;" onclick="removePathFromQueue('${p}')"></i>
                  </span>
                `).join('')}
              </div>
            </div>
          ` : ''}
        </div>

        <div class="modal-footer" style="display:flex; justify-content:space-between; align-items:center; margin-top:16px;">
          <button class="btn btn-secondary" onclick="closePickerModal()">Cancel</button>
          <button class="btn btn-primary" onclick="startSelectedScan()">
            <i data-lucide="play"></i> Start Scan (${state.selectedScanPaths.length > 0 ? `${state.selectedScanPaths.length} Target(s)` : 'Current Folder'})
          </button>
        </div>
      </div>
    </div>
  `;
}

function startSelectedScan() {
  let targets = [...state.selectedScanPaths];
  if (targets.length === 0 && state.pickerPath) {
    targets = [state.pickerPath];
  }
  if (targets.length === 0) {
    showToast('Please select at least one directory or file to scan.', 'info');
    return;
  }
  state.selectedScanPaths = [];
  closePickerModal();
  startScan(targets);
}

function attachEvents() {
  // Global helper functions attached to window for inline handlers
  window.setTab = setTab;
  window.openPickerModal = openPickerModal;
  window.closePickerModal = closePickerModal;
  window.fetchBrowsePath = fetchBrowsePath;
  window.startScan = startScan;
  window.startSelectedScan = startSelectedScan;
  window.triggerRuleUpdate = triggerRuleUpdate;
  window.toggleRule = toggleRule;
  window.saveConfig = saveConfig;
  window.restoreFile = restoreFile;
  window.addPathToQueue = addPathToQueue;
  window.removePathFromQueue = removePathFromQueue;
  window.clearQueue = clearQueue;
}
