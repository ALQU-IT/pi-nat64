/* pi-nat64 — frontend JS */

// ── API helper ────────────────────────────────────────────────────────────────
// Every request goes through api(): it adds the CSRF header, sends JSON, and
// turns anything that isn't a 2xx JSON response into a thrown Error with the
// server's message. An expired session (401, or a redirect to /login) sends the
// browser to the login page instead of silently "succeeding" on the login HTML.
function getCsrfToken() {
  return document.querySelector('meta[name="csrf-token"]')?.content || '';
}

async function api(url, { method = 'GET', body, timeout } = {}) {
  const opts = { method, headers: {} };
  if (method !== 'GET') opts.headers['X-CSRF-Token'] = getCsrfToken();
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  if (timeout) opts.signal = AbortSignal.timeout(timeout);

  const res = await fetch(url, opts);
  if (res.status === 401 || res.redirected) {
    location.href = '/login';
    throw new Error('Session expired — please log in again.');
  }
  let data = null;
  try { data = await res.json(); } catch (_) { /* non-JSON body */ }
  if (!res.ok) throw new Error((data && data.error) || `Request failed (HTTP ${res.status})`);
  if (data === null) throw new Error('Unexpected response from the server.');
  return data;
}

function flash(el, text, kind, ms = 4000) {
  if (!el) return;
  el.style.color = kind === 'error' ? 'var(--danger)'
                 : kind === 'muted' ? 'var(--muted)' : 'var(--accent)';
  el.textContent = text;
  clearTimeout(el._flashTimer);
  if (ms) el._flashTimer = setTimeout(() => { el.textContent = ''; }, ms);
}

// Run fn with the button disabled, so double-clicks can't fire a request twice
// (e.g. two identical ip6tables DNAT rules for one port-forward).
async function withBusy(btn, fn) {
  if (btn && btn.disabled) return;
  if (btn) btn.disabled = true;
  try { await fn(); }
  finally { if (btn && btn.isConnected) btn.disabled = false; }
}

// ── Event delegation ───────────────────────────────────────────────────────────
// The CSP (script-src 'self', no 'unsafe-inline') blocks inline on* handlers, so
// all click/Enter actions are wired here via data-action / data-enter-action.
const ACTIONS = {
  'update-gravity':   ()   => updateGravity(),
  'add-adlist':       ()   => addAdlist(),
  'toggle-adlist':    (ds) => toggleAdlist(Number(ds.id)),
  'delete-adlist':    (ds) => deleteAdlist(Number(ds.id)),
  'add-whitelist':    ()   => addToWhitelist(),
  'remove-whitelist': (ds) => removeFromWhitelist(ds.domain),
  'refresh-clients':  ()   => loadClients(),
  'block-client':     (ds) => setClientBlocked(ds.mac, true),
  'unblock-client':   (ds) => setClientBlocked(ds.mac, false),
  'toggle-rule':      (ds) => toggleRule(Number(ds.id)),
  'delete-rule':      (ds) => deleteRule(Number(ds.id)),
};

document.addEventListener('click', e => {
  const el = e.target.closest('[data-action]');
  if (!el || !ACTIONS[el.dataset.action]) return;
  // update-gravity manages its own (longer) busy state
  if (el.dataset.action === 'update-gravity') { ACTIONS['update-gravity'](); return; }
  withBusy(el, () => ACTIONS[el.dataset.action](el.dataset));
});

document.addEventListener('keydown', e => {
  if (e.key === 'Escape') { closeModals(); return; }
  if (e.key !== 'Enter') return;
  const el = e.target.closest('[data-enter-action]');
  if (!el || !ACTIONS[el.dataset.enterAction]) return;
  e.preventDefault();
  ACTIONS[el.dataset.enterAction](el.dataset);
});

function closeModals() {
  const reboot = document.getElementById('reboot-modal');
  if (reboot && !reboot.dataset.rebooting) reboot.style.display = 'none';
  const upd = document.getElementById('update-modal');
  if (upd && !upd.dataset.updating) upd.style.display = 'none';
  if (document.getElementById('add-rule-modal')?.style.display === 'flex') closeAddModal();
}

// Clicking the dimmed backdrop (not the dialog itself) closes a modal
document.querySelectorAll('.modal-backdrop').forEach(bd => {
  bd.addEventListener('click', e => { if (e.target === bd) closeModals(); });
});

// ── Tab navigation ──────────────────────────────────────────────────────────
let activeTab = 'status';

document.querySelectorAll('.nav-item[data-tab]').forEach(link => {
  link.addEventListener('click', e => {
    e.preventDefault();
    const tab = link.dataset.tab;
    activeTab = tab;
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    link.classList.add('active');
    document.getElementById('tab-' + tab)?.classList.add('active');
    if (tab === 'status')   loadStatus();
    if (tab === 'portfwd')  loadRules();
    if (tab === 'settings') loadSettings();
    if (tab === 'blocking') loadBlocking();
    if (tab === 'clients')  loadClients();
    syncPolling();
  });
});

// ── Status ───────────────────────────────────────────────────────────────────
function setOverall(dotClass, text) {
  const st = document.getElementById('overall-status');
  if (!st) return;
  st.innerHTML = `<span class="dot ${dotClass}"></span><span></span>`;
  st.lastElementChild.textContent = text;
}

async function loadStatus() {
  try {
    const d = await api('/api/status', { timeout: 8000 });

    setText('nat64-count', d.nat64_sessions);
    setText('dns-count',   d.dns_queries);
    setText('ap-count',    d.ap_clients);

    setDot('svc-jool',    d.jool_running);
    setDot('svc-unbound', d.unbound_running);
    setDot('svc-hostapd', d.hostapd_running);
    setDot('svc-pihole',  d.pihole_running);

    const all = d.jool_running && d.unbound_running && d.hostapd_running && d.pihole_running;
    setOverall(all ? 'dot-green' : 'dot-yellow', all ? 'All services online' : 'Some services offline');
  } catch (err) {
    setOverall('dot-red', 'Status unavailable');
    console.error('Status fetch failed', err);
  }
}

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function setDot(id, active) {
  const el = document.getElementById(id);
  if (!el) return;
  el.className = 'dot ' + (active ? 'dot-green' : 'dot-red');
}

// Poll only while the Status tab is showing and the browser tab is visible.
// An endless background poll wastes the Pi's CPU (each poll runs several
// systemctl/jool/iw calls) and keeps an idle session alive forever.
let statusTimer = null;
function syncPolling() {
  const want = activeTab === 'status' && document.visibilityState === 'visible';
  if (want && !statusTimer) {
    statusTimer = setInterval(loadStatus, 10000);
  } else if (!want && statusTimer) {
    clearInterval(statusTimer);
    statusTimer = null;
  }
}
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible' && activeTab === 'status') loadStatus();
  syncPolling();
});

// ── Port forwarding ───────────────────────────────────────────────────────────
async function loadRules() {
  try {
    renderRules(await api('/api/rules'));
  } catch (err) {
    alert('Failed to load rules: ' + err.message);
  }
}

function renderRules(rules) {
  const tbody = document.getElementById('rules-body');
  const empty = document.getElementById('rules-empty');
  const wrap  = document.getElementById('rules-table-wrap');
  if (!tbody) return;

  if (rules.length === 0) {
    if (empty) empty.style.display = 'block';
    if (wrap)  wrap.style.display  = 'none';
    return;
  }
  if (empty) empty.style.display = 'none';
  if (wrap)  wrap.style.display  = 'block';

  tbody.innerHTML = rules.map(r => `
    <tr data-id="${r.id}">
      <td>${escHtml(r.name)}</td>
      <td><span class="pill pill-${escHtml(r.proto.toLowerCase())}">${escHtml(r.proto)}</span></td>
      <td>${r.ext_port}</td>
      <td><code>${escHtml(r.dest_ip)}</code></td>
      <td>${r.dest_port}</td>
      <td><span class="pill ${r.enabled ? 'pill-on' : 'pill-off'}">${r.enabled ? 'on' : 'off'}</span></td>
      <td>
        <div class="action-row">
          <button class="btn btn-sm" data-action="toggle-rule" data-id="${r.id}">${r.enabled ? 'Disable' : 'Enable'}</button>
          <button class="btn btn-sm btn-danger" data-action="delete-rule" data-id="${r.id}">Delete</button>
        </div>
      </td>
    </tr>
  `).join('');
}

async function toggleRule(id) {
  try {
    await api(`/api/rules/${id}/toggle`, { method: 'POST' });
  } catch (err) {
    alert(err.message);
  }
  loadRules();
}

async function deleteRule(id) {
  if (!confirm('Delete this rule?')) return;
  try {
    await api(`/api/rules/${id}`, { method: 'DELETE' });
  } catch (err) {
    alert(err.message);
  }
  loadRules();
}

// Add-rule modal
document.getElementById('open-add-rule')?.addEventListener('click', () => {
  document.getElementById('add-rule-modal').style.display = 'flex';
  document.getElementById('rule-name')?.focus();
});

['close-add-rule', 'cancel-add-rule'].forEach(id => {
  document.getElementById(id)?.addEventListener('click', closeAddModal);
});

function closeAddModal() {
  document.getElementById('add-rule-modal').style.display = 'none';
  document.getElementById('rule-error').style.display = 'none';
  ['rule-name', 'rule-ext-port', 'rule-dest-ip', 'rule-dest-port'].forEach(id => setVal(id, ''));
}

document.getElementById('save-rule')?.addEventListener('click', e => withBusy(e.currentTarget, async () => {
  const body = {
    name:      document.getElementById('rule-name').value.trim(),
    proto:     document.getElementById('rule-proto').value,
    ext_port:  document.getElementById('rule-ext-port').value,
    dest_ip:   document.getElementById('rule-dest-ip').value.trim(),
    dest_port: document.getElementById('rule-dest-port').value,
  };

  const errEl = document.getElementById('rule-error');
  const showErr = text => { errEl.textContent = text; errEl.style.display = 'block'; };

  if (!body.name || !body.dest_ip || !body.ext_port || !body.dest_port) {
    showErr('All fields are required.');
    return;
  }

  try {
    await api('/api/rules', { method: 'POST', body });
    closeAddModal();
    loadRules();
  } catch (err) {
    showErr(err.message);
  }
}));

// ── Settings ─────────────────────────────────────────────────────────────────
async function loadSettings() {
  try {
    const d = await api('/api/settings');
    setVal('cfg-ssid',         d.ssid);
    setVal('cfg-channel',      d.channel);
    setVal('cfg-jool',         d.jool_prefix);
    setVal('cfg-upstream-dns', d.upstream_dns);
  } catch (err) {
    alert('Failed to load settings: ' + err.message);
  }
}

function setVal(id, val) {
  const el = document.getElementById(id);
  if (el) el.value = val ?? '';
}

document.getElementById('save-settings')?.addEventListener('click', e => withBusy(e.currentTarget, async () => {
  const body = {
    ssid:           document.getElementById('cfg-ssid').value.trim(),
    channel:        document.getElementById('cfg-channel').value,
    wpa_passphrase: document.getElementById('cfg-pass').value,
    new_password:     document.getElementById('cfg-new-pass').value,
    current_password: document.getElementById('cfg-cur-pass').value,
  };

  const msgEl = document.getElementById('settings-msg');
  const show = (ok, text) => {
    msgEl.style.display = 'block';
    msgEl.className = 'alert ' + (ok ? 'alert-success' : 'alert-error');
    msgEl.textContent = text;
    clearTimeout(msgEl._t);
    msgEl._t = setTimeout(() => { msgEl.style.display = 'none'; }, 6000);
  };

  // Mirror the server's rules so nothing is half-applied by a rejected field
  if (body.wpa_passphrase && (body.wpa_passphrase.length < 8 || body.wpa_passphrase.length > 63)) {
    show(false, 'Wi-Fi passphrase must be 8–63 characters.');
    return;
  }
  if (body.new_password && body.new_password.length < 8) {
    show(false, 'Admin password must be at least 8 characters.');
    return;
  }
  if (body.new_password && !body.current_password) {
    show(false, 'Enter your current admin password to change it.');
    return;
  }

  try {
    const d = await api('/api/settings', { method: 'POST', body });
    ['cfg-pass', 'cfg-new-pass', 'cfg-cur-pass'].forEach(id => setVal(id, ''));
    show(true, d.ap_restarted
      ? 'Settings saved. The Wi-Fi access point restarted — reconnect if you were on it.'
      : 'Settings saved.');
  } catch (err) {
    // Restarting hostapd drops clients on the gateway's own Wi-Fi mid-request
    show(false, err instanceof TypeError
      ? 'Connection lost while the Wi-Fi restarted — reconnect and reload to check the settings.'
      : err.message);
  }
}));

// ── Blocking (Pi-hole) ────────────────────────────────────────────────────────
async function loadBlocking() {
  try {
    const d = await api('/api/pihole/stats');

    setText('ph-queries', d.queries_today.toLocaleString());
    setText('ph-blocked', d.blocked_today.toLocaleString());
    setText('ph-pct',     d.block_pct.toFixed(1));
    setText('ph-gravity', d.domains_blocked.toLocaleString());

    const dot  = document.getElementById('ph-status-dot');
    const text = document.getElementById('ph-status-text');
    const btn  = document.getElementById('pihole-toggle-btn');
    const state = {
      enabled:  ['dot-green',  'Blocking enabled',        'Disable blocking'],
      disabled: ['dot-red',    'Blocking disabled',       'Enable blocking'],
    }[d.status] || ['dot-yellow', 'Blocking status unknown', 'Enable blocking'];
    if (dot)  dot.className = 'dot ' + state[0];
    if (text) text.textContent = state[1];
    if (btn)  btn.textContent = state[2];
  } catch (err) {
    console.error('Pi-hole stats fetch failed', err);
  }

  try {
    const items = await api('/api/pihole/top-blocked');
    const list = document.getElementById('ph-top-list');
    if (list) {
      list.innerHTML = items.length
        ? items.map(i => `
          <div class="service-row">
            <span class="svc-name">${escHtml(i.domain)}</span>
            <span class="svc-desc">${Number(i.count).toLocaleString()} blocked</span>
          </div>`).join('')
        : '<p class="field-hint">No blocked domains yet.</p>';
    }
  } catch (err) {
    console.error('Pi-hole top-blocked fetch failed', err);
  }

  loadWhitelist();
  loadAdlists();
}

// ── Adlists ───────────────────────────────────────────────────────────────────
async function loadAdlists() {
  const container = document.getElementById('adlist-list');
  if (!container) return;
  try {
    const lists = await api('/api/pihole/adlists');

    if (!lists.length) {
      container.innerHTML = '<p class="field-hint">No adlists configured yet.</p>';
      return;
    }

    container.innerHTML = `
      <table class="data-table" style="margin:-1px">
        <thead>
          <tr>
            <th style="width:42%">URL</th>
            <th>Comment</th>
            <th style="width:90px;text-align:right">Domains</th>
            <th style="width:80px">Status</th>
            <th style="width:110px"></th>
          </tr>
        </thead>
        <tbody>
          ${lists.map(l => `
          <tr data-id="${l.id}">
            <td style="font-size:11px;word-break:break-all" title="${escHtml(l.url)}">${escHtml(truncate(l.url, 60))}</td>
            <td style="font-size:12px;color:var(--muted)">${escHtml(l.comment || '—')}</td>
            <td style="text-align:right;font-size:12px">${l.domains ? Number(l.domains).toLocaleString() : '—'}</td>
            <td><span class="pill ${l.enabled ? 'pill-on' : 'pill-off'}">${l.enabled ? 'enabled' : 'disabled'}</span></td>
            <td>
              <div class="action-row">
                <button class="btn btn-sm" data-action="toggle-adlist" data-id="${l.id}">${l.enabled ? 'Disable' : 'Enable'}</button>
                <button class="btn btn-sm btn-danger" data-action="delete-adlist" data-id="${l.id}" aria-label="Delete adlist">✕</button>
              </div>
            </td>
          </tr>`).join('')}
        </tbody>
      </table>`;
  } catch (err) {
    container.innerHTML = '<p class="field-hint">Failed to load adlists.</p>';
  }
}

async function addAdlist() {
  const url     = document.getElementById('adlist-url').value.trim();
  const comment = document.getElementById('adlist-comment').value.trim();
  const msg     = document.getElementById('adlist-msg');
  if (!url) return;

  try {
    await api('/api/pihole/adlists', { method: 'POST', body: { url, comment } });
    setVal('adlist-url', '');
    setVal('adlist-comment', '');
    flash(msg, 'Adlist added. Run "Update gravity" to activate it.', 'ok', 5000);
    loadAdlists();
  } catch (err) {
    flash(msg, err.message, 'error', 5000);
  }
}

async function deleteAdlist(id) {
  if (!confirm('Remove this adlist?')) return;
  const msg = document.getElementById('adlist-msg');
  try {
    await api('/api/pihole/adlists', { method: 'DELETE', body: { id } });
    flash(msg, 'Adlist removed. Run "Update gravity" to apply.', 'ok', 5000);
    loadAdlists();
  } catch (err) {
    flash(msg, err.message, 'error', 5000);
  }
}

async function toggleAdlist(id) {
  try {
    await api('/api/pihole/adlists/toggle', { method: 'POST', body: { id } });
    loadAdlists();
  } catch (err) {
    flash(document.getElementById('adlist-msg'), err.message, 'error', 5000);
  }
}

const GRAVITY_LABEL = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg> Update gravity';

async function updateGravity() {
  const btn = document.getElementById('gravity-btn');
  const msg = document.getElementById('adlist-msg');
  if (btn.disabled) return;
  btn.disabled    = true;
  btn.textContent = 'Updating…';

  try {
    await api('/api/pihole/gravity', { method: 'POST' });
  } catch (err) {
    flash(msg, err.message, 'error', 5000);
    btn.disabled  = false;
    btn.innerHTML = GRAVITY_LABEL;
    return;
  }

  flash(msg, 'Gravity update started — this may take a few minutes.', 'muted', 0);
  // Re-enable after 60 s (enough time for gravity to finish on most systems)
  setTimeout(() => {
    btn.disabled  = false;
    btn.innerHTML = GRAVITY_LABEL;
    msg.textContent = '';
    loadAdlists();   // refresh domain counts
  }, 60000);
}

function truncate(s, n) {
  return s.length > n ? s.slice(0, n) + '…' : s;
}

// ── Whitelist ─────────────────────────────────────────────────────────────────
async function loadWhitelist() {
  const list = document.getElementById('wl-list');
  if (!list) return;
  try {
    const domains = await api('/api/pihole/whitelist');
    list.innerHTML = domains.length
      ? domains.map(d => `
        <div class="service-row">
          <span class="svc-name" style="flex:1">${escHtml(d)}</span>
          <button class="btn btn-sm btn-danger" data-action="remove-whitelist" data-domain="${escHtml(d)}">Remove</button>
        </div>`).join('')
      : '<p class="field-hint">No domains whitelisted yet.</p>';
  } catch (err) {
    list.innerHTML = '<p class="field-hint">Failed to load whitelist.</p>';
  }
}

async function addToWhitelist() {
  const input  = document.getElementById('wl-input');
  const msg    = document.getElementById('wl-msg');
  const domain = input.value.trim().toLowerCase();
  if (!domain) return;

  try {
    await api('/api/pihole/whitelist', { method: 'POST', body: { domain } });
    input.value = '';
    flash(msg, `${domain} added to whitelist.`, 'ok');
    loadWhitelist();
  } catch (err) {
    flash(msg, err.message, 'error');
  }
}

async function removeFromWhitelist(domain) {
  const msg = document.getElementById('wl-msg');
  try {
    await api('/api/pihole/whitelist', { method: 'DELETE', body: { domain } });
    flash(msg, `${domain} removed from whitelist.`, 'ok');
    loadWhitelist();
  } catch (err) {
    flash(msg, err.message, 'error');
  }
}

document.getElementById('pihole-toggle-btn')?.addEventListener('click', e => withBusy(e.currentTarget, async () => {
  const msg = document.getElementById('pihole-toggle-msg');
  try {
    const d = await api('/api/pihole/toggle', { method: 'POST' });
    flash(msg, d.status === 'enabled' ? 'Blocking enabled.' : 'Blocking disabled.', 'ok');
    loadBlocking();
  } catch (err) {
    flash(msg, err.message, 'error');
  }
}));

// ── Helpers ──────────────────────────────────────────────────────────────────
function escHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

// ── Clients ───────────────────────────────────────────────────────────────────
async function loadClients() {
  try {
    const clients = await api('/api/clients');
    const tbody   = document.getElementById('clients-body');
    const empty   = document.getElementById('clients-empty');
    const wrap    = document.getElementById('clients-table-wrap');
    if (!tbody) return;

    if (!clients.length) {
      if (empty) empty.style.display = 'block';
      if (wrap)  wrap.style.display  = 'none';
      return;
    }
    if (empty) empty.style.display = 'none';
    if (wrap)  wrap.style.display  = 'block';

    tbody.innerHTML = clients.map(c => {
      const name    = escHtml(c.hostname || '—');
      const ip      = escHtml(c.ip       || '—');
      const signal  = fmtSignal(c.signal);
      const traffic = c.online
        ? `${fmtBytes(c.rx_bytes)} / ${fmtBytes(c.tx_bytes)}`
        : '—';
      const uptime  = c.online ? fmtUptime(c.connected_sec) : '—';
      const status  = c.blocked
        ? '<span class="pill pill-off">blocked</span>'
        : c.online
          ? '<span class="pill pill-on">online</span>'
          : '<span class="pill" style="background:rgba(136,136,160,0.15);color:var(--muted)">offline</span>';
      const action  = c.blocked
        ? `<button class="btn btn-sm" data-action="unblock-client" data-mac="${escHtml(c.mac)}">Unblock</button>`
        : `<button class="btn btn-sm btn-danger" data-action="block-client" data-mac="${escHtml(c.mac)}">Block</button>`;

      return `<tr>
        <td>${name}</td>
        <td><code>${escHtml(c.mac)}</code></td>
        <td><code>${ip}</code></td>
        <td>${signal}</td>
        <td style="font-size:12px">${traffic}</td>
        <td style="font-size:12px;color:var(--muted)">${uptime}</td>
        <td>${status}</td>
        <td>${action}</td>
      </tr>`;
    }).join('');
  } catch (err) {
    console.error('Clients fetch failed', err);
  }
}

async function setClientBlocked(mac, block) {
  try {
    await api(block ? '/api/clients/block' : '/api/clients/unblock', { method: 'POST', body: { mac } });
    loadClients();
  } catch (err) {
    alert(err.message);
  }
}

function fmtSignal(dbm) {
  if (dbm == null) return '—';
  const n = Number(dbm);
  const cls = n >= -60 ? 'signal-good' : n >= -70 ? 'signal-ok' : 'signal-weak';
  return `<span class="${cls}">${n} dBm</span>`;
}

function fmtBytes(b) {
  if (b == null) return '—';
  if (b < 1024)       return b + ' B';
  if (b < 1048576)    return (b / 1024).toFixed(1) + ' KB';
  if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB';
  return (b / 1073741824).toFixed(2) + ' GB';
}

function fmtUptime(sec) {
  if (sec == null) return '—';
  if (sec < 60)    return sec + 's';
  if (sec < 3600)  return Math.floor(sec / 60) + 'm ' + (sec % 60) + 's';
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  return h + 'h ' + m + 'm';
}

// ── Reboot ───────────────────────────────────────────────────────────────────
document.getElementById('reboot-btn')?.addEventListener('click', () => {
  document.getElementById('reboot-modal').style.display = 'flex';
});

['close-reboot-modal', 'cancel-reboot'].forEach(id => {
  document.getElementById(id)?.addEventListener('click', () => {
    document.getElementById('reboot-modal').style.display = 'none';
  });
});

document.getElementById('confirm-reboot')?.addEventListener('click', async () => {
  const btn    = document.getElementById('confirm-reboot');
  const cancel = document.getElementById('cancel-reboot');
  const modal  = document.getElementById('reboot-modal');
  btn.textContent = 'Rebooting…';
  btn.disabled = cancel.disabled = true;

  try {
    await api('/api/reboot', { method: 'POST', timeout: 5000 });
  } catch (err) {
    // A dropped connection is expected (the Pi is going down); a real error
    // response (403, 500, expired session) means the reboot did NOT happen.
    if (!(err instanceof TypeError) && err.name !== 'TimeoutError') {
      btn.textContent = 'Reboot';
      btn.disabled = cancel.disabled = false;
      alert('Reboot failed: ' + err.message);
      return;
    }
  }

  modal.dataset.rebooting = '1';
  modal.innerHTML = `
    <div class="modal" style="text-align:center" role="dialog" aria-modal="true">
      <p style="font-size:15px;font-weight:600;margin-bottom:10px">Rebooting…</p>
      <p class="field-hint">The page will reload automatically when the gateway comes back online.</p>
    </div>`;

  // Wait 20 s for shutdown, then poll until the UI answers again. Each probe
  // has a timeout and the next one starts only after it settles, so requests
  // can't pile up while the Pi is offline.
  const probe = async () => {
    try {
      const res = await fetch('/login', { signal: AbortSignal.timeout(2500) });
      if (res.ok) { location.reload(); return; }
    } catch (_) { /* still down */ }
    setTimeout(probe, 3000);
  };
  setTimeout(probe, 20000);
});

// ── Software update ──────────────────────────────────────────────────────────
// The Update button stays hidden unless the gateway's git checkout is behind
// its upstream branch. Applying runs update.sh on the Pi; the UI restarts
// midway, so progress is polled until the new version answers.
async function checkForUpdate() {
  try {
    const d = await api('/api/update/check');
    const btn = document.getElementById('update-btn');
    if (!btn || !d.available) return;
    btn.hidden = false;
    btn.title = `${d.behind} new change${d.behind === 1 ? '' : 's'} — latest: ${d.summary || d.latest}`;
    const sum = document.getElementById('update-summary');
    sum.textContent = '';
    const lines = [
      `${d.behind} new change${d.behind === 1 ? '' : 's'} available` +
        (d.current && d.current.commit ? ` (installed: ${d.current.commit}, latest: ${d.latest}).` : '.'),
      d.summary ? `Latest: “${d.summary}”${d.date ? ` (${d.date})` : ''}` : '',
    ];
    lines.filter(Boolean).forEach(t => {
      const p = document.createElement('p');
      p.textContent = t;
      sum.appendChild(p);
    });
  } catch (err) {
    console.warn('Update check failed', err);
  }
}

document.getElementById('update-btn')?.addEventListener('click', () => {
  document.getElementById('update-modal').style.display = 'flex';
});
['close-update-modal', 'cancel-update'].forEach(id => {
  document.getElementById(id)?.addEventListener('click', () => {
    const m = document.getElementById('update-modal');
    if (!m.dataset.updating) m.style.display = 'none';
  });
});

function updateMsg(kind, text) {
  const el = document.getElementById('update-msg');
  el.style.display = 'block';
  el.className = 'alert ' + (kind === 'error' ? 'alert-error' : kind === 'ok' ? 'alert-success' : '');
  el.textContent = text;
}

document.getElementById('confirm-update')?.addEventListener('click', async () => {
  const modal   = document.getElementById('update-modal');
  const goBtn   = document.getElementById('confirm-update');
  const cancel  = document.getElementById('cancel-update');
  goBtn.disabled = cancel.disabled = true;
  goBtn.textContent = 'Updating…';

  try {
    await api('/api/update/apply', { method: 'POST' });
  } catch (err) {
    updateMsg('error', 'Could not start the update: ' + err.message);
    goBtn.disabled = cancel.disabled = false;
    goBtn.textContent = 'Update now';
    return;
  }

  modal.dataset.updating = '1';
  updateMsg('info', 'Updating — this can take a few minutes. Keep this page open.');

  const started = Date.now();
  let sawRunning = false;
  const poll = async () => {
    let state = null;
    try {
      state = (await api('/api/update/status', { timeout: 4000 })).state;
    } catch (_) { /* UI restarting mid-update — keep polling */ }

    if (state === 'running') sawRunning = true;
    if (state === 'success' && (sawRunning || Date.now() - started > 5000)) {
      updateMsg('ok', 'Update installed — reloading…');
      setTimeout(() => location.reload(), 1500);
      return;
    }
    if (state === 'failed') {
      delete modal.dataset.updating;
      updateMsg('error', 'The update failed; the previous version is still running. ' +
                         'Details on the gateway: /var/log/pi-nat64-update.log');
      goBtn.textContent = 'Update now';
      goBtn.disabled = cancel.disabled = false;
      return;
    }
    if (Date.now() - started > 30 * 60 * 1000) {
      delete modal.dataset.updating;
      updateMsg('error', 'The update is taking unusually long. Check /var/log/pi-nat64-update.log on the gateway.');
      return;
    }
    setTimeout(poll, 3000);
  };
  setTimeout(poll, 3000);
});

// ── Init ─────────────────────────────────────────────────────────────────────
// app.js is also loaded on the login page — only start the dashboard there.
if (document.getElementById('tab-status')) {
  loadStatus();
  syncPolling();
  checkForUpdate();
}
