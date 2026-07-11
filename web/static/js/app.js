/* pi-nat64 — frontend JS */

// ── CSRF token ────────────────────────────────────────────────────────────────
function getCsrfToken() {
  return document.querySelector('meta[name="csrf-token"]')?.content || '';
}

function csrfHeaders(extra) {
  return Object.assign({ 'X-CSRF-Token': getCsrfToken() }, extra);
}

// ── Event delegation ───────────────────────────────────────────────────────────
// The CSP (script-src 'self', no 'unsafe-inline') blocks inline on* handlers, so
// all click/Enter actions are wired here via data-action / data-enter-action.
document.addEventListener('click', e => {
  const el = e.target.closest('[data-action]');
  if (!el) return;
  const { action, id, mac, domain } = el.dataset;
  switch (action) {
    case 'update-gravity':   updateGravity(); break;
    case 'add-adlist':       addAdlist(); break;
    case 'toggle-adlist':    toggleAdlist(Number(id)); break;
    case 'delete-adlist':    deleteAdlist(Number(id)); break;
    case 'add-whitelist':    addToWhitelist(); break;
    case 'remove-whitelist': removeFromWhitelist(domain); break;
    case 'refresh-clients':  loadClients(); break;
    case 'block-client':     blockClient(mac); break;
    case 'unblock-client':   unblockClient(mac); break;
    case 'toggle-rule':      toggleRule(Number(id)); break;
    case 'delete-rule':      deleteRule(Number(id)); break;
  }
});

document.addEventListener('keydown', e => {
  if (e.key !== 'Enter') return;
  const el = e.target.closest('[data-enter-action]');
  if (!el) return;
  if (el.dataset.enterAction === 'add-adlist')    addAdlist();
  if (el.dataset.enterAction === 'add-whitelist') addToWhitelist();
});

// ── Tab navigation ──────────────────────────────────────────────────────────
document.querySelectorAll('.nav-item[data-tab]').forEach(link => {
  link.addEventListener('click', e => {
    e.preventDefault();
    const tab = link.dataset.tab;
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    link.classList.add('active');
    document.getElementById('tab-' + tab)?.classList.add('active');
    if (tab === 'status')   loadStatus();
    if (tab === 'portfwd')  loadRules();
    if (tab === 'settings') loadSettings();
    if (tab === 'blocking') loadBlocking();
    if (tab === 'clients')  loadClients();
  });
});

// ── Status ───────────────────────────────────────────────────────────────────
async function loadStatus() {
  try {
    const res = await fetch('/api/status');
    const d = await res.json();

    setText('nat64-count', d.nat64_sessions);
    setText('dns-count',   d.dns_queries);
    setText('ap-count',    d.ap_clients);

    setDot('svc-jool',    d.jool_running);
    setDot('svc-unbound', d.unbound_running);
    setDot('svc-hostapd', d.hostapd_running);
    setDot('svc-pihole',  d.pihole_running);

    const all = d.jool_running && d.unbound_running && d.hostapd_running && d.pihole_running;
    const st = document.getElementById('overall-status');
    if (st) {
      st.innerHTML = all
        ? '<span class="dot dot-green"></span><span>All services online</span>'
        : '<span class="dot dot-yellow"></span><span>Some services offline</span>';
    }
  } catch (err) {
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

// ── Port forwarding ───────────────────────────────────────────────────────────
async function loadRules() {
  const res = await fetch('/api/rules');
  const rules = await res.json();
  renderRules(rules);
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
      <td><span class="pill pill-${r.proto.toLowerCase()}">${r.proto}</span></td>
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
  await fetch(`/api/rules/${id}/toggle`, { method: 'POST', headers: csrfHeaders() });
  loadRules();
}

async function deleteRule(id) {
  if (!confirm('Delete this rule?')) return;
  await fetch(`/api/rules/${id}`, { method: 'DELETE', headers: csrfHeaders() });
  loadRules();
}

// Add-rule modal
document.getElementById('open-add-rule')?.addEventListener('click', () => {
  document.getElementById('add-rule-modal').style.display = 'flex';
});

['close-add-rule', 'cancel-add-rule'].forEach(id => {
  document.getElementById(id)?.addEventListener('click', closeAddModal);
});

function closeAddModal() {
  document.getElementById('add-rule-modal').style.display = 'none';
  document.getElementById('rule-error').style.display = 'none';
}

document.getElementById('save-rule')?.addEventListener('click', async () => {
  const body = {
    name:      document.getElementById('rule-name').value.trim(),
    proto:     document.getElementById('rule-proto').value,
    ext_port:  document.getElementById('rule-ext-port').value,
    dest_ip:   document.getElementById('rule-dest-ip').value.trim(),
    dest_port: document.getElementById('rule-dest-port').value,
  };

  const errEl = document.getElementById('rule-error');

  if (!body.name || !body.dest_ip || !body.ext_port || !body.dest_port) {
    errEl.textContent = 'All fields are required.';
    errEl.style.display = 'block';
    return;
  }

  const res = await fetch('/api/rules', {
    method: 'POST',
    headers: csrfHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(body),
  });

  if (res.ok) {
    closeAddModal();
    loadRules();
  } else {
    const d = await res.json();
    errEl.textContent = d.error || 'Failed to save rule.';
    errEl.style.display = 'block';
  }
});

// ── Settings ─────────────────────────────────────────────────────────────────
async function loadSettings() {
  const res = await fetch('/api/settings');
  const d = await res.json();
  setVal('cfg-ssid',        d.ssid);
  setVal('cfg-channel',     d.channel);
  setVal('cfg-jool',        d.jool_prefix);
  setVal('cfg-upstream-dns',d.upstream_dns);
}

function setVal(id, val) {
  const el = document.getElementById(id);
  if (el) el.value = val ?? '';
}

document.getElementById('save-settings')?.addEventListener('click', async () => {
  const body = {
    ssid:           document.getElementById('cfg-ssid').value.trim(),
    channel:        document.getElementById('cfg-channel').value,
    wpa_passphrase: document.getElementById('cfg-pass').value,
    new_password:   document.getElementById('cfg-new-pass').value,
  };

  const msgEl = document.getElementById('settings-msg');
  const res = await fetch('/api/settings', {
    method: 'POST',
    headers: csrfHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(body),
  });

  msgEl.style.display = 'block';
  if (res.ok) {
    msgEl.className = 'alert alert-success';
    msgEl.textContent = 'Settings saved. hostapd restarted.';
  } else {
    const d = await res.json();
    msgEl.className = 'alert alert-error';
    msgEl.textContent = d.error || 'Failed to save settings.';
  }
  setTimeout(() => { msgEl.style.display = 'none'; }, 4000);
});

// ── Blocking (Pi-hole) ────────────────────────────────────────────────────────
async function loadBlocking() {
  try {
    const res = await fetch('/api/pihole/stats');
    const d = await res.json();

    setText('ph-queries', d.queries_today.toLocaleString());
    setText('ph-blocked',  d.blocked_today.toLocaleString());
    setText('ph-pct',      d.block_pct.toFixed(1));
    setText('ph-gravity',  d.domains_blocked.toLocaleString());

    const dot  = document.getElementById('ph-status-dot');
    const text = document.getElementById('ph-status-text');
    if (dot && text) {
      const on = d.status === 'enabled';
      dot.className = 'dot ' + (on ? 'dot-green' : 'dot-red');
      text.textContent = on ? 'Blocking enabled' : 'Blocking disabled';
    }

    const btn = document.getElementById('pihole-toggle-btn');
    if (btn) btn.textContent = d.status === 'enabled' ? 'Disable blocking' : 'Enable blocking';
  } catch (err) {
    console.error('Pi-hole stats fetch failed', err);
  }

  try {
    const res = await fetch('/api/pihole/top-blocked');
    const items = await res.json();
    const list = document.getElementById('ph-top-list');
    if (!list) return;
    if (!items.length) {
      list.innerHTML = '<p class="field-hint">No blocked domains yet.</p>';
      return;
    }
    list.innerHTML = items.map(i => `
      <div class="service-row">
        <span class="svc-name">${escHtml(i.domain)}</span>
        <span class="svc-desc">${i.count.toLocaleString()} blocked</span>
      </div>`).join('');
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
    const res   = await fetch('/api/pihole/adlists');
    const lists = await res.json();

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
            <td style="text-align:right;font-size:12px">${l.domains ? l.domains.toLocaleString() : '—'}</td>
            <td><span class="pill ${l.enabled ? 'pill-on' : 'pill-off'}">${l.enabled ? 'enabled' : 'disabled'}</span></td>
            <td>
              <div class="action-row">
                <button class="btn btn-sm" data-action="toggle-adlist" data-id="${l.id}">${l.enabled ? 'Disable' : 'Enable'}</button>
                <button class="btn btn-sm btn-danger" data-action="delete-adlist" data-id="${l.id}">✕</button>
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

  const res = await fetch('/api/pihole/adlists', {
    method: 'POST',
    headers: csrfHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ url, comment }),
  });
  const d = await res.json();

  if (res.ok) {
    document.getElementById('adlist-url').value     = '';
    document.getElementById('adlist-comment').value = '';
    msg.style.color   = 'var(--accent)';
    msg.textContent   = 'Adlist added. Run "Update gravity" to activate it.';
    loadAdlists();
  } else {
    msg.style.color = 'var(--danger)';
    msg.textContent = d.error || 'Failed to add adlist.';
  }
  setTimeout(() => { msg.textContent = ''; }, 5000);
}

async function deleteAdlist(id) {
  const msg = document.getElementById('adlist-msg');
  const res = await fetch('/api/pihole/adlists', {
    method: 'DELETE',
    headers: csrfHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ id }),
  });
  if (res.ok) {
    msg.style.color = 'var(--accent)';
    msg.textContent = 'Adlist removed. Run "Update gravity" to apply.';
    setTimeout(() => { msg.textContent = ''; }, 5000);
    loadAdlists();
  }
}

async function toggleAdlist(id) {
  const res = await fetch('/api/pihole/adlists/toggle', {
    method: 'POST',
    headers: csrfHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ id }),
  });
  if (res.ok) loadAdlists();
}

async function updateGravity() {
  const btn = document.getElementById('gravity-btn');
  const msg = document.getElementById('adlist-msg');
  btn.disabled    = true;
  btn.textContent = 'Updating…';
  msg.style.color = 'var(--muted)';
  msg.textContent = 'Gravity update started — this may take a few minutes.';

  await fetch('/api/pihole/gravity', { method: 'POST', headers: csrfHeaders() });

  // Re-enable after 60 s (enough time for gravity to finish on most systems)
  setTimeout(() => {
    btn.disabled    = false;
    btn.innerHTML   = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg> Update gravity';
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
    const res = await fetch('/api/pihole/whitelist');
    const domains = await res.json();
    if (!domains.length) {
      list.innerHTML = '<p class="field-hint">No domains whitelisted yet.</p>';
      return;
    }
    list.innerHTML = domains.map(d => `
      <div class="service-row">
        <span class="svc-name" style="flex:1">${escHtml(d)}</span>
        <button class="btn btn-sm btn-danger" data-action="remove-whitelist" data-domain="${escHtml(d)}">Remove</button>
      </div>`).join('');
  } catch (err) {
    list.innerHTML = '<p class="field-hint">Failed to load whitelist.</p>';
  }
}

async function addToWhitelist() {
  const input = document.getElementById('wl-input');
  const msg   = document.getElementById('wl-msg');
  const domain = input.value.trim().toLowerCase();
  if (!domain) return;

  const res = await fetch('/api/pihole/whitelist', {
    method: 'POST',
    headers: csrfHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ domain }),
  });
  const d = await res.json();

  if (res.ok) {
    input.value = '';
    msg.style.color = 'var(--accent)';
    msg.textContent = `${domain} added to whitelist.`;
    loadWhitelist();
  } else {
    msg.style.color = 'var(--danger)';
    msg.textContent = d.error || 'Failed to add domain.';
  }
  setTimeout(() => { msg.textContent = ''; }, 4000);
}

async function removeFromWhitelist(domain) {
  const msg = document.getElementById('wl-msg');
  const res = await fetch('/api/pihole/whitelist', {
    method: 'DELETE',
    headers: csrfHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ domain }),
  });
  const d = await res.json();

  if (res.ok) {
    msg.style.color = 'var(--accent)';
    msg.textContent = `${domain} removed from whitelist.`;
    loadWhitelist();
  } else {
    msg.style.color = 'var(--danger)';
    msg.textContent = d.error || 'Failed to remove domain.';
  }
  setTimeout(() => { msg.textContent = ''; }, 4000);
}

document.getElementById('pihole-toggle-btn')?.addEventListener('click', async () => {
  const msg = document.getElementById('pihole-toggle-msg');
  try {
    const res = await fetch('/api/pihole/toggle', { method: 'POST', headers: csrfHeaders() });
    const d = await res.json();
    if (!res.ok) throw new Error(d.error || 'Failed');
    if (msg) msg.textContent = d.status === 'enabled' ? 'Blocking enabled.' : 'Blocking disabled.';
    loadBlocking();
  } catch (err) {
    if (msg) msg.textContent = String(err);
  }
  setTimeout(() => { if (msg) msg.textContent = ''; }, 4000);
});

// ── Helpers ──────────────────────────────────────────────────────────────────
function escHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

// ── Clients ───────────────────────────────────────────────────────────────────
async function loadClients() {
  try {
    const res     = await fetch('/api/clients');
    const clients = await res.json();
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

async function blockClient(mac) {
  const res = await fetch('/api/clients/block', {
    method: 'POST',
    headers: csrfHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ mac }),
  });
  if (res.ok) loadClients();
  else {
    const d = await res.json();
    alert(d.error || 'Failed to block client.');
  }
}

async function unblockClient(mac) {
  const res = await fetch('/api/clients/unblock', {
    method: 'POST',
    headers: csrfHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ mac }),
  });
  if (res.ok) loadClients();
  else {
    const d = await res.json();
    alert(d.error || 'Failed to unblock client.');
  }
}

function fmtSignal(dbm) {
  if (dbm == null) return '—';
  const cls = dbm >= -60 ? 'signal-good' : dbm >= -70 ? 'signal-ok' : 'signal-weak';
  return `<span class="${cls}">${dbm} dBm</span>`;
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
  const btn = document.getElementById('confirm-reboot');
  btn.textContent = 'Rebooting…';
  btn.disabled = true;
  document.getElementById('cancel-reboot').disabled = true;

  try {
    await fetch('/api/reboot', { method: 'POST', headers: csrfHeaders() });
  } catch (_) { /* connection drop is expected */ }

  document.getElementById('reboot-modal').innerHTML = `
    <div class="modal" style="text-align:center">
      <p style="font-size:15px;font-weight:600;margin-bottom:10px">Rebooting…</p>
      <p class="field-hint">The page will reload automatically when the gateway comes back online.</p>
    </div>`;

  // Wait 20 s for shutdown, then poll until /api/status responds again
  setTimeout(() => {
    const poll = setInterval(async () => {
      try {
        const res = await fetch('/api/status');
        if (res.ok) { clearInterval(poll); location.reload(); }
      } catch (_) {}
    }, 3000);
  }, 20000);
});

// ── Init ─────────────────────────────────────────────────────────────────────
loadStatus();
setInterval(loadStatus, 10000);
