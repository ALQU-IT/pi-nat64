/* pi-nat64 — demo backend for the GitHub Pages demo.
 *
 * The demo page IS the real web UI (rendered by scripts/build-demo.py); this
 * script replaces fetch() for the UI's /api/... requests and answers them in
 * the browser from a simulated gateway. State lives in sessionStorage, so it
 * survives reloads (e.g. after "Update") and resets when the tab is closed.
 * Response shapes and validation mirror web/app.py.
 */
(() => {
  'use strict';

  const KEY = 'pi-nat64-demo-v2';
  const RESERVED = new Set([22, 53, 80, 443, 5335, 8053]);
  const now = () => Math.floor(Date.now() / 1000);
  const DAY_START = (() => { const d = new Date(); d.setHours(0, 0, 0, 0); return d.getTime(); })();

  function initialState() {
    return {
      wifi: { ssid: 'pi-nat64', channel: '6', hw_mode: 'g', country_code: 'DE', wpa_passphrase: 'ChangeMe123' },
      rules: [
        { id: 1, name: 'Home NAS', proto: 'TCP', ext_port: 8443, dest_ip: 'fd00::20', dest_port: 443, enabled: true },
        { id: 2, name: 'Game server', proto: 'UDP', ext_port: 27015, dest_ip: 'fd00::31', dest_port: 27015, enabled: false },
      ],
      blocked: ['3c:22:fb:91:0a:7e'],
      stations: [
        { mac: 'a4:83:e7:12:9c:01', ip: '192.168.50.23', hostname: 'alex-iphone', signal: -48, rx: 734003200, tx: 52428800, since: 15420 },
        { mac: 'f0:18:98:4b:22:6d', ip: '192.168.50.41', hostname: 'macbook-pro', signal: -57, rx: 2147483648, tx: 314572800, since: 31200 },
        { mac: 'b8:27:eb:5a:c3:10', ip: '192.168.50.57', hostname: 'living-room-tv', signal: -69, rx: 5368709120, tx: 41943040, since: 86000 },
        { mac: '60:01:94:77:ab:3c', ip: '192.168.50.72', hostname: 'thermostat', signal: -76, rx: 1048576, tx: 524288, since: 240000 },
      ],
      offline: { '3c:22:fb:91:0a:7e': { ip: '192.168.50.88', hostname: 'old-tablet' } },
      blocking: true,
      adlists: [
        { id: 1, url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', enabled: true, comment: 'Pi-hole default', domains: 174253 },
        { id: 2, url: 'https://v.firebog.net/hosts/AdguardDNS.txt', enabled: true, comment: 'AdGuard DNS', domains: 13179 },
        { id: 3, url: 'https://v.firebog.net/hosts/Easyprivacy.txt', enabled: false, comment: 'Trackers', domains: 0 },
      ],
      domains: [
        { type: 0, domain: 's.youtube.com', enabled: true, comment: '' },
        { type: 0, domain: 'clients4.google.com', enabled: true, comment: '' },
        { type: 3, domain: '(^|\\.)telemetry\\.', enabled: true, comment: 'regex deny' },
      ],
      gravityUntil: 0,
      updated: false,
      updateStarted: 0,
      nextId: 100,
    };
  }

  let state;
  try { state = JSON.parse(sessionStorage.getItem(KEY)) || initialState(); } catch (_) { state = initialState(); }
  const save = () => { try { sessionStorage.setItem(KEY, JSON.stringify(state)); } catch (_) { /* private mode */ } };

  // ── helpers ────────────────────────────────────────────────────────────────
  class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
  const bad = msg => { throw new HttpError(400, msg); };
  const gravityRunning = () => Date.now() < state.gravityUntil;
  const minutesToday = () => Math.max(1, (Date.now() - DAY_START) / 60000);
  const queriesToday = () => Math.round(minutesToday() * 21);
  const blockedToday = () => state.blocking ? Math.round(queriesToday() * 0.117) : Math.round(minutesToday() * 0.6);
  const gravityCount = () => state.adlists.filter(a => a.enabled).reduce((n, a) => n + (a.domains || 0), 0);
  const jitter = (n, pct) => Math.round(n * (1 + (Math.random() - 0.5) * pct));
  const normIPv6 = s => {
    s = String(s || '').trim().toLowerCase();
    if (!/^[0-9a-f:]+$/.test(s) || !s.includes(':') || s.length > 39 || (s.match(/::/g) || []).length > 1) return null;
    const groups = s.split(':');
    if (groups.some(g => g.length > 4) || (!s.includes('::') && groups.length !== 8)) return null;
    if (s.startsWith('ff') || s === '::' || s === '::1' || s.startsWith('fe8')) return null;
    return s;
  };
  const validDomain = d => d.length <= 253 &&
    /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(d);
  const validMac = m => /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(m);
  const str = (v, k) => { if (v != null && typeof v !== 'string') bad(`'${k}' must be a string`); return v || ''; };
  const int = (v, k) => { const n = Number(v); if (v === null || v === '' || typeof v === 'boolean' || !Number.isInteger(n)) bad(`Invalid ${k}`); return n; };

  function validateRule(d) {
    if (!d || typeof d !== 'object') bad('Port-forward must be an object');
    const name = str(d.name, 'name').trim().slice(0, 64);
    const proto = str(d.proto, 'proto').toUpperCase();
    if (!name) bad('Name is required');
    if (!['TCP', 'UDP'].includes(proto)) bad('proto must be TCP or UDP');
    const ext = int(d.ext_port, 'ext_port'), dst = int(d.dest_port, 'dest_port');
    if (ext < 1 || ext > 65535) bad('Invalid port: ext_port');
    if (dst < 1 || dst > 65535) bad('Invalid port: dest_port');
    if (RESERVED.has(ext)) bad(`External port ${ext} is used by the gateway itself`);
    const ip = normIPv6(d.dest_ip);
    if (!ip) bad('Invalid IPv6 destination address');
    return { name, proto, ext_port: ext, dest_ip: ip, dest_port: dst };
  }

  function validateWifi(d, cur) {
    const ch = {};
    if ('ssid' in d) {
      const ssid = str(d.ssid, 'ssid').replace(/[^\x20-\x7E]/g, '').slice(0, 32);
      if (!ssid) bad('SSID cannot be empty');
      if (ssid !== cur.ssid) ch.ssid = ssid;
    }
    const band = d.hw_mode || cur.hw_mode || 'g';
    if (d.channel !== undefined && String(d.channel).trim() !== '') {
      const c = int(d.channel, 'channel');
      const ok = band === 'a' ? [36, 40, 44, 48].includes(c) : c >= 1 && c <= 13;
      if (!ok) bad(`Channel ${c} is not valid for hw_mode=${band} (allowed: ${band === 'a' ? '36, 40, 44, 48' : '1–13'})`);
      if (String(c) !== cur.channel) ch.channel = String(c);
    }
    const pw = str(d.wpa_passphrase, 'wpa_passphrase');
    if (pw && pw !== '••••••••') {
      if (pw.length < 8 || pw.length > 63) bad('Passphrase must be 8–63 characters');
      if (!/^[\x20-\x22\x24-\x7E]+$/.test(pw)) bad('Passphrase contains invalid characters (# not allowed)');
      if (pw !== cur.wpa_passphrase) ch.wpa_passphrase = pw;
    }
    if (d.country_code && d.country_code !== cur.country_code) {
      if (!/^[A-Za-z]{2}$/.test(d.country_code)) bad('country_code must be a two-letter ISO country code');
      ch.country_code = d.country_code.toUpperCase();
    }
    if (d.hw_mode && d.hw_mode !== cur.hw_mode) {
      if (!['a', 'b', 'g'].includes(d.hw_mode)) bad('hw_mode must be a, b or g');
      ch.hw_mode = d.hw_mode;
    }
    return ch;
  }

  function needPassword(d) {
    // the demo accepts any non-empty admin password
    if (!d || !d.password) throw new HttpError(403, 'Admin password is incorrect');
  }

  // ── configuration backup (same format as the gateway) ──────────────────────
  function exportConfig(secrets) {
    const wifi = { ssid: state.wifi.ssid, channel: state.wifi.channel, hw_mode: state.wifi.hw_mode, country_code: state.wifi.country_code };
    if (secrets) wifi.wpa_passphrase = state.wifi.wpa_passphrase;
    const cfg = {
      format: 'pi-nat64-config', version: 1,
      exported_at: new Date().toISOString(),
      source: { hostname: 'pi-nat64-demo', commit: 'demo' },
      includes_secrets: !!secrets,
      wifi,
      port_forwards: state.rules.map(({ id, ...r }) => r),
      blocked_clients: [...state.blocked].sort(),
      pihole: {
        adlists: state.adlists.map(a => ({ url: a.url, enabled: a.enabled, comment: a.comment })),
        domains: state.domains.map(d => ({ ...d })),
        blocking: state.blocking,
      },
    };
    if (secrets) cfg.admin = { password_hash: 'scrypt$' + '0'.repeat(32) + '$' + 'demo'.repeat(16) };
    return cfg;
  }

  function importConfig(d) {
    needPassword(d);
    const cfg = d.config;
    if (!cfg || typeof cfg !== 'object' || cfg.format !== 'pi-nat64-config') bad('This is not a pi-nat64 configuration file');
    if (!Number.isInteger(cfg.version) || cfg.version < 1) bad('The file has no valid format version');
    if (cfg.version > 1) bad(`This backup was made by a newer pi-nat64 (format ${cfg.version}) — update this gateway first`);
    const want = (Array.isArray(d.sections) ? d.sections : ['wifi', 'port_forwards', 'blocked_clients', 'pihole', 'admin'])
      .filter(s => s in cfg);
    if (!want.length) bad('Nothing to import — the file has none of the selected sections');
    if (want.includes('pihole') && gravityRunning()) throw new HttpError(409, 'A gravity update is running — try again when it finishes');

    // validate everything first — nothing changes if any entry is bad
    const plan = {};
    const where = (label, fn) => { try { return fn(); } catch (e) { if (e instanceof HttpError) bad(`${label}: ${e.message}`); throw e; } };
    if (want.includes('wifi')) plan.wifi = where('Wi-Fi', () => validateWifi(cfg.wifi || {}, state.wifi));
    if (want.includes('port_forwards')) {
      if (!Array.isArray(cfg.port_forwards)) bad("The 'port_forwards' section is malformed");
      const seen = new Set();
      plan.rules = cfg.port_forwards.map((r, i) => {
        const v = where(`Port-forward #${i + 1}`, () => validateRule(r));
        const k = v.proto + v.ext_port;
        if (seen.has(k)) bad(`Port-forward #${i + 1}: ${v.proto} port ${v.ext_port} is listed twice`);
        seen.add(k);
        return { id: i + 1, ...v, enabled: r.enabled !== false };
      });
    }
    if (want.includes('blocked_clients')) {
      if (!Array.isArray(cfg.blocked_clients)) bad("The 'blocked_clients' section is malformed");
      plan.blocked = [...new Set(cfg.blocked_clients.map((m, i) => {
        m = typeof m === 'string' ? m.trim().toLowerCase() : '';
        if (!validMac(m)) bad(`Blocked client #${i + 1}: invalid MAC address`);
        return m;
      }))];
    }
    if (want.includes('pihole')) {
      const ph = cfg.pihole || {};
      const adl = ph.adlists || [], doms = ph.domains || [];
      if (!Array.isArray(adl) || !Array.isArray(doms)) bad("The 'pihole' section is malformed");
      plan.adlists = adl.map((a, i) => {
        if (!a || !/^https?:\/\/[^\s<>"'`\\{}|\[\]^]{1,2000}$/.test(a.url || '')) bad(`Adlist #${i + 1}: invalid URL`);
        return { url: a.url, enabled: a.enabled !== false, comment: String(a.comment || '').slice(0, 255) };
      });
      plan.domains = doms.map((x, i) => {
        if (!x || ![0, 1, 2, 3].includes(x.type)) bad(`Domain #${i + 1}: type must be 0–3`);
        const v = String(x.domain || '').trim();
        if (x.type < 2 && !validDomain(v.toLowerCase())) bad(`Domain #${i + 1}: invalid domain name`);
        return { type: x.type, domain: x.type < 2 ? v.toLowerCase() : v, enabled: x.enabled !== false, comment: String(x.comment || '') };
      });
      if (ph.blocking !== undefined && typeof ph.blocking !== 'boolean') bad("Pi-hole: 'blocking' must be true or false");
      plan.blocking = ph.blocking;
    }
    if (want.includes('admin') && !/^scrypt\$[0-9a-f]{32}\$[0-9a-f]{64}$/.test((cfg.admin || {}).password_hash || '')) {
      bad('Admin: the password hash is invalid');
    }

    // apply
    const imported = {}, warnings = [];
    if (plan.adlists) {
      const before = new Set(state.adlists.map(a => a.url));
      const byUrl = Object.fromEntries(state.adlists.map(a => [a.url, a]));
      state.adlists = plan.adlists.map(a => ({ id: byUrl[a.url]?.id || ++state.nextId, domains: byUrl[a.url]?.domains || 0, ...a }));
      state.domains = plan.domains;
      if (typeof plan.blocking === 'boolean') state.blocking = plan.blocking;
      imported.pihole = { adlists: state.adlists.length, domains: state.domains.length };
      const after = new Set(state.adlists.map(a => a.url));
      if (before.size !== after.size || [...after].some(u => !before.has(u))) {
        startGravity();
        imported.pihole.gravity_started = true;
      }
    }
    if (plan.rules)   { state.rules = plan.rules; imported.port_forwards = plan.rules.length; }
    if (plan.blocked) { state.blocked = plan.blocked; imported.blocked_clients = plan.blocked.length; }
    if (want.includes('admin')) imported.admin = true;
    let apRestarted = false;
    if (plan.wifi) {
      Object.assign(state.wifi, plan.wifi);
      imported.wifi = Object.keys(plan.wifi).sort();
      apRestarted = imported.wifi.length > 0;
    }
    return { ok: true, imported, warnings, ap_restarted: apRestarted };
  }

  function startGravity() {
    state.gravityUntil = Date.now() + 8000;
    state.adlists.forEach(a => { if (a.enabled && !a.domains) a.domains = jitter(42000, 0.6); });
  }

  // ── routes ─────────────────────────────────────────────────────────────────
  const routes = [
    ['GET', /^\/api\/status$/, () => ({
      nat64_sessions: jitter(140, 0.25), dns_queries: queriesToday(),
      ap_clients: state.stations.filter(s => !state.blocked.includes(s.mac)).length,
      jool_running: true, unbound_running: true, hostapd_running: true, pihole_running: true,
    })],

    ['GET', /^\/api\/rules$/, () => state.rules],
    ['POST', /^\/api\/rules$/, d => {
      const v = validateRule(d);
      if (state.rules.some(r => r.proto === v.proto && r.ext_port === v.ext_port)) {
        throw new HttpError(409, `${v.proto} port ${v.ext_port} is already forwarded`);
      }
      const rule = { id: Math.max(0, ...state.rules.map(r => r.id)) + 1, ...v, enabled: true };
      state.rules.push(rule);
      return [201, rule];
    }],
    ['DELETE', /^\/api\/rules\/(\d+)$/, (d, m) => {
      const id = Number(m[1]);
      if (!state.rules.some(r => r.id === id)) throw new HttpError(404, 'Not found');
      state.rules = state.rules.filter(r => r.id !== id);
      return { deleted: id };
    }],
    ['POST', /^\/api\/rules\/(\d+)\/toggle$/, (d, m) => {
      const r = state.rules.find(x => x.id === Number(m[1]));
      if (!r) throw new HttpError(404, 'Not found');
      r.enabled = !r.enabled;
      return r;
    }],

    ['GET', /^\/api\/settings$/, () => ({
      ssid: state.wifi.ssid, channel: state.wifi.channel, hw_mode: state.wifi.hw_mode,
      wpa_passphrase: '••••••••', jool_prefix: '64:ff9b::/96', upstream_dns: '2606:4700:4700::1111',
    })],
    ['POST', /^\/api\/settings$/, d => {
      const changes = validateWifi(d, state.wifi);
      if (d.new_password) {
        if (d.new_password.length < 8) bad('Admin password must be at least 8 characters');
        if (!d.current_password) throw new HttpError(403, 'Current admin password is incorrect');
      }
      Object.assign(state.wifi, changes);
      return { ok: true, ap_restarted: Object.keys(changes).length > 0 };
    }],

    ['GET', /^\/api\/pihole\/stats$/, () => {
      const q = queriesToday(), b = blockedToday();
      return { domains_blocked: gravityCount(), queries_today: q, blocked_today: b,
               block_pct: q ? Math.round(1000 * b / q) / 10 : 0, status: state.blocking ? 'enabled' : 'disabled' };
    }],
    ['GET', /^\/api\/pihole\/top-blocked$/, () => {
      const f = blockedToday() / 2211;
      return [['doubleclick.net', 412], ['googleadservices.com', 233], ['app-measurement.com', 198],
              ['graph.facebook.com', 151], ['telemetry.microsoft.com', 120], ['ads.yahoo.com', 77]]
        .map(([domain, c], i) => ({ rank: i + 1, domain, count: Math.max(1, Math.round(c * f)) }));
    }],
    ['POST', /^\/api\/pihole\/toggle$/, () => { state.blocking = !state.blocking; return { status: state.blocking ? 'enabled' : 'disabled' }; }],
    ['GET', /^\/api\/pihole\/adlists$/, () => [...state.adlists].sort((a, b) => a.url.localeCompare(b.url))],
    ['POST', /^\/api\/pihole\/adlists$/, d => {
      const url = str(d.url, 'url').trim();
      if (!/^https?:\/\/[^\s<>"'`\\{}|\[\]^]{1,2000}$/.test(url)) bad('Invalid URL — must start with http:// or https://');
      if (gravityRunning()) throw new HttpError(409, 'A gravity update is running — try again when it finishes');
      if (state.adlists.some(a => a.url === url)) throw new HttpError(409, 'This URL is already in your adlists');
      state.adlists.push({ id: ++state.nextId, url, enabled: true, comment: str(d.comment, 'comment').trim().slice(0, 255), domains: 0 });
      return [201, { ok: true, url }];
    }],
    ['DELETE', /^\/api\/pihole\/adlists$/, d => {
      state.adlists = state.adlists.filter(a => a.id !== Number(d.id));
      return { ok: true, deleted: Number(d.id) };
    }],
    ['POST', /^\/api\/pihole\/adlists\/toggle$/, d => {
      const a = state.adlists.find(x => x.id === Number(d.id));
      if (!a) throw new HttpError(404, 'Adlist not found');
      a.enabled = !a.enabled;
      return { ok: true, id: a.id, enabled: a.enabled };
    }],
    ['POST', /^\/api\/pihole\/gravity$/, () => {
      if (gravityRunning()) throw new HttpError(409, 'A gravity update is running — try again when it finishes');
      startGravity();
      return { ok: true };
    }],
    ['GET', /^\/api\/pihole\/whitelist$/, () => state.domains.filter(d => d.type === 0).map(d => d.domain).sort()],
    ['POST', /^\/api\/pihole\/whitelist$/, d => {
      const dom = str(d.domain, 'domain').trim().toLowerCase();
      if (!validDomain(dom)) bad('Invalid domain name');
      if (state.domains.some(x => x.type === 0 && x.domain === dom)) throw new HttpError(409, 'Domain already whitelisted');
      state.domains.push({ type: 0, domain: dom, enabled: true, comment: 'added by pi-nat64' });
      return [201, { domain: dom }];
    }],
    ['DELETE', /^\/api\/pihole\/whitelist$/, d => {
      const dom = str(d.domain, 'domain').trim().toLowerCase();
      const n = state.domains.length;
      state.domains = state.domains.filter(x => !(x.type === 0 && x.domain === dom));
      if (state.domains.length === n) throw new HttpError(404, 'Domain is not whitelisted');
      return { deleted: dom };
    }],

    ['GET', /^\/api\/clients$/, () => {
      const t = now();
      const online = state.stations.map(s => ({
        mac: s.mac, ip: s.ip, hostname: s.hostname, signal: s.signal + Math.round((Math.random() - 0.5) * 4),
        rx_bytes: s.rx + (t % 100000) * 900, tx_bytes: s.tx + (t % 100000) * 60,
        connected_sec: s.since + (t % 3600), online: true, blocked: state.blocked.includes(s.mac),
      })).filter(c => !c.blocked);
      const offline = state.blocked.map(mac => {
        const st = state.stations.find(s => s.mac === mac) || state.offline[mac] || {};
        return { mac, ip: st.ip || '', hostname: st.hostname || '', signal: null, rx_bytes: null, tx_bytes: null,
                 connected_sec: null, online: false, blocked: true };
      });
      return [...online, ...offline];
    }],
    ['POST', /^\/api\/clients\/block$/, d => {
      const mac = str(d.mac, 'mac').trim().toLowerCase();
      if (!validMac(mac)) bad('Invalid MAC address');
      if (!state.blocked.includes(mac)) state.blocked.push(mac);
      return { mac, blocked: true };
    }],
    ['POST', /^\/api\/clients\/unblock$/, d => {
      const mac = str(d.mac, 'mac').trim().toLowerCase();
      if (!validMac(mac)) bad('Invalid MAC address');
      state.blocked = state.blocked.filter(m => m !== mac);
      return { mac, blocked: false };
    }],

    ['POST', /^\/api\/reboot$/, () => ({ ok: true })],

    ['GET', /^\/api\/update\/check$/, () => state.updated
      ? { supported: true, available: false, current: { commit: 'demo', date: '', branch: 'main' } }
      : { supported: true, available: true, behind: 3, latest: 'f3c9a1e', summary: 'Settings: export and import the whole configuration',
          date: new Date().toISOString().slice(0, 10), current: { commit: 'demo', date: '', branch: 'main' } }],
    ['POST', /^\/api\/update\/apply$/, () => { state.updateStarted = Date.now(); return [202, { ok: true }]; }],
    ['GET', /^\/api\/update\/status$/, () => {
      if (!state.updateStarted) return { state: 'idle' };
      if (Date.now() - state.updateStarted < 7000) return { state: 'running' };
      state.updated = true;
      return { state: 'success' };
    }],

    ['POST', /^\/api\/config\/export$/, d => {
      if (d.include_secrets === true) needPassword(d);
      return exportConfig(d.include_secrets === true);
    }],
    ['POST', /^\/api\/config\/import$/, d => importConfig(d)],
  ];

  // ── fetch shim ─────────────────────────────────────────────────────────────
  const realFetch = window.fetch.bind(window);
  const json = (status, body) => new Response(JSON.stringify(body), {
    status, headers: { 'Content-Type': 'application/json' },
  });

  window.fetch = async (input, init = {}) => {
    const url = new URL(typeof input === 'string' ? input : input.url, location.href);
    const path = url.pathname;
    // the real UI talks to root-absolute /api/... (and probes /login after a reboot)
    if (!path.startsWith('/api/') && path !== '/login') return realFetch(input, init);
    await new Promise(r => setTimeout(r, 120 + Math.random() * 180));   // feel like a network
    if (path === '/login') return new Response('<!doctype html><title>pi-nat64</title>', { status: 200 });

    const method = (init.method || 'GET').toUpperCase();
    let body = {};
    if (init.body) { try { body = JSON.parse(init.body); } catch (_) { return json(400, { error: 'Expected a JSON object' }); } }
    for (const [m, re, handler] of routes) {
      const match = m === method && path.match(re);
      if (!match) continue;
      try {
        let out = handler(body, match);
        let status = 200;
        if (Array.isArray(out) && typeof out[0] === 'number' && out.length === 2) [status, out] = out;
        save();
        return json(status, out);
      } catch (e) {
        if (e instanceof HttpError) return json(e.status, { error: e.message });
        console.error(e);
        return json(500, { error: 'Demo error: ' + e.message });
      }
    }
    return json(404, { error: 'Not found' });
  };

  // ── demo chrome: login without a server, and a banner ──────────────────────
  document.addEventListener('submit', e => {
    if (e.target.matches('form[action="index.html"]')) {
      e.preventDefault();
      location.href = 'index.html';
    }
  });

  function banner() {
    const host = document.querySelector('.main') || document.querySelector('.login-card');
    if (!host || document.querySelector('.demo-banner')) return;
    const el = document.createElement('div');
    el.className = 'demo-banner';
    el.innerHTML = '<strong>Interactive demo</strong> — simulated gateway, try anything. ' +
      'Changes stay in this tab only' + (document.querySelector('.login-card') ? ' · any password works' : '') +
      '. <a href="https://github.com/ALQU-IT/pi-nat64" target="_blank" rel="noopener">Get pi-nat64 on GitHub →</a>';
    if (host.classList.contains('main')) host.prepend(el); else host.append(el);
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', banner); else banner();
})();
