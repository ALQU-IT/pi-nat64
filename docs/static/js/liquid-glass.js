/* pi-nat64 — Liquid Glass refraction
 *
 * Gives every element marked [data-liquid] a glass edge that bends whatever is
 * behind it, like light through the curved rim of a glass slab:
 *
 *   1. For the element's size and corner radius, draw a displacement map on a
 *      canvas. Inside a "bezel" band along the edge, each pixel stores an
 *      offset pointing inward (R = x, G = y), strongest right at the edge and
 *      fading to zero; B stores how strongly the crisp refracted rim shows.
 *   2. An SVG filter uses that map: displace the backdrop, frost a blurred copy
 *      for the interior, lay the crisp refracted rim over it, boost saturation.
 *   3. The element's backdrop-filter points at that filter.
 *
 * Only Chromium supports SVG filters in backdrop-filter; every other browser
 * keeps the plain CSS frosted glass from style.css. Maps are rebuilt when an
 * element changes size. An element whose computed `--lg` is `off` (e.g. the
 * sidebar on phones) is skipped.
 */
(() => {
  'use strict';

  const brands = navigator.userAgentData && navigator.userAgentData.brands;
  const isChromium = !!brands && brands.some(b => /Chromium|Google Chrome|Microsoft Edge/.test(b.brand));
  if (!isChromium || !window.ResizeObserver) return;
  if (matchMedia('(prefers-reduced-transparency: reduce)').matches) return;

  // Chromium's software compositor (GPU blocklisted / unavailable) renders SVG
  // backdrop filters with hard-edged unfiltered patches — keep the CSS glass there.
  function softwareRendering() {
    try {
      const gl = document.createElement('canvas').getContext('webgl');
      if (!gl) return true;
      const ext = gl.getExtension('WEBGL_debug_renderer_info');
      const renderer = String(ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)
                                  : gl.getParameter(gl.RENDERER));
      gl.getExtension('WEBGL_lose_context')?.loseContext();
      return /SwiftShader|llvmpipe|Software|softpipe/i.test(renderer);
    } catch (e) {
      return true;
    }
  }
  if (!window.__lgForce && softwareRendering()) return;

  const NS = 'http://www.w3.org/2000/svg';
  const MAX_PIXELS = 1400 * 1100;   // skip giant surfaces (cost grows with area)

  let defs = null;
  let seq = 0;
  const state = new Map();          // element -> { id, filter, key }

  function ensureDefs() {
    if (defs) return defs;
    const svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('aria-hidden', 'true');
    svg.setAttribute('width', '0');
    svg.setAttribute('height', '0');
    svg.style.cssText = 'position:absolute;width:0;height:0;overflow:hidden;pointer-events:none';
    defs = document.createElementNS(NS, 'defs');
    svg.appendChild(defs);
    document.body.appendChild(svg);
    return defs;
  }

  function num(el, prop, fallback) {
    const v = parseFloat(getComputedStyle(el).getPropertyValue(prop));
    return Number.isFinite(v) ? v : fallback;
  }

  /* Displacement map for a rounded rectangle (w × h, corner radius r). */
  function buildMap(w, h, r, bezel) {
    const canvas = document.createElement('canvas');
    canvas.width = w;
    canvas.height = h;
    const ctx = canvas.getContext('2d');
    const img = ctx.createImageData(w, h);
    const d = img.data;
    const hw = w / 2, hh = h / 2;

    for (let y = 0; y < h; y++) {
      const py = y + 0.5 - hh;
      const ay = Math.abs(py);
      for (let x = 0; x < w; x++) {
        const px = x + 0.5 - hw;
        const ax = Math.abs(px);
        const qx = ax - (hw - r);
        const qy = ay - (hh - r);

        // distance to the edge (inside > 0) and the outward edge normal
        let dist, nx, ny;
        if (qx > 0 && qy > 0) {                 // rounded corner
          const len = Math.hypot(qx, qy);
          dist = r - len;
          nx = qx / len;
          ny = qy / len;
        } else if (qx > qy) {                   // left / right edge
          dist = hw - ax; nx = 1; ny = 0;
        } else {                                // top / bottom edge
          dist = hh - ay; nx = 0; ny = 1;
        }
        if (px < 0) nx = -nx;
        if (py < 0) ny = -ny;

        const i = (y * w + x) * 4;
        let R = 128, G = 128, B = 0;
        if (dist > 0 && dist < bezel) {
          const t = dist / bezel;               // 0 at the edge → 1 at the bezel's inner side
          // Convex (squircle-ish) glass edge: steepest — so most refraction — at the rim
          const m = Math.pow(1 - t, 2.2);
          // sample INWARD (never outside the element, where the backdrop is empty)
          R = 128 - nx * m * 127;
          G = 128 - ny * m * 127;
          B = 255 * Math.pow(1 - t, 1.3);
        }
        d[i] = R; d[i + 1] = G; d[i + 2] = B; d[i + 3] = 255;
      }
    }
    ctx.putImageData(img, 0, 0);
    return canvas.toDataURL('image/png');
  }

  function el(tag, attrs, parent) {
    const node = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
    if (parent) parent.appendChild(node);
    return node;
  }

  function makeFilter(id, w, h, mapUrl, opts) {
    // Explicit filter region in element pixels. With the default
    // (objectBoundingBox -10%/120%) Chromium resolves the region for
    // backdrop-filter against a smaller box and leaves part of the element
    // unfiltered — a hard seam across the glass.
    const f = el('filter', { id, 'color-interpolation-filters': 'sRGB',
                             filterUnits: 'userSpaceOnUse', primitiveUnits: 'userSpaceOnUse',
                             x: 0, y: 0, width: w, height: h });
    el('feImage', { href: mapUrl, x: 0, y: 0, width: w, height: h,
                    preserveAspectRatio: 'none', result: 'map' }, f);
    // refract the backdrop through the rim
    el('feDisplacementMap', { in: 'SourceGraphic', in2: 'map', scale: opts.scale,
                              xChannelSelector: 'R', yChannelSelector: 'G', result: 'refr' }, f);
    // frosted interior; force alpha to 1 so the blur doesn't fade at the edges
    el('feGaussianBlur', { in: 'refr', stdDeviation: opts.blur, result: 'frost0' }, f);
    const ct = el('feComponentTransfer', { in: 'frost0', result: 'frost' }, f);
    el('feFuncA', { type: 'discrete', tableValues: '1' }, ct);
    // rim mask from the map's blue channel → keep the refracted rim crisp
    el('feColorMatrix', { in: 'map', type: 'matrix', result: 'rimMask',
                          values: '0 0 0 0 0  0 0 0 0 0  0 0 0 0 0  0 0 1 0 0' }, f);
    el('feComposite', { in: 'refr', in2: 'rimMask', operator: 'in', result: 'rim' }, f);
    el('feComposite', { in: 'rim', in2: 'frost', operator: 'over', result: 'glass' }, f);
    el('feColorMatrix', { in: 'glass', type: 'saturate', values: opts.saturate }, f);
    return f;
  }

  function disable(node) {
    const s = state.get(node);
    if (s && s.filter) { s.filter.remove(); s.filter = null; s.key = ''; }
    node.style.removeProperty('backdrop-filter');
    node.classList.remove('lg-on');
  }

  function update(node) {
    const cs = getComputedStyle(node);
    if (cs.getPropertyValue('--lg').trim() === 'off' || cs.display === 'none') {
      disable(node);
      return;
    }
    const w = Math.round(node.offsetWidth);
    const h = Math.round(node.offsetHeight);
    if (w < 16 || h < 16 || w * h > MAX_PIXELS) { disable(node); return; }

    const r = Math.min(parseFloat(cs.borderTopLeftRadius) || 0, w / 2, h / 2);
    const bezel = Math.max(6, Math.min(num(node, '--lg-bezel', 22), w / 2 - 1, h / 2 - 1));
    const opts = {
      scale:    num(node, '--lg-scale', 34),
      blur:     num(node, '--lg-blur', 14),
      saturate: num(node, '--lg-saturate', 1.8),
    };
    const key = [w, h, r, bezel, opts.scale, opts.blur, opts.saturate].join('/');

    let s = state.get(node);
    if (!s) { s = { id: 'lg-' + (++seq), filter: null, key: '' }; state.set(node, s); }
    if (s.key === key || s.pending === key) return;
    s.pending = key;

    // Decode the map before the filter goes live, so the glass never renders
    // for a frame with an empty map (which would shift the whole backdrop).
    const mapUrl = buildMap(w, h, r, bezel);
    const probe = new Image();
    probe.src = mapUrl;
    probe.decode().catch(() => {}).then(() => {
      if (s.pending !== key) return;          // superseded by a newer size
      s.pending = '';
      const filter = makeFilter(s.id, w, h, mapUrl, opts);
      if (s.filter) s.filter.replaceWith(filter); else ensureDefs().appendChild(filter);
      s.filter = filter;
      s.key = key;
      node.style.setProperty('backdrop-filter', `url(#${s.id})`);
      node.classList.add('lg-on');
    });
  }

  // Coalesce resize bursts (window resizes, tab switches) into one pass per frame
  const pending = new Set();
  let raf = 0;
  function schedule(node) {
    pending.add(node);
    if (!raf) raf = requestAnimationFrame(() => {
      raf = 0;
      const nodes = [...pending];
      pending.clear();
      nodes.forEach(n => { try { update(n); } catch (e) { disable(n); } });
    });
  }

  const ro = new ResizeObserver(entries => entries.forEach(e => schedule(e.target)));

  function scan() {
    document.querySelectorAll('[data-liquid]').forEach(node => {
      if (!state.has(node)) { state.set(node, { id: 'lg-' + (++seq), filter: null, key: '' }); ro.observe(node); }
    });
  }

  // Breakpoint changes can flip --lg without resizing an element
  matchMedia('(max-width: 760px)').addEventListener?.('change', () => state.forEach((_, n) => schedule(n)));

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', scan);
  else scan();
})();
