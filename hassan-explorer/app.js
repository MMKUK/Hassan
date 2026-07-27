/* Hassan Explorer — standalone client, talks to any Hassan node's JSON API.
 * No build step, no dependencies. Hash-routed: #/, #/blocks, #/block/:id,
 * #/address/:addr, #/fees, #/pruning, #/registry, #/escrow, #/tx/:hash.
 */
const $ = (id) => document.getElementById(id);

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
/** Compact display for any hash / address / signature: first 4 + ...... + last 4.
 *  Preserves a leading `hsn:` or `hsn1` HRP when present. */
function short(h) {
  if (!h) return '';
  let s = String(h);
  let prefix = '';
  if (/^hsn1/i.test(s)) {
    prefix = 'hsn1';
    s = s.slice(4);
  } else if (/^hsn:/i.test(s)) {
    prefix = 'hsn:';
    s = s.slice(4);
  }
  if (s.length <= 8) return esc(prefix + s);
  return esc(prefix + s.slice(0, 4) + '......' + s.slice(-4));
}
/** Shorten long hex / hsn blobs inside free-form detail strings. */
function shortDetail(d) {
  if (!d) return '';
  return esc(String(d).replace(/hsn1[0-9a-z]{16,}|hsn:[0-9a-fA-F]{16,}|[0-9a-fA-F]{16,}/gi, (m) => {
    if (/^hsn1/i.test(m)) return 'hsn1' + m.slice(4, 8) + '......' + m.slice(-4);
    if (/^hsn:/i.test(m)) return 'hsn:' + m.slice(4, 8) + '......' + m.slice(-4);
    return m.slice(0, 4) + '......' + m.slice(-4);
  }));
}
const agoShort = (t) => { const s = Math.max(0, (Date.now() - t) / 1000); return s < 1 ? 'now' : s < 60 ? Math.floor(s) + 's ago' : s < 3600 ? Math.floor(s / 60) + 'm ago' : s < 86400 ? Math.floor(s / 3600) + 'h ago' : Math.floor(s / 86400) + 'd ago'; };
const commas = (x) => String(x).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
function hsn(x) {
  try {
    const n = BigInt(x), W = n / (10n ** 8n), f = (n % (10n ** 8n)).toString().padStart(8, '0').replace(/0+$/, '');
    return commas(W.toString()) + (f ? '.' + f : '');
  } catch (_) { return x; }
}
function toast(m) { const t = $('toast'); t.textContent = m; t.classList.add('show'); clearTimeout(t._t); t._t = setTimeout(() => t.classList.remove('show'), 1200); }
function copy(s) { navigator.clipboard && navigator.clipboard.writeText(s).then(() => toast('copied ' + short(s).replace(/&[^;]+;/g, ''))); }
window.copy = copy;
function cp(s) { return `<span class="copybtn" onclick="event.stopPropagation();copy('${esc(s)}')">copy</span>`; }
function info(text) { return `<i class="info" title="${esc(text)}">i</i>`; }
/** Shortened hash/address with full value on hover + one-click copy. */
function fullHash(h) { return h ? `<span class="hashval mono" title="${esc(h)}">${short(h)}${cp(h)}</span>` : '—'; }
function hashLink(h, route) { return h ? `<a class="mono" href="#/${route}/${esc(h)}" title="${esc(h)}">${short(h)}</a>` : '—'; }
/* Hassan addresses look like "hsn:<hex>" — ':' is a valid unescaped path
 * character and this server's minimal HTTP router does not percent-decode,
 * so encode everything except the colon. */
function encAddr(a) { return encodeURIComponent(a).replace(/%3A/gi, ':'); }
function icon(p) { return `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${p}</svg>`; }
const IC = {
  height: '<path d="M3 17l6-6 4 4 8-8"/><path d="M17 7h4v4"/>',
  dag: '<circle cx="6" cy="6" r="2"/><circle cx="18" cy="7" r="2"/><circle cx="12" cy="17" r="2"/><path d="M8 7l8 0M7 8l4 7M16 9l-3 6"/>',
  diff: '<path d="M12 2l3 7h7l-6 4 2 8-6-5-6 5 2-8-6-4h7z"/>',
  time: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  coin: '<circle cx="12" cy="12" r="9"/><path d="M12 7v10M9 9.5c0-1 1-1.5 3-1.5s3 .8 3 2-1 1.8-3 2-3 1-3 2 1 1.5 3 1.5 3-.5 3-1.5"/>',
  mem: '<rect x="4" y="5" width="16" height="14" rx="2"/><path d="M8 5v14M16 5v14"/>',
  chain: '<path d="M10 13a5 5 0 007 0l2-2a5 5 0 00-7-7l-1 1"/><path d="M14 11a5 5 0 00-7 0l-2 2a5 5 0 007 7l1-1"/>',
  cut: '<circle cx="6" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><path d="M20 4L8.1 15.9M14.5 14.5L20 20"/>',
  blue: '<path d="M12 21s-7-4.5-9.5-9A5.5 5.5 0 0112 5a5.5 5.5 0 019.5 7c-2.5 4.5-9.5 9-9.5 9z"/>',
  lock: '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V7a4 4 0 018 0v4"/>',
  shield: '<path d="M12 3l7 3v6c0 4.5-3 8-7 9-4-1-7-4.5-7-9V6l7-3z"/>',
  gauge: '<path d="M4 14a8 8 0 0116 0"/><path d="M12 14l3-4"/>',
  proof: '<rect x="4" y="4" width="7" height="7" rx="1.2"/><rect x="13" y="4" width="7" height="7" rx="1.2"/><rect x="4" y="13" width="7" height="7" rx="1.2"/><path d="M17 13v3M15.5 14.5h3"/>',
  bank: '<path d="M3 21h18M4 21V10M20 21V10M2 10l10-6 10 6M6 10v11M10 10v11M14 10v11M18 10v11"/>',
  king: '<path d="M3 8l4 3 5-6 5 6 4-3v11H3V8z"/><path d="M5 19h14"/>',
  wallet: '<rect x="3" y="7" width="18" height="12" rx="2"/><path d="M3 10h18M16 14h2"/>',
  book: '<path d="M4 5a2 2 0 012-2h12v16H6a2 2 0 01-2-2V5z"/><path d="M6 3v14a1 1 0 001 1h11"/>',
};
/** Current coin / title owner — king mark + shortened address. */
function ownerMark(addr, link) {
  if (!addr) return '—';
  const body = `<span class="owner-mark" title="Current owner">${icon(IC.king)}</span> ${short(addr)}`;
  if (link === false) return `<span class="mono owner-line" title="${esc(addr)}">${body}</span>`;
  return `<a class="mono owner-line" href="#/address/${encAddr(addr)}" title="${esc(addr)}">${body}</a>`;
}

/* ---------- node connection ---------- */
const DEFAULT_BASE = '';
let API_BASE = localStorage.getItem('hassan-explorer-api') || DEFAULT_BASE;
function apiUrl(path) { return (API_BASE || '') + path; }
async function j(path) { const r = await fetch(apiUrl(path)); if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); }

function renderNetLabel() { $('netLabel').textContent = API_BASE ? API_BASE.replace(/^https?:\/\//, '') : 'same origin'; }
renderNetLabel();
$('netInput').value = API_BASE;
$('netBtn').addEventListener('click', () => $('netPanel').classList.toggle('hidden'));
document.addEventListener('click', (e) => { if (!e.target.closest('.net')) $('netPanel').classList.add('hidden'); });
$('netSave').addEventListener('click', () => {
  API_BASE = $('netInput').value.trim().replace(/\/$/, '');
  if (API_BASE && !/^https?:\/\/(127\.0\.0\.1|localhost|\[::1\])/i.test(API_BASE) && !API_BASE.startsWith('/')) {
    toast('non-loopback API — treat balances as untrusted');
  }
  localStorage.setItem('hassan-explorer-api', API_BASE);
  renderNetLabel(); $('netPanel').classList.add('hidden'); router();
});
$('netReset').addEventListener('click', () => {
  API_BASE = DEFAULT_BASE; localStorage.removeItem('hassan-explorer-api');
  $('netInput').value = ''; renderNetLabel(); $('netPanel').classList.add('hidden'); router();
});

/* ---------- search ---------- */
let suggestTimer = null;
async function routeSearch(q) {
  q = (q || '').trim(); if (!q) return;
  try {
    const r = await j('/api/v1/search?q=' + encodeURIComponent(q));
    const results = r.results || [];
    if (results.length === 1) {
      goResult(results[0]);
      return;
    }
    if (results.length > 1) {
      location.hash = '#/search/' + encodeURIComponent(q);
      return;
    }
  } catch (_) {}
  if (/^\d+$/.test(q)) { location.hash = '#/block/' + q; return; }
  if (/^hsn:/i.test(q) || /^hsn1/i.test(q)) { location.hash = '#/address/' + encAddr(q); return; }
  if (/^[0-9a-fA-F]{32,}$/.test(q)) { location.hash = '#/block/' + q.toLowerCase(); return; }
  if (/^[0-9a-fA-F]{64,}:\d+$/i.test(q)) { location.hash = '#/search/' + encodeURIComponent(q); return; }
  location.hash = '#/address/' + encAddr(q);
}
function goResult(r) {
  if (!r) return;
  if (r.kind === 'block') location.hash = '#/block/' + (r.height != null ? r.height : r.id);
  else if (r.kind === 'tx') location.hash = '#/tx/' + r.id;
  else if (r.kind === 'address') location.hash = '#/address/' + encAddr(r.id);
  else if (r.kind === 'outpoint') location.hash = '#/search/' + encodeURIComponent(r.id);
  else if (r.kind === 'label') {
    if (/^hsn:/i.test(r.id) || /^hsn1/i.test(r.id)) location.hash = '#/address/' + encAddr(r.id);
    else if (/^[0-9a-fA-F]{32,}$/i.test(r.id)) location.hash = '#/block/' + r.id;
    else location.hash = '#/labels';
  }
}
$('navQ').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') { $('navSuggest').classList.add('hidden'); routeSearch(e.target.value); }
  if (e.key === 'Escape') $('navSuggest').classList.add('hidden');
});
$('navQ').addEventListener('input', (e) => {
  clearTimeout(suggestTimer);
  const q = e.target.value.trim();
  if (q.length < 2) { $('navSuggest').classList.add('hidden'); return; }
  suggestTimer = setTimeout(async () => {
    try {
      const r = await j('/api/v1/search?q=' + encodeURIComponent(q));
      const results = (r.results || []).slice(0, 8);
      if (!results.length) { $('navSuggest').classList.add('hidden'); return; }
      $('navSuggest').innerHTML = results.map((x) =>
        `<button type="button" data-kind="${esc(x.kind)}" data-id="${esc(x.id)}" data-h="${x.height != null ? x.height : ''}"><span class="sk">${esc(x.kind)}</span><span class="mono">${short(x.id)}</span>${x.label ? ` <span class="faint">${esc(x.label)}</span>` : ''}</button>`
      ).join('');
      $('navSuggest').classList.remove('hidden');
      $('navSuggest').querySelectorAll('button').forEach((btn) => {
        btn.addEventListener('click', () => {
          goResult({ kind: btn.dataset.kind, id: btn.dataset.id, height: btn.dataset.h ? Number(btn.dataset.h) : undefined });
          $('navSuggest').classList.add('hidden');
        });
      });
    } catch (_) { $('navSuggest').classList.add('hidden'); }
  }, 180);
});
document.addEventListener('keydown', (e) => { if (e.key === '/' && !/input|textarea/i.test(document.activeElement.tagName)) { e.preventDefault(); $('navQ').focus(); } });
document.addEventListener('click', (e) => { if (!e.target.closest('.nav-search')) $('navSuggest').classList.add('hidden'); });

function downloadJson(filename, obj) {
  const blob = new Blob([typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1500);
  toast('downloaded ' + filename);
}
window.downloadJson = downloadJson;

function sparkline(points, key, color) {
  if (!points || points.length < 2) return '<div class="placeholder">not enough history yet</div>';
  const W = 520, H = 150, pad = 12;
  const vals = points.map((p) => {
    const v = p[key];
    if (typeof v === 'string') { try { return Number(BigInt(v) > 10n ** 12n ? BigInt(v) / (10n ** 8n) : BigInt(v)); } catch (_) { return Number(v) || 0; } }
    return Number(v) || 0;
  });
  const min = Math.min(...vals), max = Math.max(...vals);
  const span = Math.max(1e-9, max - min);
  const coords = vals.map((v, i) => {
    const x = pad + (i / (vals.length - 1)) * (W - 2 * pad);
    const y = H - pad - ((v - min) / span) * (H - 2 * pad);
    return [x, y];
  });
  const d = coords.map((c, i) => (i ? 'L' : 'M') + c[0].toFixed(1) + ' ' + c[1].toFixed(1)).join(' ');
  const area = d + ` L${coords[coords.length - 1][0]} ${H - pad} L${coords[0][0]} ${H - pad} Z`;
  return `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">
    <defs><linearGradient id="chartGrad" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="${color || 'var(--accent)'}" stop-opacity=".35"/><stop offset="100%" stop-color="${color || 'var(--accent)'}" stop-opacity="0"/></linearGradient></defs>
    <path class="chart-area" d="${area}"></path>
    <path class="chart-line" style="stroke:${color || 'var(--accent)'}" d="${d}"></path>
  </svg>`;
}

/* ---------- era + status cache ---------- */
let statusCache = null;
function eraFor(minted, s) {
  const m = BigInt(minted);
  const bootstrapEnd = BigInt(s.bootstrap_era_end || 0);
  if (m < bootstrapEnd) return { label: 'Bootstrap', cls: 'b-era-easy' };
  return { label: 'Hard', cls: 'b-era-btc' };
}

/* ================= VIEWS ================= */

async function viewHome(gen) {
  const [s, blocks, m] = await Promise.all([
    j('/api/v1/status'), j('/api/v1/blocks'), j('/api/v1/mining'),
  ]);
  statusCache = s;
  const pct = (() => { try { return Number(BigInt(s.circulating_supply) * 1000000n / BigInt(s.max_supply)) / 10000; } catch (_) { return 0; } })();
  const era = eraFor(s.circulating_supply, s);
  const sorted = [...blocks].sort((a, b) => a.height - b.height);
  let dt = 0, dn = 0;
  for (let i = 1; i < sorted.length; i++) { const d = sorted[i].timestamp - sorted[i - 1].timestamp; if (d > 0 && d < 600000) { dt += d; dn++; } }
  const avg = dn ? dt / dn / 1000 : null;

  let light = {}, net = {};
  const extras = await Promise.allSettled([
    j('/api/v1/light/tip'), j('/api/v1/network'),
  ]);
  if (extras[0].status === 'fulfilled') light = extras[0].value;
  if (extras[1].status === 'fulfilled') net = extras[1].value;
  const kpi = [
    ['Height', IC.height, commas(s.height), null, null],
    ['Supply', IC.coin, hsn(s.circulating_supply), pct.toFixed(2) + '% of cap', pct, 'HSN'],
    ['Peers', IC.chain, commas(s.peers != null ? s.peers : (net.peer_count || 0)), s.p2p_listening ? 'listening' : 'local', null],
    ['UTXO set', IC.bank, commas(s.utxo_set_size || 0), s.supply_ok === false ? 'supply check failed' : null, null],
    ['Blue score', IC.blue, commas(s.blue_score), null, null],
    ['Mempool', IC.mem, commas(s.mempool), null, null],
  ];

  const html = `
  <div class="hero">
    <div class="hero-in">
      <div class="hero-brand">Hassan</div>
      <p class="hero-lead">Blocks and peer escrow — live from the node you connect.</p>
      <div class="hero-cta">
        <a class="btn primary" href="#/blocks">Blocks</a>
        <a class="btn" href="#/escrow">Escrow</a>
      </div>
      <div class="hero-search">
        <input id="heroQ" spellcheck="false" autocomplete="off" placeholder="Search height, hash, txid, hsn1…">
      </div>
    </div>
  </div>

  <div class="section" style="padding-top:28px">
    <div class="sys-strip">
      <div class="sys-chip"><div class="l">Genesis</div><div class="v">${esc(s.genesis_domain)}</div></div>
      <div class="sys-chip"><div class="l">Chain id</div><div class="v" title="u64 LE of blake3(hassan)[0..8]">${esc(String(s.chain_id ?? ''))}</div></div>
      <div class="sys-chip"><div class="l">State root</div><div class="v" title="${esc(s.state_root || light.state_root || '')}">${short(s.state_root || light.state_root || '')}</div></div>
      <div class="sys-chip"><div class="l">UTXO commit</div><div class="v" title="${esc(s.utxo_commitment || light.utxo_commitment || '')}">${short(s.utxo_commitment || light.utxo_commitment || '')}</div></div>
      <div class="sys-chip"><div class="l">Difficulty</div><div class="v">${commas(s.difficulty)} · ${era.label}</div></div>
      <div class="sys-chip"><div class="l">DAG / avg</div><div class="v">${commas(s.dag_blocks)} · ${avg ? avg.toFixed(2) + 's' : '—'}</div></div>
    </div>
  </div>

  <div class="section" style="padding-top:0">
    <div class="section-h"><h2>Overview</h2><span class="r">${esc(s.genesis_domain)}</span></div>
    <div class="stat-grid">
      ${kpi.map(([k, ic, v, sub, bar, unit]) => `
        <div class="stat-card">
          <div class="sk">${icon(ic)}${k}</div>
          <div class="sv">${v}${unit ? `<span class="unit">${unit}</span>` : ''}</div>
          ${sub ? `<div class="ssub">${esc(sub)}</div>` : ''}
          ${bar != null ? `<div class="sbar"><i style="width:${Math.min(100, bar)}%"></i></div>` : ''}
        </div>`).join('')}
    </div>
  </div>

  <div class="section">
    <div class="section-h"><h2>Latest blocks</h2><span class="r"><a href="#/blocks">view all &rarr;</a></span></div>
    <div class="card">
      <div class="scroll">
        <table><thead><tr><th>Height</th><th>Hash</th><th>Era</th><th>Transactions</th><th>Miner</th><th>Age</th></tr></thead>
        <tbody>${blocks.slice(0, 12).map((b) => blockRow(b, era)).join('') || '<tr><td colspan="6" class="empty">no blocks yet</td></tr>'}</tbody></table>
      </div>
    </div>

    <div class="card">
      <h3>Economics</h3>
      <table class="kvtable">
        <tr><td class="k">Block reward</td><td class="v">${hsn(m.block_reward)} HSN</td></tr>
        <tr><td class="k">Max supply</td><td class="v">${hsn(s.max_supply)} HSN</td></tr>
        <tr><td class="k">Treasury</td><td class="v">${hsn(m.treasury)} HSN</td></tr>
        <tr><td class="k">Min relay fee</td><td class="v">${hsn(s.min_relay_fee)} HSN</td></tr>
        <tr><td class="k">Signatures</td><td class="v">${esc(s.signature_scheme)}</td></tr>
      </table>
      <p class="mut" style="margin:10px 12px 4px;font-size:12px"><a href="#/supply">Supply detail</a> · <a href="#/audit">Audit</a></p>
    </div>
  </div>`;
  if (gen !== renderGen) return;
  $('app').innerHTML = html;
  $('heroQ').addEventListener('keydown', (e) => { if (e.key === 'Enter') routeSearch(e.target.value); });
  setFootMeta(s);
}

function blockRow(b, era) {
  return `<tr class="clickable" onclick="location.hash='#/block/${b.height}'">` +
    `<td class="mono h-num">${commas(b.height)}</td>` +
    `<td class="mono mut" title="${esc(b.hash)}">${short(b.hash)}</td>` +
    `<td><span class="badge ${era.cls}">${era.label}</span></td>` +
    `<td>${b.transfers || b.tx_count ? `<span class="badge b-tf">${b.transfers || b.tx_count} transfer</span>` : '<span class="empty">empty</span>'}</td>` +
    `<td class="mono mut" title="${esc(b.miner || '')}">${b.miner ? ownerMark(b.miner, false) : '—'}</td>` +
    `<td class="mut" title="${new Date(b.timestamp).toLocaleString()}">${agoShort(b.timestamp)}</td></tr>`;
}

async function viewBlocks(gen) {
  const s = await j('/api/v1/status'); statusCache = s;
  const blocks = await j('/api/v1/blocks');
  const era = eraFor(s.circulating_supply, s);
  const sorted = [...blocks].sort((a, b) => a.height - b.height);
  let dt = 0, dn = 0;
  for (let i = 1; i < sorted.length; i++) { const d = sorted[i].timestamp - sorted[i - 1].timestamp; if (d > 0 && d < 600000) { dt += d; dn++; } }
  const avg = dn ? dt / dn / 1000 : null;
  const targetS = (s.target_block_time_ms || 100) / 1000;

  if (gen !== renderGen) return;
  $('app').innerHTML = `
  <div class="section" style="padding-top:22px">
    <div class="breadcrumb"><a href="#/">Overview</a> / Blocks</div>
    <div class="page-title"><span class="pi">${icon(IC.dag)}</span><h1>Blocks</h1></div>

    <div class="stat-grid" style="margin-bottom:18px">
      <div class="stat-card"><div class="sk">Chain height</div><div class="sv">${commas(s.height)}</div></div>
      <div class="stat-card"><div class="sk">Blue score</div><div class="sv">${commas(s.blue_score)}</div></div>
      <div class="stat-card"><div class="sk">Average block time</div><div class="sv">${avg ? avg.toFixed(2) + 's' : '—'}<span class="unit">target ${targetS}s</span></div></div>
      <div class="stat-card"><div class="sk">Difficulty</div><div class="sv">${commas(s.difficulty)}<span class="unit">${era.label}</span></div></div>
    </div>

    <p class="lead-note">${commas(blocks.length)} most recent main-chain blocks &middot; height ${commas(s.height)} &middot; blue score ${commas(s.blue_score)} &middot; ${targetS}s target interval</p>

    <div style="margin-bottom:14px">
      <input id="blockFilter" class="mono" style="width:100%;max-width:420px;background:var(--card);border:1px solid var(--border2);border-radius:10px;padding:10px 14px;font-size:13px;outline:none" placeholder="Filter by height or hash&hellip;">
    </div>

    <div class="card">
      <div class="scroll">
        <table><thead><tr><th>Timestamp</th><th>Height</th><th>Hash</th><th>Blue score</th><th>Era</th><th>Transactions</th><th>Miner</th></tr></thead>
        <tbody id="blockRows">${blocks.map((b) => `
          <tr class="clickable blockrow" data-h="${b.height}" data-hash="${esc(b.hash)}" onclick="location.hash='#/block/${b.height}'">
            <td class="mut" title="${new Date(b.timestamp).toLocaleString()}">${agoShort(b.timestamp)}</td>
            <td class="mono h-num">${commas(b.height)}</td>
            <td class="mono mut" title="${esc(b.hash)}">${short(b.hash)}${cp(b.hash)}</td>
            <td class="mono">${b.blue_score != null ? commas(b.blue_score) : '—'}</td>
            <td><span class="badge ${era.cls}">${era.label}</span></td>
            <td>${b.transfers || b.tx_count ? `<span class="badge b-tf">${b.transfers || b.tx_count} transfer</span>` : '<span class="empty">empty</span>'}</td>
            <td class="mono mut" title="${esc(b.miner || '')}">${b.miner ? ownerMark(b.miner, false) : '—'}</td>
          </tr>`).join('') || '<tr><td colspan="7" class="empty">no blocks yet</td></tr>'}</tbody></table>
      </div>
    </div>
  </div>`;
  $('blockFilter').addEventListener('input', (e) => {
    const q = e.target.value.trim().toLowerCase();
    document.querySelectorAll('.blockrow').forEach((r) => {
      const match = !q || r.dataset.h.includes(q) || r.dataset.hash.toLowerCase().includes(q);
      r.style.display = match ? '' : 'none';
    });
  });
  setFootMeta(s);
}

async function viewBlockDetail(id, gen) {
  let b, fam, eco, bio, ms;
  try { b = await j('/api/v1/block/' + encodeURIComponent(id)); }
  catch (e) { if (gen === renderGen) $('app').innerHTML = `<div class="section" style="padding-top:22px"><div class="placeholder err">Block not found (pruned below the finality point, or it never existed).</div></div>`; return; }
  try { fam = await j('/api/v1/block/' + encodeURIComponent(id) + '/family'); } catch (_) { fam = null; }
  try { eco = await j('/api/v1/block/' + encodeURIComponent(id) + '/economic-entity'); } catch (_) { eco = null; }
  try { bio = await j('/api/v1/block/' + encodeURIComponent(id) + '/economic-biography'); } catch (_) { bio = null; }
  try { ms = await j('/api/v1/block/' + encodeURIComponent(b.hash || id) + '/mergeset'); } catch (_) { ms = null; }
  if (!statusCache) { try { statusCache = await j('/api/v1/status'); } catch (_) {} }
  const s = statusCache;

  const tf = b.transfers || [];
  const isChain = fam && typeof fam.is_chain_block === 'boolean' ? (fam.is_chain_block ? 'Yes &mdash; selected chain' : 'No &mdash; non-selected DAG block') : '—';
  const blues = (ms && ms.mergeset_blues) || [];
  const reds = (ms && ms.mergeset_reds) || [];

  if (gen !== renderGen) return;
  $('app').innerHTML = `
  <div class="section" style="padding-top:22px">
    <div class="breadcrumb"><a href="#/">Overview</a> / <a href="#/blocks">Blocks</a> / #${commas(b.height)}</div>
    <div class="page-title"><span class="pi">${icon(IC.dag)}</span><h1>Block #${commas(b.height)}</h1>
      ${b.birth_ok ? '<span class="badge b-sh">birth certificate verified</span>' : '<span class="badge" style="color:var(--danger);background:var(--danger-soft);border-color:#f0c4bf">invalid / genesis</span>'}
    </div>
    <div class="actions">
      <button class="btn primary" id="dlAudit">Download audit JSON</button>
      <button class="btn" id="dlMergeset">Download mergeset</button>
      <button class="btn" id="dlPack">Audit pack (tip+block)</button>
    </div>

    <div class="card">
      <h3>Main information</h3>
      <table class="kvtable">
        <tr><td class="k">Block hash${info('The Blake3-512 hash committing to every field of this block header.')}</td><td class="v">${fullHash(b.hash)}</td></tr>
        <tr><td class="k">Settlement ID${info('A 512-bit settlement identifier derived from this block, used for bank-grade notarization.')}</td><td class="v">${fullHash(b.settlement_id)}</td></tr>
        <tr><td class="k">Height</td><td class="v">${commas(b.height)}</td></tr>
        <tr><td class="k">Blue score${info("GHOSTDAG blue score: the number of blue (honestly-ordered) blocks in this block's past.")}</td><td class="v">${b.blue_score != null ? commas(b.blue_score) : (fam && fam.blue_score != null ? commas(fam.blue_score) : '—')}</td></tr>
        <tr><td class="k">Is chain block${info("Whether this block is on the selected GHOSTDAG chain (Hassan's main chain) rather than a non-selected red DAG block.")}</td><td class="v">${isChain}</td></tr>
        <tr><td class="k">Difficulty</td><td class="v">${commas(b.difficulty)}</td></tr>
        <tr><td class="k">Nonce</td><td class="v">${esc(b.nonce)}</td></tr>
        <tr><td class="k">State root</td><td class="v">${fullHash(b.state_root)}</td></tr>
        <tr><td class="k">Merkle root</td><td class="v">${fullHash(b.merkle_root)}</td></tr>
        <tr><td class="k">Version</td><td class="v">${b.version != null ? esc(b.version) : '—'}</td></tr>
        <tr><td class="k">UTXO txs / custody</td><td class="v">${commas(b.utxo_txs || 0)} / ${commas(b.custody_ops || 0)}</td></tr>
        <tr><td class="k">Timestamp</td><td class="v">${new Date(b.timestamp).toLocaleString()} <span class="faint">(${agoShort(b.timestamp)})</span></td></tr>
      </table>
    </div>

    <div class="card">
      <h3>Connections <span class="r">GHOSTDAG topology</span></h3>
      <table class="kvtable">
        <tr><td class="k">Selected parent${info('The parent with the highest blue score — the block this one directly extends on the selected chain.')}</td><td class="v">${fam && fam.selected_parent ? hashLink(fam.selected_parent, 'block') + ' ' + cp(fam.selected_parent) : (ms && ms.selected_parent ? hashLink(ms.selected_parent, 'block') + ' ' + cp(ms.selected_parent) : '—')}</td></tr>
        <tr><td class="k">Parents</td><td class="v list">${(b.parents || []).length ? b.parents.map((p) => hashLink(p, 'block')).join('') : '—'}</td></tr>
        <tr><td class="k">Children</td><td class="v list">${fam && (fam.children || []).length ? fam.children.map((c) => hashLink(c, 'block')).join('') : '<span class="faint">none yet</span>'}</td></tr>
        <tr><td class="k">Sibling tips</td><td class="v list">${fam && (fam.sibling_tips || []).length ? fam.sibling_tips.map((c) => hashLink(c, 'block')).join('') : '<span class="faint">none</span>'}</td></tr>
        <tr><td class="k">Blue mergeset size${info('How many blocks this one merged and colored blue (honest) under the GHOSTDAG k-cluster rule.')}</td><td class="v">${fam && fam.blue_mergeset_size != null ? commas(fam.blue_mergeset_size) : (blues.length ? commas(blues.length) : '—')}</td></tr>
        <tr><td class="k">Red mergeset size${info('How many merged blocks violated the k-cluster rule and were colored red (excluded from the blue set).')}</td><td class="v">${fam && fam.red_mergeset_size != null ? commas(fam.red_mergeset_size) : (reds.length ? commas(reds.length) : '—')}</td></tr>
        <tr><td class="k">Mergeset blues</td><td class="v list">${blues.length ? blues.map((h) => hashLink(h, 'block')).join('') : '<span class="faint">none</span>'}</td></tr>
        <tr><td class="k">Mergeset reds</td><td class="v list">${reds.length ? reds.map((h) => hashLink(h, 'block')).join('') : '<span class="faint">none</span>'}</td></tr>
      </table>
    </div>

    <div class="card">
      <h3>Issuance &amp; settlement <span class="r">Hassan-specific notarization</span></h3>
      <table class="kvtable">
        <tr><td class="k">Issuer</td><td class="v">${b.issuer ? ownerMark(b.issuer) + ' ' + cp(b.issuer) : '<span class="faint">— (genesis)</span>'}</td></tr>
        <tr><td class="k">Miner / payee</td><td class="v">${b.miner ? ownerMark(b.miner) + ' ' + cp(b.miner) : '—'}</td></tr>
        <tr><td class="k">Birth certificate${info("An ML-DSA-87 signature over the block's settlement ID, verifiable anywhere without trusting this node.")}</td><td class="v">${fullHash(b.birth_certificate)}</td></tr>
        <tr><td class="k">Registry ops</td><td class="v">${b.registry_ops != null ? commas(b.registry_ops) : 0}</td></tr>
      </table>
    </div>

    ${eco ? `
    <div class="card">
      <h3>${icon(IC.bank)} Economic Entity <span class="r">E = (H, T, P, C, L, F)</span></h3>
      <table class="kvtable">
        <tr><td class="k">Instrument type${info('Provenance Record: the formal type of economic instrument this block represents.')}</td><td class="v">${esc(eco.provenance.instrument_type)}</td></tr>
        <tr><td class="k">Issuing authority${info('Provenance Record: the primary issuer who notarized this instrument (its Birth Certificate).')}</td><td class="v">${eco.provenance.issuing_authority ? ownerMark(eco.provenance.issuing_authority) : '<span class="faint">— (genesis)</span>'}</td></tr>
        <tr><td class="k">Jurisdiction</td><td class="v mono">${esc(eco.provenance.jurisdiction)}</td></tr>
        <tr><td class="k">Beneficial owner${info('Custody Chain: current recipient of record for this block\u2019s issuance (king mark = current owner of record).')}</td><td class="v">${eco.custody.beneficial_owner.address ? ownerMark(eco.custody.beneficial_owner.address) + ` <span class="mut">(balance ${hsn(eco.custody.beneficial_owner.current_balance)} HSN)</span>` : '—'}</td></tr>
        <tr><td class="k">Archive custodian${info('Custody Chain: whether the node currently serving this data retains full history (HASSAN_ARCHIVAL=1) instead of pruning it.')}</td><td class="v">${eco.custody.archive_custodian.is_local_node_archival ? 'Yes' : 'No (pruning node)'}</td></tr>
        <tr><td class="k">Economic offspring${info('Lineage Graph: descendant blocks directly extending this one.')}</td><td class="v">${eco.lineage.economic_offspring.length ? eco.lineage.economic_offspring.map((c) => hashLink(c, 'block')).join('') : '<span class="faint">none yet</span>'}</td></tr>
        <tr><td class="k">Economic siblings${info('Lineage Graph: parallel blocks GHOSTDAG preserves instead of discarding as orphans.')}</td><td class="v">${eco.lineage.economic_siblings.length ? eco.lineage.economic_siblings.map((c) => hashLink(c, 'block')).join('') : '<span class="faint">none</span>'}</td></tr>
        <tr><td class="k">Economic finality${info('Whether this block is beyond the reorg window (confirmations \u2265 finality depth) and its claims are considered settled.')}</td><td class="v">${eco.finality.is_economically_final ? `<span class="badge b-sh">final</span>` : `<span class="mut">pending (${commas(eco.finality.confirmations ?? 0)} / ${commas(eco.finality.finality_depth)} confirmations)</span>`}</td></tr>
      </table>
    </div>

    <div class="card">
      <h3>Cost Basis <span class="r">illustrative estimate — not measured data</span></h3>
      <table class="kvtable">
        <tr><td class="k">Estimated hash attempts${info('Expected PoW hash attempts for this block, approximated directly from its difficulty (target = MAX_TARGET / difficulty).')}</td><td class="v mono">${commas(eco.cost_basis.estimated_hashes)}</td></tr>
        <tr><td class="k">Estimated energy cost</td><td class="v">$${eco.cost_basis.estimated_energy_cost_usd.toFixed(6)}</td></tr>
        <tr><td class="k">Estimated hardware depreciation</td><td class="v">$${eco.cost_basis.estimated_hardware_depreciation_usd.toFixed(6)}</td></tr>
        <tr><td class="k">Estimated capital opportunity cost</td><td class="v">$${eco.cost_basis.estimated_capital_opportunity_cost_usd.toFixed(6)}</td></tr>
        <tr><td class="k">Estimated total cost basis</td><td class="v" style="font-weight:600">$${eco.cost_basis.estimated_total_cost_usd.toFixed(6)}</td></tr>
      </table>
      <p class="mut" style="margin:10px 2px 0;font-size:12.5px">${esc(eco.cost_basis.methodology)}</p>
    </div>` : ''}

    ${eco && eco.audit_trail ? `
    <div class="card">
      <h3>Audit Trail <span class="r">hash-chained verification events</span></h3>
      <p class="mut" style="margin:2px 2px 10px;font-size:12.5px">Deterministically re-derived from this block's own consensus data, not a stored log — any node computes the same chain, so nothing here needs to be trusted. Each entry hashes the previous one (Blake3-512); tampering with any entry changes every hash after it.</p>
      <div class="scroll"><table><thead><tr><th>#</th><th>Event</th><th>Detail</th><th>Entry hash</th></tr></thead>
        <tbody>${eco.audit_trail.entries.map((e) => `<tr><td class="mut">${e.sequence}</td><td><span class="badge b-sh" style="text-transform:none">${esc(e.event.replace(/_/g, ' '))}</span></td><td class="mono mut" style="font-size:12px" title="${esc(e.detail)}">${shortDetail(e.detail)}</td><td title="${esc(e.entry_hash)}">${short(e.entry_hash)} ${cp(e.entry_hash)}</td></tr>`).join('')}</tbody></table></div>
      <table class="kvtable" style="margin-top:10px"><tr><td class="k">Trail hash${info('A single 512-bit fingerprint of the whole audit trail (the last entry\u2019s hash) \u2014 two nodes with the same valid chain state always compute the same value.')}</td><td class="v">${fullHash(eco.audit_trail.trail_hash)}</td></tr></table>
    </div>` : ''}

    ${bio ? `
    <div class="card">
      <h3>Economic Biography <span class="r">life history</span></h3>
      <p style="margin:4px 2px"><strong>Origin:</strong> ${shortDetail(bio.origin)}</p>
      ${bio.transformations.length ? `<p style="margin:4px 2px"><strong>Transformations:</strong></p><ul style="margin:2px 0 8px 20px;padding:0">${bio.transformations.map((t) => `<li class="mut" style="margin:2px 0">${shortDetail(t)}</li>`).join('')}</ul>` : ''}
      <p style="margin:4px 2px"><strong>Current state:</strong> ${shortDetail(bio.current_state)}</p>
    </div>` : ''}

    <div class="card">
      <h3>Transfers <span class="r">${tf.length} in this block</span></h3>
      ${tf.length ? `<div class="scroll"><table><thead><tr><th>From</th><th>To</th><th>Amount</th><th>Fee</th><th>Nonce</th></tr></thead>
        <tbody>${tf.map((t) => `<tr class="clickable" onclick="location.hash='#/tx/${esc(t.tx_hash)}'"><td class="mono" onclick="event.stopPropagation()">${ownerMark(t.from)}</td><td class="mono" onclick="event.stopPropagation()">${ownerMark(t.to)}</td><td class="mono">${hsn(t.amount)} HSN</td><td class="mono mut">${t.fee != null ? hsn(t.fee) : '—'}</td><td class="mut">${t.nonce}</td></tr>`).join('')}</tbody></table></div>`
      : '<div class="placeholder">no transactions — empty block</div>'}
    </div>
  </div>`;
  if (s) setFootMeta(s);
  const bid = b.hash || id;
  $('dlAudit')?.addEventListener('click', async () => {
    try { downloadJson(`hassan-block-${b.height}-audit.json`, await j('/api/v1/block/' + encodeURIComponent(bid) + '/audit')); }
    catch (e) { toast('audit download failed'); }
  });
  $('dlMergeset')?.addEventListener('click', async () => {
    try { downloadJson(`hassan-block-${b.height}-mergeset.json`, await j('/api/v1/block/' + encodeURIComponent(bid) + '/mergeset')); }
    catch (e) { toast('mergeset download failed'); }
  });
  $('dlPack')?.addEventListener('click', async () => {
    try { downloadJson(`hassan-audit-pack-${b.height}.json`, await j('/api/v1/audit/pack?block=' + encodeURIComponent(bid))); }
    catch (e) { toast('pack download failed'); }
  });
}

async function viewTxDetail(txHash, gen) {
  let t;
  try { t = await j('/api/v1/tx/' + encodeURIComponent(txHash) + '/economic-entity'); }
  catch (e) { if (gen === renderGen) $('app').innerHTML = `<div class="section" style="padding-top:22px"><div class="placeholder err">Transfer not found (not pending, and not on the selected chain).</div></div>`; return; }
  if (!statusCache) { try { statusCache = await j('/api/v1/status'); } catch (_) {} }
  const s = statusCache;
  const isPending = t.lineage.status === 'Pending';
  const journey = t.journey || {};

  if (gen !== renderGen) return;
  $('app').innerHTML = `
  <div class="section" style="padding-top:22px">
    <div class="breadcrumb"><a href="#/">Overview</a> / Transfer</div>
    <div class="page-title"><span class="pi">${icon(IC.bank)}</span><h1>Transfer</h1>
      ${isPending ? '<span class="badge" style="color:var(--blue);background:var(--blue-soft);border-color:#c5d6ef">pending in mempool</span>' : '<span class="badge b-sh">confirmed</span>'}
    </div>

    <div class="card">
      <h3>Birth <span class="r">signature &amp; sequencing</span></h3>
      <table class="kvtable">
        <tr><td class="k">Transfer hash</td><td class="v">${fullHash(t.tx_hash)}</td></tr>
        <tr><td class="k">Signed by</td><td class="v">${ownerMark(t.signed_by)}</td></tr>
        <tr><td class="k">Nonce${info('Sequence number for the sender\u2019s account — enforces exactly-once ordering per sender.')}</td><td class="v">${t.nonce}</td></tr>
      </table>
    </div>

    <div class="card">
      <h3>Custody <span class="r">economic agents</span></h3>
      <table class="kvtable">
        <tr><td class="k">Remitting agent</td><td class="v">${ownerMark(t.remitting_agent)}</td></tr>
        <tr><td class="k">Beneficiary agent</td><td class="v">${ownerMark(t.beneficiary_agent)}</td></tr>
        <tr><td class="k">Amount</td><td class="v mono">${hsn(t.amount)} HSN</td></tr>
        <tr><td class="k">Fee (burned)</td><td class="v mono">${hsn(t.fee)} HSN</td></tr>
      </table>
    </div>

    <div class="card">
      <h3>Lineage <span class="r">settlement status</span></h3>
      <table class="kvtable">
        <tr><td class="k">Status</td><td class="v">${isPending ? '<span class="mut">Pending &mdash; awaiting inclusion in a block</span>' : 'Confirmed'}</td></tr>
        ${!isPending ? `<tr><td class="k">Containing block</td><td class="v">${hashLink(t.lineage.containing_block, 'block')} ${cp(t.lineage.containing_block)}</td></tr>
        <tr><td class="k">Height</td><td class="v">${t.lineage.height != null ? commas(t.lineage.height) : '—'}</td></tr>` : ''}
      </table>
    </div>

    <div class="card">
      <h3>Journey <span class="r">mempool propagation timing</span></h3>
      <table class="kvtable">
        <tr><td class="k">First seen (this node)${info('When this node\u2019s mempool first admitted this transfer. Best-effort, per-node telemetry — not consensus data.')}</td><td class="v">${journey.first_seen_ms != null ? new Date(journey.first_seen_ms).toLocaleString() : '<span class="faint">unknown (node restarted, or seen by a different node)</span>'}</td></tr>
        <tr><td class="k">Confirmed at</td><td class="v">${journey.confirmed_at_ms != null ? new Date(journey.confirmed_at_ms).toLocaleString() : '<span class="faint">not yet confirmed</span>'}</td></tr>
        <tr><td class="k">Mempool dwell time</td><td class="v">${journey.mempool_dwell_ms != null ? commas(journey.mempool_dwell_ms) + ' ms' : '—'}</td></tr>
      </table>
    </div>
  </div>`;
  if (s) setFootMeta(s);
}

async function viewAddress(addr, gen) {
  addr = decodeURIComponent(addr);
  let r;
  try { r = await j('/api/v1/account/' + encAddr(addr)); }
  catch (e) { if (gen === renderGen) $('app').innerHTML = `<div class="section" style="padding-top:22px"><div class="placeholder err">Could not look up this address.</div></div>`; return; }
  if (gen !== renderGen) return;
  $('app').innerHTML = `
  <div class="section" style="padding-top:22px">
    <div class="breadcrumb"><a href="#/">Overview</a> / Address</div>
    <div class="page-title"><span class="pi">${icon(IC.king)}</span><h1>Account</h1>
      <span class="badge b-sh" title="Current owner of record">owner</span>
    </div>
    <div class="card">
      <div class="pad">
        <div class="mut" style="font-size:11px;text-transform:uppercase;letter-spacing:.6px;margin-bottom:8px">Balance</div>
        <div class="balance">${hsn(r.balance)} <span style="font-size:16px;color:var(--mut);font-family:var(--sans)">HSN</span></div>
        <div class="faint mono" style="margin:4px 0 0">${commas(r.balance)} base units (1 HSN = 10^8 base units)</div>
      </div>
      <table class="kvtable">
        <tr><td class="k">Owner address</td><td class="v">${ownerMark(r.address, false)} ${cp(r.address)}</td></tr>
        <tr><td class="k">Next nonce${info('The next transaction sequence number this address must use to prevent replay.')}</td><td class="v">${r.nonce}</td></tr>
        <tr><td class="k">Titles held</td><td class="v">${r.titles_held != null ? commas(r.titles_held) : 0}</td></tr>
      </table>
    </div>
    <div class="card"><h3>UTXOs</h3><div class="scroll"><table><thead><tr><th>Outpoint</th><th>Value</th><th>Created blue</th><th>Predicate</th></tr></thead>
    <tbody id="utxoRows"><tr><td colspan="4" class="empty">loading…</td></tr></tbody></table></div></div>
    <div class="card"><h3>Indexed transfer history <span class="r" id="histLabel"></span></h3>
      <div class="scroll"><table><thead><tr><th>Tx</th><th>From</th><th>To</th><th>Amount</th><th>Height</th></tr></thead>
      <tbody id="histRows"><tr><td colspan="5" class="empty">loading…</td></tr></tbody></table></div>
    </div>
  </div>`;
  try {
    const u = await j('/api/v1/utxos/' + encAddr(addr));
    if (gen !== renderGen) return;
    const list = u.utxos || [];
    $('utxoRows').innerHTML = list.map((o) => `<tr><td class="mono mut" title="${esc(o.txid)}:${o.vout}">${short(o.txid)}:${o.vout}${o.coinbase ? ' <span class="badge b-sh">coinbase</span>' : ''}</td><td class="mono">${hsn(o.value)} HSN</td><td class="mut">${o.created_blue != null ? commas(o.created_blue) : '—'}</td><td class="mut">${esc(o.predicate || '')}</td></tr>`).join('') || '<tr><td colspan="4" class="empty">no UTXOs</td></tr>';
  } catch (_) {
    if (gen === renderGen) $('utxoRows').innerHTML = '<tr><td colspan="4" class="empty">UTXO lookup failed</td></tr>';
  }
  try {
    const h = await j('/api/v1/address/' + encAddr(addr) + '/history');
    if (gen !== renderGen) return;
    if (h.label) $('histLabel').textContent = h.label;
    const txs = h.txs || [];
    $('histRows').innerHTML = txs.map((t) => `<tr class="clickable" onclick="location.hash='#/tx/${esc(t.tx_hash)}'"><td class="mono mut">${short(t.tx_hash)}</td><td class="mono" onclick="event.stopPropagation()">${ownerMark(t.from)}</td><td class="mono" onclick="event.stopPropagation()">${ownerMark(t.to)}</td><td class="mono">${hsn(t.amount)} HSN</td><td class="mono h-num">${commas(t.height)}</td></tr>`).join('') || '<tr><td colspan="5" class="empty">no indexed transfers yet</td></tr>';
  } catch (_) {
    if (gen === renderGen) $('histRows').innerHTML = '<tr><td colspan="5" class="empty">indexer history unavailable</td></tr>';
  }
}

async function viewFees(gen) {
  const [f, mp, s] = await Promise.all([j('/api/v1/fee/estimate'), j('/api/v1/mempool'), j('/api/v1/status')]);
  statusCache = s;
  const congested = BigInt(f.min_relay_fee) > BigInt(f.protocol_min_fee);
  if (gen !== renderGen) return;
  $('app').innerHTML = `
  <div class="section" style="padding-top:22px">
    <div class="breadcrumb"><a href="#/">Overview</a> / Fee market</div>
    <div class="page-title"><span class="pi">${icon(IC.mem)}</span><h1>Fee market</h1></div>
    <p class="lead-note">Hassan admits transactions by ancestor-package fee-rate (account-nonce CPFP), supports package-aware Replace-by-Fee (RBF), and raises its relay minimum automatically once the mempool gets congested &mdash; the same category of policy depth as Bitcoin's fee market, at a much earlier stage.</p>

    <div class="stat-grid" style="grid-template-columns:repeat(2,1fr);margin-bottom:20px">
      <div class="card" style="margin-bottom:0">
        <h3>Percentile fee estimates</h3>
        <div class="fee-row"><span class="lbl"><span class="swatch" style="background:var(--teal)"></span>Low priority</span><span class="val">${hsn(f.low)} HSN</span></div>
        <div class="fee-row"><span class="lbl"><span class="swatch" style="background:var(--accent)"></span>Medium priority</span><span class="val">${hsn(f.medium)} HSN</span></div>
        <div class="fee-row"><span class="lbl"><span class="swatch" style="background:var(--danger)"></span>High priority</span><span class="val">${hsn(f.high)} HSN</span></div>
        <div class="fee-row"><span class="lbl">Sampled from mempool</span><span class="val">${commas(f.mempool_txs)} tx</span></div>
        <div class="fee-row"><span class="lbl">Ancestor packages${info('Contiguous same-sender nonce chains ranked by package fee-rate (CPFP-style: a high-fee child can pay for a low-fee parent).')}</span><span class="val">${commas(f.package_count || 0)}</span></div>
        <div class="fee-row"><span class="lbl">Best package fee</span><span class="val">${hsn(f.best_package_fee || 0)} HSN</span></div>
      </div>
      <div class="card" style="margin-bottom:0">
        <h3>Congestion &amp; relay policy</h3>
        <div class="fee-row"><span class="lbl">Protocol minimum fee</span><span class="val">${hsn(f.protocol_min_fee)} HSN</span></div>
        <div class="fee-row"><span class="lbl">Current relay minimum</span><span class="val" style="color:${congested ? 'var(--danger)' : 'var(--teal)'}">${hsn(f.min_relay_fee)} HSN</span></div>
        <div class="fee-row"><span class="lbl">Congestion state</span><span class="val" style="font-size:13px">${congested ? '<span class="err">congested</span>' : '<span style="color:var(--teal)">normal</span>'}</span></div>
        <div class="fee-row"><span class="lbl">Replace-by-fee</span><span class="val" style="font-size:13px;color:var(--teal)">package-aware</span></div>
      </div>
    </div>

    <div class="section-h" style="margin-top:0"><h2>Mempool</h2><span class="r">${commas(mp.length)} pending transactions</span></div>
    <div class="card">
      <div class="scroll">
        <table><thead><tr><th>Tx hash</th><th>From</th><th>To</th><th>Amount</th><th>Fee</th><th>Nonce</th></tr></thead>
        <tbody>${mp.map((t) => `<tr><td class="mono mut" title="${esc(t.tx_hash)}">${short(t.tx_hash)}</td><td class="mono">${ownerMark(t.from)}</td><td class="mono">${ownerMark(t.to)}</td><td class="mono">${hsn(t.amount)} HSN</td><td class="mono" style="color:var(--accent-ink)">${hsn(t.fee)} HSN</td><td class="mut">${t.nonce}</td></tr>`).join('') || '<tr><td colspan="6" class="empty">mempool is empty</td></tr>'}</tbody></table>
      </div>
    </div>
  </div>`;
  setFootMeta(s);
}

async function viewPruning(gen) {
  const [p, s] = await Promise.all([j('/api/v1/pruning/stats'), j('/api/v1/status')]);
  statusCache = s;
  let body;
  if (!p.linear_proof_headers) {
    body = '<div class="placeholder">This node has not pruned yet — both proof types converge to the same full chain until a pruning point exists. Mine past the pruning depth to see a live comparison.</div>';
  } else {
    const ratio = p.compression_ratio || '—';
    body = `
      <div class="compression-banner"><div><div class="cap">Multi-level (NIPoPoW/FlyClient-style interlink) proof vs. shipping every header from genesis, measured live on this node's own chain right now.</div></div><div class="big">${ratio}</div></div>
      <div class="tile-grid">
        <div class="tile"><div class="tk">Linear proof headers</div><div class="tv">${commas(p.linear_proof_headers)}</div><div class="ts">one header per block, genesis &rarr; pruning point</div></div>
        <div class="tile"><div class="tk">Multi-level proof headers</div><div class="tv acc">${commas(p.multilevel_proof_headers)}</div><div class="ts">${commas(p.multilevel_recent_headers)} full recent + ${commas(p.multilevel_hops)} interlink hops</div></div>
        <div class="tile"><div class="tk">Compression</div><div class="tv tealacc">${ratio}</div><div class="ts">fewer headers a syncing node must fetch &amp; verify</div></div>
        <div class="tile"><div class="tk">Verified work</div><div class="tv">${p.verified_work ? commas(p.verified_work) : '—'}</div><div class="ts">hash-checked lower bound &mdash; cannot be forged</div></div>
        <div class="tile"><div class="tk">Estimated total work</div><div class="tv">${p.estimated_total_work ? commas(p.estimated_total_work) : '—'}</div><div class="ts">statistical estimate incl. skipped history</div></div>
        <div class="tile"><div class="tk">Archival node</div><div class="tv ${p.archival ? 'tealacc' : ''}">${p.archival ? 'yes' : 'no'}</div><div class="ts">can this node serve either proof type</div></div>
      </div>`;
  }
  if (gen !== renderGen) return;
  $('app').innerHTML = `
  <div class="section" style="padding-top:22px">
    <div class="breadcrumb"><a href="#/">Overview</a> / Pruning proofs</div>
    <div class="page-title"><span class="pi">${icon(IC.proof)}</span><h1>Pruning proofs</h1></div>
    <p class="lead-note">Hassan ships two cold-start sync proofs: a simple <b>linear</b> proof (one header per block from genesis) and a succinct <b>multi-level</b> proof that compresses old, settled history to roughly O(log n) headers while still shipping the recent finality window in full, exact-DAA-checked.</p>
    ${body}
  </div>`;
  setFootMeta(s);
}

async function viewRegistry(gen) {
  const [titles, escrows, vaults, s] = await Promise.all([
    j('/api/v1/titles'),
    j('/api/v1/escrows'),
    j('/api/v1/bdpe/vaults').catch(() => []),
    j('/api/v1/status'),
  ]);
  statusCache = s;
  if (gen !== renderGen) return;
  const vaultList = Array.isArray(vaults) ? vaults : [];
  $('app').innerHTML = `
  <div class="section" style="padding-top:22px">
    <div class="breadcrumb"><a href="#/">Overview</a> / Registry</div>
    <div class="page-title"><span class="pi">${icon(IC.lock)}</span><h1>Titles &amp; escrow</h1></div>
    <p class="lead-note">Title deeds and registry escrow are on-ledger. Peer UTXO escrow lives under <a href="#/escrow">Escrow</a>; inspect balances via address search.</p>
    <div class="card">
      <h3>BDPE vaults (UTXO) <span class="r">${commas(vaultList.length)} · <a href="#/escrow">Escrow tab</a></span></h3>
      <div class="scroll"><table><thead><tr><th>Outpoint</th><th>Buyer</th><th>Seller</th><th>Value</th><th>Timeout blue</th><th>Reached</th></tr></thead>
      <tbody>${vaultList.map((v) => `<tr><td class="mono mut">${v.txid ? `<a href="#/tx/${esc(v.txid)}" title="${esc(v.txid)}:${v.vout}">${short(v.txid)}:${v.vout}</a>` : '—'}</td><td class="mono">${ownerMark(v.buyer)}</td><td class="mono">${ownerMark(v.seller)}</td><td class="mono">${hsn(v.value)} HSN</td><td class="mono">${commas(v.timeout_blue)}</td><td>${v.timeout_reached ? '<span class="badge b-era-easy">yes</span>' : '<span class="badge b-era-ramp">no</span>'}</td></tr>`).join('') || '<tr><td colspan="6" class="empty">no BDPE vaults in UTXO set</td></tr>'}</tbody></table></div>
    </div>
    <div class="card">
      <h3>Titles <span class="r">${commas(titles.length)}</span></h3>
      <div class="scroll"><table><thead><tr><th>Title</th><th>Asset class</th><th>Owner</th><th>Status</th></tr></thead>
      <tbody>${titles.map((t) => `<tr><td class="mono mut" title="${esc(t.title_id)}">${short(t.title_id)}</td><td>${esc(t.asset_class)}</td><td class="mono">${ownerMark(t.current_owner)}</td><td>${t.in_escrow ? '<span class="badge b-era-ramp">in escrow</span>' : '<span class="badge b-era-easy">clear</span>'}</td></tr>`).join('') || '<tr><td colspan="4" class="empty">no titles on file yet</td></tr>'}</tbody></table></div>
    </div>
    <div class="card">
      <h3>Registry escrows <span class="r">${commas(escrows.length)}</span></h3>
      <div class="scroll"><table><thead><tr><th>Escrow</th><th>Buyer</th><th>Seller</th><th>Amount</th><th>Timeout h</th><th>Status</th></tr></thead>
      <tbody>${escrows.map((e) => `<tr><td class="mono mut" title="${esc(e.escrow_id)}">${short(e.escrow_id)}</td><td class="mono">${ownerMark(e.buyer)}</td><td class="mono">${ownerMark(e.seller)}</td><td class="mono">${hsn(e.amount)} HSN</td><td class="mono">${e.timeout_blue != null ? commas(e.timeout_blue) : (e.timeout_height != null ? commas(e.timeout_height) : '—')}</td><td><span class="badge b-era-ramp">${esc(e.status)}</span></td></tr>`).join('') || '<tr><td colspan="6" class="empty">no open registry escrows</td></tr>'}</tbody></table></div>
    </div>
  </div>`;
  setFootMeta(s);
}

async function viewMempool(gen) {
  const [mp, s] = await Promise.all([j('/api/v1/mempool'), j('/api/v1/status')]);
  statusCache = s;
  if (gen !== renderGen) return;
  $('app').innerHTML = `
  <div class="section" style="padding-top:22px">
    <div class="breadcrumb"><a href="#/">Overview</a> / Mempool</div>
    <div class="page-title"><span class="pi">${icon(IC.mem)}</span><h1>Mempool</h1>
      <span class="badge b-tf">${commas(mp.length)} pending</span></div>
    <p class="lead-note">Transparent transfers awaiting inclusion — ancestor package fees and feerates shown when available.</p>
    <div class="card"><div class="scroll"><table><thead><tr><th>Tx</th><th>From</th><th>To</th><th>Amount</th><th>Fee</th><th>Feerate</th><th>Ancestors</th><th>Nonce</th></tr></thead>
    <tbody>${mp.map((t) => `<tr class="clickable" onclick="location.hash='#/tx/${esc(t.tx_hash)}'"><td class="mono mut" title="${esc(t.tx_hash)}">${short(t.tx_hash)}</td><td class="mono" onclick="event.stopPropagation()">${ownerMark(t.from)}</td><td class="mono" onclick="event.stopPropagation()">${ownerMark(t.to)}</td><td class="mono">${hsn(t.amount)} HSN</td><td class="mono">${hsn(t.fee)} HSN</td><td class="mono mut">${t.feerate != null ? t.feerate : '—'}</td><td class="mut">${t.ancestor_count != null ? t.ancestor_count : '—'}</td><td class="mut">${t.nonce}</td></tr>`).join('') || '<tr><td colspan="8" class="empty">mempool empty</td></tr>'}</tbody></table></div></div>
  </div>`;
  setFootMeta(s);
}

async function viewMining(gen) {
  const [m, s, tmpl, stratum, light] = await Promise.all([
    j('/api/v1/mining'), j('/api/v1/status'),
    j('/api/v1/mining/template').catch(() => ({})),
    j('/api/v1/stratum').catch(() => ({})),
    j('/api/v1/mining/light?max=25000').catch(() => ({})),
  ]);
  statusCache = s;
  if (gen !== renderGen) return;
  $('app').innerHTML = `
  <div class="section" style="padding-top:22px">
    <div class="breadcrumb"><a href="#/">Overview</a> / Mining</div>
    <div class="page-title"><span class="pi">${icon(IC.diff)}</span><h1>Mining</h1>
      <span class="badge b-sh">Blake3-512</span></div>
    <p class="lead-note">Blake3-512 PoW; target ${((s.target_block_time_ms || 100) / 1000).toFixed(2)}s. Bootstrap floor ${commas(m.min_difficulty || 7000)} until 1M HSN minted; then hard floor ${commas(m.hard_era_min_difficulty || 16777216)}. Solo miner, stratum, and light-mine API included.</p>
    <div class="stat-grid" style="margin-bottom:18px">
      <div class="stat-card"><div class="sk">Network difficulty</div><div class="sv">${commas(m.difficulty)}</div></div>
      <div class="stat-card"><div class="sk">Era floor</div><div class="sv">${commas(m.era_min_difficulty || s.era_min_difficulty)}</div></div>
      <div class="stat-card"><div class="sk">Share difficulty</div><div class="sv">${commas(m.default_share_difficulty || 16)}</div></div>
      <div class="stat-card"><div class="sk">Light mine H/s</div><div class="sv">${light.hashes_per_sec != null ? commas(light.hashes_per_sec) : '—'}</div><div class="ssub">${light.found ? 'share found' : (light.hashes_tried != null ? commas(light.hashes_tried) + ' tried' : '')}</div></div>
    </div>
    <div class="card"><h3>Template</h3><table class="kvtable">
      <tr><td class="k">Height hint</td><td class="v">${tmpl.height != null ? commas(tmpl.height) : '—'}</td></tr>
      <tr><td class="k">Difficulty</td><td class="v">${tmpl.difficulty != null ? commas(tmpl.difficulty) : '—'}</td></tr>
      <tr><td class="k">State root hint</td><td class="v">${fullHash(tmpl.state_root_hint)}</td></tr>
      <tr><td class="k">UTXO commitment</td><td class="v">${fullHash(tmpl.utxo_commitment)}</td></tr>
      <tr><td class="k">Parents</td><td class="v list">${(tmpl.parents || []).map((p) => hashLink(p, 'block')).join('') || '—'}</td></tr>
      <tr><td class="k">Selected txs</td><td class="v">${(tmpl.transactions || []).length}</td></tr>
    </table></div>
    <div class="card"><h3>Stratum</h3><table class="kvtable">
      <tr><td class="k">Notify job</td><td class="v">${stratum.notify ? esc(JSON.stringify(stratum.notify).slice(0, 120)) + '…' : '—'}</td></tr>
      <tr><td class="k">Workers</td><td class="v">${stratum.workers && stratum.workers.workers ? commas(stratum.workers.workers.length) : '0'}</td></tr>
    </table></div>
    <div class="card"><h3>Economics</h3><table class="kvtable">
      <tr><td class="k">Block reward</td><td class="v">${hsn(m.block_reward)} HSN</td></tr>
      <tr><td class="k">Treasury</td><td class="v">${hsn(m.treasury)} HSN</td></tr>
    </table></div>
  </div>`;
  setFootMeta(s);
}

async function viewNetwork(gen) {
  const [net, s, light] = await Promise.all([j('/api/v1/network'), j('/api/v1/status'), j('/api/v1/light/tip').catch(() => ({}))]);
  statusCache = s;
  if (gen !== renderGen) return;
  $('app').innerHTML = `
  <div class="section" style="padding-top:22px">
    <div class="breadcrumb"><a href="#/">Overview</a> / Network</div>
    <div class="page-title"><span class="pi">${icon(IC.chain)}</span><h1>Network</h1></div>
    <div class="stat-grid" style="margin-bottom:18px">
      <div class="stat-card"><div class="sk">Peers</div><div class="sv">${commas(net.peer_count || 0)}</div></div>
      <div class="stat-card"><div class="sk">Listening</div><div class="sv" style="font-size:16px">${net.listening ? 'yes' : 'no'}</div><div class="ssub mono">${esc(net.listen_addr || '—')}</div></div>
      <div class="stat-card"><div class="sk">Known addrs</div><div class="sv">${commas(net.known_addrs || 0)}</div></div>
      <div class="stat-card"><div class="sk">Banned</div><div class="sv">${commas(net.banned_count || 0)}</div></div>
    </div>
    <div class="card"><h3>Tips</h3><div class="pad list">${(net.tips || []).map((t) => `<div>${hashLink(t, 'block')} ${cp(t)}</div>`).join('') || '<span class="empty">no tips</span>'}</div></div>
    <div class="card"><h3>Light tip</h3><table class="kvtable">
      <tr><td class="k">Tip</td><td class="v">${fullHash(light.tip)}</td></tr>
      <tr><td class="k">Blue score</td><td class="v">${light.blue_score != null ? commas(light.blue_score) : '—'}</td></tr>
      <tr><td class="k">State root</td><td class="v">${fullHash(light.state_root)}</td></tr>
      <tr><td class="k">UTXO commitment</td><td class="v">${fullHash(light.utxo_commitment)}</td></tr>
      <tr><td class="k">Pruning point</td><td class="v">${fullHash(light.pruning_point)}</td></tr>
      <tr><td class="k">Supply ok</td><td class="v">${light.supply_ok === true ? 'yes' : (light.supply_ok === false ? 'no' : '—')}</td></tr>
    </table></div>
  </div>`;
  setFootMeta(s);
}

async function viewSupply(gen) {
  const [sup, s] = await Promise.all([j('/api/v1/supply'), j('/api/v1/status')]);
  statusCache = s;
  if (gen !== renderGen) return;
  $('app').innerHTML = `
  <div class="section" style="padding-top:22px">
    <div class="breadcrumb"><a href="#/">Overview</a> / Supply</div>
    <div class="page-title"><span class="pi">${icon(IC.coin)}</span><h1>Supply</h1>
      <span class="badge ${s.supply_ok === false ? 'b-era-btc' : 'b-sh'}">${s.supply_ok === false ? 'invariant fail' : 'invariant ok'}</span></div>
    <div class="card"><table class="kvtable">
      <tr><td class="k">Minted</td><td class="v">${hsn(sup.minted_supply)} HSN</td></tr>
      <tr><td class="k">Max supply</td><td class="v">${hsn(sup.max_supply)} HSN</td></tr>
      <tr><td class="k">Account balances</td><td class="v">${hsn(sup.account_balances)} HSN</td></tr>
      <tr><td class="k">UTXO value</td><td class="v">${hsn(sup.utxo_value)} HSN</td></tr>
      <tr><td class="k">Staked</td><td class="v">${hsn(sup.staked)} HSN</td></tr>
      <tr><td class="k">Cumulative issuance @ tip</td><td class="v">${hsn(sup.cumulative_issuance_at_tip)} HSN</td></tr>
    </table></div>
  </div>`;
  setFootMeta(s);
}

async function viewCustody(gen) {
  const [c, s] = await Promise.all([j('/api/v1/custody'), j('/api/v1/status')]);
  statusCache = s;
  if (gen !== renderGen) return;
  const rows = c.staked || [];
  $('app').innerHTML = `
  <div class="section" style="padding-top:22px">
    <div class="breadcrumb"><a href="#/">Overview</a> / Custody</div>
    <div class="page-title"><span class="pi">${icon(IC.lock)}</span><h1>Custody</h1>
      <span class="badge b-tf">mempool ${commas(c.custody_mempool || 0)}</span></div>
    <p class="lead-note">On-chain stake locks. Bridge exit/enter remain consensus-disabled until a real bridge ships.</p>
    <div class="card"><div class="scroll"><table><thead><tr><th>Owner</th><th>Amount</th></tr></thead>
    <tbody>${rows.map((r) => `<tr><td class="mono">${ownerMark(r.owner)}</td><td class="mono">${hsn(r.amount)} HSN</td></tr>`).join('') || '<tr><td colspan="2" class="empty">no stake locks</td></tr>'}</tbody></table></div></div>
  </div>`;
  setFootMeta(s);
}

async function viewVersionbits(gen) {
  const [vb, s] = await Promise.all([j('/api/v1/versionbits'), j('/api/v1/status')]);
  statusCache = s;
  if (gen !== renderGen) return;
  const deps = vb.deployments || vb.bits || (Array.isArray(vb) ? vb : null);
  let rows = '';
  if (Array.isArray(deps)) {
    rows = deps.map((d) => `<tr><td>${esc(d.name || d.bit || '')}</td><td class="mono">${esc(String(d.bit ?? ''))}</td><td><span class="badge b-sh">${esc(d.state || d.status || JSON.stringify(d))}</span></td></tr>`).join('');
  } else {
    rows = Object.keys(vb || {}).map((k) => `<tr><td>${esc(k)}</td><td colspan="2" class="mono">${esc(typeof vb[k] === 'object' ? JSON.stringify(vb[k]) : String(vb[k]))}</td></tr>`).join('');
  }
  $('app').innerHTML = `
  <div class="section" style="padding-top:22px">
    <div class="breadcrumb"><a href="#/">Overview</a> / Versionbits</div>
    <div class="page-title"><span class="pi">${icon(IC.gauge)}</span><h1>Versionbits</h1></div>
    <p class="lead-note">Soft-upgrade signaling status from the selected chain.</p>
    <div class="card"><div class="scroll"><table><thead><tr><th>Name / key</th><th>Bit</th><th>State</th></tr></thead>
    <tbody>${rows || '<tr><td colspan="3" class="empty">no deployments reported</td></tr>'}</tbody></table></div></div>
  </div>`;
  setFootMeta(s);
}

async function viewAnalytics(gen) {
  const [a, s, fees] = await Promise.all([
    j('/api/v1/analytics/history?limit=512'),
    j('/api/v1/status'),
    j('/api/v1/fees/history').catch(() => ({ samples: [] })),
  ]);
  statusCache = s;
  const pts = a.points || [];
  if (gen !== renderGen) return;
  $('app').innerHTML = `
  <div class="section" style="padding-top:22px">
    <div class="breadcrumb"><a href="#/">Overview</a> / Analytics</div>
    <div class="page-title"><span class="pi">${icon(IC.gauge)}</span><h1>Analytics</h1>
      <span class="badge b-tf">${commas(pts.length)} points</span></div>
    <p class="lead-note">Indexer series over selected-chain history — blue score, difficulty, fees, supply, mempool depth. TPS estimate ${a.tps_estimate != null ? Number(a.tps_estimate).toFixed(3) : '—'} over the window.</p>
    <div class="stat-grid" style="margin-bottom:18px">
      <div class="stat-card"><div class="sk">Indexed blocks</div><div class="sv">${commas(a.block_index_size || 0)}</div></div>
      <div class="stat-card"><div class="sk">Indexed txs</div><div class="sv">${commas(a.tx_index_size || 0)}</div></div>
      <div class="stat-card"><div class="sk">Addresses</div><div class="sv">${commas(a.address_index_size || 0)}</div></div>
      <div class="stat-card"><div class="sk">TPS (window)</div><div class="sv">${a.tps_estimate != null ? Number(a.tps_estimate).toFixed(2) : '—'}</div></div>
    </div>
    <div class="chart-grid">
      <div class="chart-card"><h3>Blue score</h3>${sparkline(pts, 'blue_score', '#1f5aab')}</div>
      <div class="chart-card"><h3>Difficulty</h3>${sparkline(pts, 'difficulty', '#b8941f')}</div>
      <div class="chart-card"><h3>Transfers / block</h3>${sparkline(pts, 'transfers', '#0e8f6e')}</div>
      <div class="chart-card"><h3>Fees (base units)</h3>${sparkline(pts, 'fees', '#c0392b')}</div>
      <div class="chart-card"><h3>Minted supply (HSN)</h3>${sparkline(pts, 'minted_supply', '#b8941f')}</div>
      <div class="chart-card"><h3>Mempool depth</h3>${sparkline(pts, 'mempool', '#1f5aab')}</div>
    </div>
    <div class="actions" style="margin-top:16px">
      <button class="btn primary" id="dlAnalytics">Download analytics JSON</button>
      <button class="btn" id="dlFeeHist">Download fee history</button>
    </div>
    <div class="card" style="margin-top:8px"><h3>Fee history samples <span class="r">${commas((fees.samples || []).length)}</span></h3>
      <div class="scroll"><table><thead><tr><th>Blue score</th><th>Feerates</th><th>Confirm blues</th></tr></thead>
      <tbody>${(fees.samples || []).slice(-40).reverse().map((sm) => `<tr><td class="mono">${commas(sm.blue_score)}</td><td class="mono mut">${(sm.feerates || []).slice(0, 6).join(', ')}${(sm.feerates || []).length > 6 ? '…' : ''}</td><td class="mut">${(sm.confirm_blues || []).slice(0, 6).join(', ')}</td></tr>`).join('') || '<tr><td colspan="3" class="empty">no fee samples yet</td></tr>'}</tbody></table></div>
    </div>
  </div>`;
  setFootMeta(s);
  $('dlAnalytics')?.addEventListener('click', () => downloadJson('hassan-analytics.json', a));
  $('dlFeeHist')?.addEventListener('click', () => downloadJson('hassan-fee-history.json', fees));
}

async function viewAudit(gen) {
  const [s, idx, prune] = await Promise.all([
    j('/api/v1/status'),
    j('/api/v1/indexer/status').catch(() => ({})),
    j('/api/v1/pruning/stats').catch(() => ({})),
  ]);
  statusCache = s;
  if (gen !== renderGen) return;
  $('app').innerHTML = `
  <div class="section" style="padding-top:22px">
    <div class="breadcrumb"><a href="#/">Overview</a> / Audit</div>
    <div class="page-title"><span class="pi">${icon(IC.proof)}</span><h1>Audit</h1></div>
    <p class="lead-note">Downloadable transparency packs from this node — status, supply, fee history, pruning proofs, UTXO snapshot, and tip block dump.</p>
    <div class="actions">
      <button class="btn primary" id="dlPack">Download audit pack</button>
      <button class="btn" id="dlProof">Download pruning proofs</button>
      <button class="btn" id="dlUtxo">Download UTXO snapshot</button>
      <button class="btn" id="dlDiff">Download tip state diff (0→tip)</button>
    </div>
    <div class="card"><h3>Indexer</h3>
      <table class="kvtable">
        <tr><td class="k">Path</td><td class="v">${esc(idx.path || '—')}</td></tr>
        <tr><td class="k">Tip height</td><td class="v">${idx.tip_height != null ? commas(idx.tip_height) : '—'}</td></tr>
        <tr><td class="k">Blocks / txs / addresses</td><td class="v">${commas(idx.blocks || 0)} / ${commas(idx.txs || 0)} / ${commas(idx.addresses || 0)}</td></tr>
        <tr><td class="k">Checksum</td><td class="v">${fullHash(idx.checksum)}</td></tr>
      </table>
    </div>
    <div class="card"><h3>Pruning</h3>
      <table class="kvtable">
        <tr><td class="k">Linear headers</td><td class="v">${prune.linear_proof_headers != null ? commas(prune.linear_proof_headers) : '—'}</td></tr>
        <tr><td class="k">Multilevel headers</td><td class="v">${prune.multilevel_proof_headers != null ? commas(prune.multilevel_proof_headers) : '—'}</td></tr>
        <tr><td class="k">Compression</td><td class="v">${esc(prune.compression_ratio || '—')}</td></tr>
        <tr><td class="k">Archival</td><td class="v">${prune.archival ? 'yes' : 'no'}</td></tr>
      </table>
    </div>
    <div class="card"><h3>Replayable state diff</h3>
      <div class="pad" style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
        <input id="diffFrom" class="mono" style="padding:8px 10px;border:1px solid var(--border2);border-radius:8px" placeholder="from height or blue:N" value="0">
        <input id="diffTo" class="mono" style="padding:8px 10px;border:1px solid var(--border2);border-radius:8px" placeholder="to height (default tip)">
        <button class="btn teal" id="runDiff">Compute diff</button>
      </div>
      <pre id="diffOut" class="pad mono" style="max-height:320px;overflow:auto;font-size:12px;margin:0;background:var(--surface)"></pre>
    </div>
  </div>`;
  setFootMeta(s);
  $('dlPack')?.addEventListener('click', async () => {
    try { downloadJson('hassan-audit-pack.json', await j('/api/v1/audit/pack')); } catch (_) { toast('failed'); }
  });
  $('dlProof')?.addEventListener('click', async () => {
    try { downloadJson('hassan-pruning-proof.json', await j('/api/v1/pruning/proof')); } catch (_) { toast('failed'); }
  });
  $('dlUtxo')?.addEventListener('click', async () => {
    try { downloadJson('hassan-utxo-snapshot.json', await j('/api/v1/utxo/snapshot?limit=500')); } catch (_) { toast('failed'); }
  });
  $('dlDiff')?.addEventListener('click', async () => {
    try { downloadJson('hassan-state-diff.json', await j('/api/v1/audit/diff?from=0')); } catch (_) { toast('failed'); }
  });
  $('runDiff')?.addEventListener('click', async () => {
    const from = $('diffFrom').value.trim() || '0';
    const to = $('diffTo').value.trim();
    const url = '/api/v1/audit/diff?from=' + encodeURIComponent(from) + (to ? '&to=' + encodeURIComponent(to) : '');
    try {
      const d = await j(url);
      $('diffOut').textContent = JSON.stringify(d, null, 2);
    } catch (e) { $('diffOut').textContent = String(e); }
  });
}

async function viewLabels(gen) {
  const [lab, s] = await Promise.all([j('/api/v1/labels'), j('/api/v1/status')]);
  statusCache = s;
  const rows = lab.labels || [];
  if (gen !== renderGen) return;
  $('app').innerHTML = `
  <div class="section" style="padding-top:22px">
    <div class="breadcrumb"><a href="#/">Overview</a> / Labels</div>
    <div class="page-title"><span class="pi">${icon(IC.king)}</span><h1>Labels</h1>
      <span class="badge b-lab">${commas(rows.length)}</span></div>
    <p class="lead-note">Entity tags from the indexer (miners, active accounts, protocol seeds). Search with <span class="mono">op:</span> or <span class="mono">label:</span>.</p>
    <div class="card"><div class="scroll"><table><thead><tr><th>ID</th><th>Label</th></tr></thead>
    <tbody>${rows.map((r) => `<tr class="clickable" onclick="routeSearch('${esc(r.id).replace(/'/g, '')}')"><td class="mono" title="${esc(r.id)}">${short(r.id)}</td><td>${esc(r.label)}</td></tr>`).join('') || '<tr><td colspan="2" class="empty">no labels</td></tr>'}</tbody></table></div></div>
  </div>`;
  setFootMeta(s);
}

async function viewSearch(q, gen) {
  q = decodeURIComponent(q || '');
  const [r, s] = await Promise.all([j('/api/v1/search?q=' + encodeURIComponent(q)), j('/api/v1/status')]);
  statusCache = s;
  const results = r.results || [];
  if (gen !== renderGen) return;
  $('app').innerHTML = `
  <div class="section" style="padding-top:22px">
    <div class="breadcrumb"><a href="#/">Overview</a> / Search</div>
    <div class="page-title"><h1>Search</h1><span class="badge b-tf">${commas(results.length)} hits</span></div>
    <p class="lead-note mono">${esc(q)}</p>
    <div class="card"><div class="scroll"><table><thead><tr><th>Kind</th><th>ID</th><th>Detail</th><th>Label</th></tr></thead>
    <tbody>${results.map((x, i) => `<tr class="clickable search-hit" data-i="${i}"><td><span class="badge b-lab">${esc(x.kind)}</span></td><td class="mono" title="${esc(x.id)}">${short(x.id)}</td><td class="mut">${x.height != null ? 'height ' + commas(x.height) : (x.tx_count != null ? commas(x.tx_count) + ' txs' : '—')}</td><td>${esc(x.label || '')}</td></tr>`).join('') || '<tr><td colspan="4" class="empty">no results</td></tr>'}</tbody></table></div></div>
  </div>`;
  setFootMeta(s);
  document.querySelectorAll('.search-hit').forEach((row) => {
    row.addEventListener('click', () => goResult(results[Number(row.dataset.i)]));
  });
}

/* ---------- footer / live indicator ---------- */
function setFootMeta(s) {
  const gen = (s && s.genesis_domain) || '—';
  const h = (s && s.height != null) ? commas(s.height) : '—';
  $('footMeta').textContent = `Hassan · ${gen} · ${h}`;
  $('dot').classList.remove('off'); $('live').textContent = 'live · ' + new Date().toLocaleTimeString();
}
function setFootError() {
  $('dot').classList.add('off'); $('live').textContent = 'offline';
  $('footMeta').textContent = 'Connect';
}

/* ================= ROUTER ================= */
function currentRoute() { return (location.hash.replace(/^#\/?/, '')).split('/').filter(Boolean); }
const MORE_ROUTES = new Set([
  'fees', 'supply', 'network', 'mining', 'registry', 'custody',
  'pruning', 'analytics', 'audit', 'labels', 'versionbits',
]);
function updateNavActive(top) {
  const route = top || '';
  document.querySelectorAll('#navLinks a[data-route]').forEach((a) => {
    const r = a.dataset.route;
    a.classList.toggle('active', r === route || (r === '' && !route));
  });
  const more = document.querySelector('#navLinks .nav-more');
  if (more) {
    more.classList.toggle('active-parent', MORE_ROUTES.has(route));
    if (!MORE_ROUTES.has(route)) more.open = false;
  }
}
let renderGen = 0;
let routerBusy = false;
let pollBackoffUntil = 0;
async function router(opts) {
  const soft = !!(opts && opts.soft); // background poll: keep last good page on failure
  if (soft && (routerBusy || Date.now() < pollBackoffUntil || document.hidden)) return;
  const myGen = ++renderGen;
  routerBusy = true;
  const seg = currentRoute();
  updateNavActive(seg[0] || '');
  const scrollY = window.scrollY;
  const hadContent = !!($('app') && $('app').innerHTML.trim());
  try {
    if (!seg[0]) await viewHome(myGen);
    else if (seg[0] === 'blocks') await viewBlocks(myGen);
    else if (seg[0] === 'block' && seg[1]) await viewBlockDetail(decodeURIComponent(seg[1]), myGen);
    else if (seg[0] === 'tx' && seg[1]) await viewTxDetail(decodeURIComponent(seg[1]), myGen);
    else if (seg[0] === 'address' && seg[1]) await viewAddress(seg[1], myGen);
    else if (seg[0] === 'fees') await viewFees(myGen);
    else if (seg[0] === 'mempool') await viewMempool(myGen);
    else if (seg[0] === 'mining') await viewMining(myGen);
    else if (seg[0] === 'network') await viewNetwork(myGen);
    else if (seg[0] === 'supply') await viewSupply(myGen);
    else if (seg[0] === 'custody') await viewCustody(myGen);
    else if (seg[0] === 'versionbits') await viewVersionbits(myGen);
    else if (seg[0] === 'pruning') await viewPruning(myGen);
    else if (seg[0] === 'registry') await viewRegistry(myGen);
    else if (seg[0] === 'escrow') await viewEscrow(myGen);
    else if (seg[0] === 'analytics') await viewAnalytics(myGen);
    else if (seg[0] === 'audit') await viewAudit(myGen);
    else if (seg[0] === 'labels') await viewLabels(myGen);
    else if (seg[0] === 'search' && seg[1]) await viewSearch(seg.slice(1).join('/'), myGen);
    else await viewHome(myGen); // unknown hashes (e.g. old #/ghostdag) → Overview
    pollBackoffUntil = 0;
  } catch (e) {
    if (myGen !== renderGen) return;
    const msg = String(e && e.message || e);
    const rateLimited = /HTTP 429/.test(msg);
    if (rateLimited) pollBackoffUntil = Date.now() + 15000;
    setFootError();
    // Soft polls and rate-limits must not blank a page that already rendered.
    if (soft || (rateLimited && hadContent)) {
      $('live').textContent = rateLimited ? 'rate limited · retrying' : 'node unreachable';
    } else {
      const hint = rateLimited
        ? `Node rate-limited requests from this IP. Wait a few seconds and retry — Overview will recover automatically.`
        : `Could not reach the node at ${esc(API_BASE || 'same-origin')}. Open the connect panel (top right) and point it at a running Hassan node's API port.`;
      $('app').innerHTML = `<div class="section" style="padding-top:22px"><div class="placeholder err">${hint}</div></div>`;
    }
  } finally {
    if (myGen === renderGen) routerBusy = false;
  }
  if (myGen === renderGen) window.scrollTo(0, scrollY === 0 ? 0 : scrollY);
}
window.addEventListener('hashchange', () => router());
window.addEventListener('DOMContentLoaded', () => router());
// Re-clicking Overview / brand while already on #/ does not fire hashchange —
// force a hard re-render so a prior error page can recover.
document.querySelectorAll('a[href="#/"], a[href="#"]').forEach((a) => {
  a.addEventListener('click', (e) => {
    const h = location.hash.replace(/^#\/?/, '');
    if (!h) { e.preventDefault(); router(); }
  });
});
window.routeSearch = routeSearch;
window.goResult = goResult;

/* Live pages auto-refresh; SSE tips bump live indicator. Soft = keep UI on failure. */
setInterval(() => {
  const top = currentRoute()[0] || '';
  if (['', 'blocks', 'fees', 'mempool', 'mining', 'network', 'supply', 'analytics'].includes(top)) {
    router({ soft: true });
  }
}, 8000);

let sse = null;
function connectSse() {
  if (sse) { try { sse.close(); } catch (_) {} }
  try {
    const url = apiUrl('/api/v1/events/sse');
    sse = new EventSource(url);
    sse.addEventListener('tip', (ev) => {
      try {
        const d = JSON.parse(ev.data);
        $('dot').classList.remove('off');
        $('live').textContent = 'sse · h' + (d.height != null ? d.height : '?') + ' · ' + new Date().toLocaleTimeString();
      } catch (_) {}
    });
    sse.onerror = () => { $('dot').classList.add('off'); };
  } catch (_) {}
}
connectSse();
$('netSave').addEventListener('click', () => setTimeout(connectSse, 50));
$('netReset').addEventListener('click', () => setTimeout(connectSse, 50));
