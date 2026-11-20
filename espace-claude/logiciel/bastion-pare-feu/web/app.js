'use strict';
/* Bastion — interface. Tout le DOM est construit avec textContent (aucun innerHTML sur des données). */

const S = { st: null, view: 'dash', conn: [], log: null, alerts: [], lib: [], libAll: [], locked: false, hl: null, helpSec: 'demarrage', logTab: 'paquets', connFilter: { q: '', state: '', proto: '' } };

/* ------------------------------------------------------------ utilitaires DOM */
function h(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k === 'style') e.style.cssText = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (k === 'value' || k === 'checked' || k === 'disabled' || k === 'selected') e[k] = v;
    else e.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat(Infinity)) { if (c == null || c === false) continue; e.append(c.nodeType ? c : document.createTextNode(String(c))); }
  return e;
}
const ICONS = {
  dash: '<rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/>',
  rules: '<path d="M4 6h16M4 12h16M4 18h10"/><path d="M18 15l2 2 3-4" />',
  apps: '<rect x="3" y="3" width="8" height="8" rx="2"/><rect x="13" y="3" width="8" height="8" rx="2"/><rect x="3" y="13" width="8" height="8" rx="2"/><path d="M17 13v8M13 17h8"/>',
  zones: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 010 18M12 3a14 14 0 000 18"/>',
  conn: '<path d="M5 12a7 7 0 0114 0M8.5 12a3.5 3.5 0 017 0"/><circle cx="12" cy="12" r="1"/><path d="M12 13v8"/>',
  log: '<path d="M6 3h9l4 4v14H6z"/><path d="M14 3v5h5M9 13h7M9 17h7"/>',
  prof: '<circle cx="12" cy="8" r="4"/><path d="M4 21c1-4 4-6 8-6s7 2 8 6"/>',
  opt: '<circle cx="12" cy="12" r="3"/><path d="M19 12a7 7 0 00-.1-1.2l2-1.6-2-3.4-2.4 1a7 7 0 00-2-1.2L14 3h-4l-.5 2.6a7 7 0 00-2 1.2l-2.4-1-2 3.4 2 1.6a7 7 0 000 2.4l-2 1.6 2 3.4 2.4-1a7 7 0 002 1.2L10 21h4l.5-2.6a7 7 0 002-1.2l2.4 1 2-3.4-2-1.6c.1-.4.1-.8.1-1.2z"/>',
  help: '<circle cx="12" cy="12" r="9"/><path d="M9.5 9a2.5 2.5 0 115 0c0 1.7-2.5 2-2.5 4M12 17h.01"/>',
  shield: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M9 12l2 2 4-4"/>',
  plus: '<path d="M12 5v14M5 12h14"/>', edit: '<path d="M4 20h4L19 9l-4-4L4 16z"/>', copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 012-2h9"/>',
  trash: '<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/>', up: '<path d="M12 19V5M6 11l6-6 6 6"/>', down: '<path d="M12 5v14M6 13l6 6 6-6"/>',
  play: '<path d="M7 4l13 8-13 8z"/>', code: '<path d="M8 8l-5 4 5 4M16 8l5 4-5 4M14 5l-4 14"/>', book: '<path d="M4 5a2 2 0 012-2h13v16H6a2 2 0 00-2 2z"/><path d="M4 19V5"/>',
  down2: '<path d="M12 4v12M6 12l6 6 6-6"/>', up2: '<path d="M12 20V8M6 12l6-6 6 6"/>', both: '<path d="M8 4v16M4 8l4-4 4 4M16 20V4M12 16l4 4 4-4"/>',
  lock: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/>', alert: '<path d="M12 3l10 18H2z"/><path d="M12 10v5M12 18h.01"/>',
  check: '<path d="M5 12l5 5 9-10"/>', x: '<path d="M6 6l12 12M18 6L6 18"/>', export: '<path d="M12 3v12M7 8l5-5 5 5M5 21h14"/>', import: '<path d="M12 15V3M7 10l5 5 5-5M5 21h14"/>',
  block: '<circle cx="12" cy="12" r="9"/><path d="M5.6 5.6l12.8 12.8"/>', allow: '<circle cx="12" cy="12" r="9"/><path d="M8 12l3 3 5-6"/>', pc: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
};
function setKids(el, ...kids) { el.replaceChildren(...kids.flat(Infinity).filter(k => k != null && k !== false)); }
function icon(n, size = 18) {
  const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  s.setAttribute('viewBox', '0 0 24 24'); s.setAttribute('width', size); s.setAttribute('height', size);
  s.setAttribute('fill', 'none'); s.setAttribute('stroke', 'currentColor'); s.setAttribute('stroke-width', '1.8');
  s.setAttribute('stroke-linecap', 'round'); s.setAttribute('stroke-linejoin', 'round');
  s.innerHTML = ICONS[n] || ''; // constantes internes uniquement
  return s;
}
function toast(msg, kind = '') {
  const t = h('div', { class: 'toast ' + kind }, msg); document.body.append(t); setTimeout(() => t.remove(), 3500);
}
function sw(checked, onchange) { return h('label', { class: 'sw' }, h('input', { type: 'checkbox', checked: !!checked, onchange: e => onchange(e.target.checked) }), h('span')); }

/* ------------------------------------------------------------ API */
async function api(path, body) {
  const opt = { headers: { 'X-Bastion': '1' }, credentials: 'same-origin' };
  if (body !== undefined) { opt.method = 'POST'; opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
  const r = await fetch(path, opt);
  if (r.status === 401) { S.locked = true; boot(); throw new Error('verrouillé'); }
  return r.json();
}
async function refresh(full = true) {
  S.st = await api('/api/state');
  if (full) renderAll(); else { renderSide(); renderTop(); renderBanners(); }
}

/* ------------------------------------------------------------ modales */
function openModal({ title, body, buttons = [], wide = false, onclose }) {
  const close = () => { ov.remove(); document.removeEventListener('keydown', esc); onclose && onclose(); };
  const esc = e => { if (e.key === 'Escape') close(); };
  const ov = h('div', { class: 'overlay', onmousedown: e => { if (e.target === ov) close(); } },
    h('div', { class: 'modal' + (wide ? ' wide' : '') },
      h('header', {}, h('h2', {}, title), h('button', { class: 'icon-btn', onclick: close, title: 'Fermer' }, icon('x'))),
      h('div', { class: 'body' }, body),
      buttons.length ? h('footer', {}, buttons.map(b => h('button', { class: 'btn ' + (b.cls || ''), onclick: async () => { if (await b.fn(close) !== false && b.close !== false) close(); } }, b.label))) : null));
  document.addEventListener('keydown', esc); document.body.append(ov);
  return close;
}
function confirmBox(title, text, okLabel, fn, cls = 'primary') {
  openModal({ title, body: h('p', {}, text), buttons: [{ label: 'Annuler', cls: 'ghost', fn: () => true }, { label: okLabel, cls, fn }] });
}

/* ------------------------------------------------------------ description en clair d'une règle */
function describe(r) {
  const act = r.action === 'allow' ? 'Autorise' : 'Bloque';
  const dir = { in: 'entrantes', out: 'sortantes', both: 'entrantes et sortantes' }[r.direction];
  const proto = r.protocol === 'any' ? 'de tout protocole' : r.protocol.toUpperCase();
  let s = [h('b', { class: r.action }, act), ` les connexions ${dir} ${proto}`];
  const bits = [];
  if (r.local_ports) bits.push(`port(s) de ce PC : ${r.local_ports}`);
  if (r.remote_ports) bits.push(`port(s) distant(s) : ${r.remote_ports}`);
  if (r.remote_ip) bits.push(`adresse(s) distante(s) : ${r.remote_ip}`);
  if (r.mac) bits.push(`appareil(s) d’adresse MAC : ${r.mac}`);
  if (r.local_ip) bits.push(`adresse(s) locale(s) : ${r.local_ip}`);
  if (r.icmp_type) bits.push(`type ICMP ${r.icmp_type}` + (r.icmp_code ? ` code ${r.icmp_code}` : ''));
  if (r.app) bits.push(`programme : ${r.app}`);
  if (r.user) bits.push(`utilisateur : ${r.user}`);
  if (bits.length) s.push(' — ' + bits.join(' ; '));
  else s.push(' — sans autre restriction');
  s.push('.');
  return s;
}
const DIR_ICON = { in: ['down2', 'Entrant'], out: ['up2', 'Sortant'], both: ['both', 'Entrant + sortant'] };

/* ------------------------------------------------------------ sauvegarde des règles */
async function commit(patch, quiet) {
  const r = await api('/api/save', patch);
  if (!r.ok) { const m = Object.values(r.errors || {}).join('\n') || 'Erreur'; toast(m, 'bad'); await refresh(); return false; }
  await refresh(); if (!quiet) { } return true;
}
const newRule = (o = {}) => Object.assign({ name: '', enabled: true, action: 'allow', direction: 'out', protocol: 'tcp', local_ports: '', remote_ports: '', local_ip: '', remote_ip: '', mac: '', icmp_type: '', icmp_code: '', app: '', user: '', log: false, comment: '' }, o);
async function addRule(rule, note = true) {
  const id = Math.random().toString(36).slice(2, 10);
  const rules = [...S.st.rules, Object.assign(newRule(rule), { id })];
  S.hl = id; const ok = await commit({ rules });
  if (ok && note) toast('Règle ajoutée. Cliquez sur « Appliquer » pour l’activer.', 'ok');
  return ok;
}

/* ------------------------------------------------------------ éditeur de règle */
function ruleModal(init, onsave, title) {
  const r = newRule(init); const isWin = S.st.os === 'windows';
  const F = {};
  const mk = (name, el) => { F[name] = el; return el; };
  const text = (name, ph, val) => mk(name, h('input', { type: 'text', placeholder: ph || '', value: val || '', oninput: upd }));
  const radio = (grp, items, cur) => h('div', { class: 'seg' }, items.map(([v, label, cls]) =>
    h('label', {}, h('input', { type: 'radio', name: grp, value: v, checked: v === cur, onchange: upd }), h('div', { class: cls || 'n' }, label))));
  const protoSel = mk('protocol', h('select', { onchange: upd }, [['any', 'Tous les protocoles'], ['tcp', 'TCP'], ['udp', 'UDP'], ['icmp', 'ICMP (IPv4)'], ['icmpv6', 'ICMPv6'], ['igmp', 'IGMP'], ['gre', 'GRE (47)'], ['esp', 'ESP (50)']].map(([v, l]) => h('option', { value: v, selected: v === r.protocol }, l))));
  const name = text('name', 'Ex. : Web sortant', r.name);
  const lports = text('local_ports', 'Ex. : 80,443 ou 5000-5100', r.local_ports);
  const rports = text('remote_ports', 'Ex. : 443', r.remote_ports);
  const mac = text('mac', 'Ex. : AA:BB:CC:DD:EE:FF', r.mac);
  const lip = text('local_ip', 'Ex. : 192.168.1.20', r.local_ip);
  const rip = text('remote_ip', 'Ex. : 192.168.0.0/16 ou 8.8.8.8', r.remote_ip);
  const it = text('icmp_type', 'Ex. : 8', r.icmp_type); const ic = text('icmp_code', 'Ex. : 0', r.icmp_code);
  const app = text('app', isWin ? 'Ex. : C:\\Program Files\\Mozilla Firefox\\firefox.exe' : '', r.app);
  const user = text('user', 'Ex. : www-data', r.user);
  const log = mk('log', h('input', { type: 'checkbox', checked: r.log, onchange: upd }));
  const cmt = text('comment', 'Note personnelle (facultatif)', r.comment);
  const sentence = h('div', { class: 'sentence' });
  const err = h('div', { class: 'err' });
  const portsBox = h('div', { class: 'row' }, h('div', { class: 'field' }, h('label', {}, 'Port(s) de CE PC (local)'), lports, h('span', { class: 'help' }, 'Entrant : le port que vous ouvrez. Sortant : rarement utile.')), h('div', { class: 'field' }, h('label', {}, 'Port(s) DISTANT(S)'), rports, h('span', { class: 'help' }, 'Sortant : le port du service visité (443 pour le web).')));
  const icmpBox = h('div', { class: 'row' }, h('div', { class: 'field' }, h('label', {}, 'Type ICMP'), it, h('span', { class: 'help' }, '8 = ping (demande), 0 = réponse, 3 = injoignable')), h('div', { class: 'field' }, h('label', {}, 'Code ICMP'), ic));
  const appField = isWin
    ? h('div', { class: 'field' }, h('label', {}, 'Programme (chemin complet de l’exécutable)'), app, h('span', { class: 'help' }, 'Laissez vide pour une règle valable pour tous les programmes.'))
    : h('div', { class: 'field' }, h('label', {}, 'Utilisateur (compte Linux, en sortie)'), user, h('span', { class: 'help' }, 'Sous Linux le filtrage se fait par compte et non par programme. Laissez vide pour tous.'));
  function read() {
    const g = n => document.querySelector(`input[name=${n}]:checked`)?.value;
    return Object.assign({}, r, { name: F.name.value.trim(), action: g('action'), direction: g('direction'), protocol: F.protocol.value, local_ports: F.local_ports.value, remote_ports: F.remote_ports.value, local_ip: F.local_ip.value, remote_ip: F.remote_ip.value, mac: F.mac.value, icmp_type: F.icmp_type.value, icmp_code: F.icmp_code.value, app: isWin ? F.app.value : '', user: isWin ? '' : F.user.value, log: F.log.checked, comment: F.comment.value });
  }
  function upd() {
    const v = read(); const p = v.protocol;
    portsBox.style.display = (p === 'any' || p === 'tcp' || p === 'udp') ? '' : 'none';
    icmpBox.style.display = (p === 'icmp' || p === 'icmpv6') ? '' : 'none';
    sentence.replaceChildren(...describe(v));
  }
  const body = h('div', {},
    h('div', { class: 'field' }, h('label', {}, 'Nom de la règle'), name, h('span', { class: 'help' }, 'Un nom clair rend le journal plus lisible.')),
    h('div', { class: 'field' }, h('label', {}, 'Action'), radio('action', [['allow', 'Autoriser', 'allow'], ['block', 'Bloquer', 'block']], r.action)),
    h('div', { class: 'row' }, h('div', { class: 'field' }, h('label', {}, 'Sens du trafic'), radio('direction', [['in', '↓ Entrant'], ['out', '↑ Sortant'], ['both', '⇅ Les deux']], r.direction)),
      h('div', { class: 'field' }, h('label', {}, 'Protocole'), protoSel)),
    portsBox, icmpBox,
    h('div', { class: 'row' }, h('div', { class: 'field' }, h('label', {}, 'Adresse(s) distante(s)'), rip, h('span', { class: 'help' }, 'IP, réseau (CIDR) ou plage a-b, séparés par des virgules. Vide = toutes.')),
      h('div', { class: 'field' }, h('label', {}, 'Adresse(s) locale(s)'), lip, h('span', { class: 'help' }, 'Utile si le PC a plusieurs cartes réseau.'))),
    h('div', { class: 'field' }, h('label', {}, 'Adresse MAC de l’appareil distant (facultatif)'), mac, h('span', { class: 'help' }, S.st.os === 'linux' ? 'Entrant : comparée directement à l’adresse MAC de l’émetteur. Sortant : convertie en IP via la table ARP. Réseau local uniquement. Ne se combine pas avec une IP distante.' : 'Windows ne filtre pas les MAC : Bastion les convertit en adresses IP actuelles (table ARP) à l’application. Réseau local uniquement. Ne se combine pas avec une IP distante.')),
    appField,
    h('div', { class: 'field' }, h('label', {}, 'Note'), cmt),
    h('label', { style: 'display:flex;gap:10px;align-items:center;margin:4px 0 12px' }, log, 'Journaliser les paquets concernés par cette règle (Linux)'),
    h('div', { class: 'field' }, h('label', {}, 'En clair'), sentence), err);
  const close = openModal({
    title: title || (init && init.id ? 'Modifier la règle' : 'Nouvelle règle'), body, wide: true,
    buttons: [{ label: 'Annuler', cls: 'ghost', fn: () => true },
      { label: 'Enregistrer', cls: 'primary', close: false, fn: async () => { const v = read(); if (!v.name) { err.textContent = 'Donnez un nom à la règle.'; return false; } const res = await onsave(v); if (res === false) { err.textContent = 'Règle refusée : vérifiez les champs (ports, adresses…).'; return false; } close(); } }]
  });
  upd();
}

/* ------------------------------------------------------------ chrome : barre latérale, barre du haut, bandeaux */
const NAV = [['dash', 'Tableau de bord', 'dash'], ['rules', 'Filtrage Internet', 'rules'], ['apps', 'Applications', 'apps'], ['zones', 'Zones', 'zones'], ['conn', 'Connexions', 'conn'], ['log', 'Journal', 'log'], ['prof', 'Profils & règles', 'prof'], ['opt', 'Options', 'opt'], ['help', 'Aide', 'help']];
const TITLES = { dash: ['Tableau de bord', 'État de la protection'], rules: ['Filtrage Internet', 'Règles de paquets évaluées dans l’ordre, de haut en bas'], apps: ['Applications', 'Autoriser ou bloquer des programmes'], zones: ['Zones', 'Réseaux de confiance et réseaux bloqués'], conn: ['Connexions actives', 'Ce qui communique en ce moment'], log: ['Journal', 'Paquets bloqués et événements'], prof: ['Profils & règles', 'Profils, bibliothèque, import/export'], opt: ['Options', 'Politique par défaut, mode furtif, sécurité'], help: ['Aide', 'Guide et exemples de règles'] };
function renderSide() {
  const el = document.getElementById('side'); if (!el) return;
  const st = S.st; const nAl = S.alerts.length;
  const state = st.simulate ? ['warn', 'Simulation'] : st.active ? ['ok', 'Protection active'] : ['bad', 'Non appliqué'];
  el.replaceChildren(
    h('div', { class: 'brand' }, h('div', { class: 'logo' }, icon('shield', 22)), h('div', {}, h('b', {}, 'Bastion'), h('small', {}, 'Pare-feu personnel'))),
    h('div', { class: 'nav' }, NAV.map(([k, label, ic]) => [k === 'prof' || k === 'help' ? h('hr') : null,
      h('button', { class: S.view === k ? 'on' : '', onclick: () => { S.view = k; renderAll(); } }, icon(ic), h('span', { class: 'lbl' }, label), k === 'apps' && nAl ? h('span', { class: 'badge-n' }, nAl) : null)])),
    h('div', { class: 'side-foot' }, h('span', { class: 'pill' }, h('i', { class: 'dot ' + state[0] }), state[1]), h('div', { class: 'faint small', style: 'margin-top:8px' }, (st.os === 'windows' ? 'Windows' : 'Linux') + ' · v' + st.version)));
}
function renderTop() {
  const el = document.getElementById('top'); if (!el) return; const st = S.st; const [t, sub] = TITLES[S.view];
  setKids(el, h('div', {}, h('h1', {}, t), h('div', { class: 'sub' }, sub)), h('div', { class: 'grow' }),
    st.dirty ? h('span', { class: 'tag warn' }, icon('alert', 14), 'Modifications non appliquées') : null,
    h('button', { class: 'btn', onclick: previewModal }, icon('code', 16), 'Aperçu des commandes'),
    h('button', { class: 'btn primary', onclick: applyNow }, icon('play', 16), 'Appliquer'));
}
function renderBanners() {
  const el = document.getElementById('banners'); if (!el) return; const st = S.st; const out = [];
  if (st.pending_seconds > 0) out.push(h('div', { class: 'banner warn' }, icon('alert', 22), h('div', {}, h('b', {}, 'Confirmez les nouvelles règles'), h('div', { class: 'muted' }, 'Si vous ne confirmez pas, l’état précédent sera restauré automatiquement (sécurité anti-blocage).')), h('div', { class: 'grow' }), h('span', { class: 'countdown' }, st.pending_seconds + ' s'),
    h('button', { class: 'btn primary', onclick: async () => { await api('/api/confirm', {}); toast('Règles confirmées', 'ok'); refresh(); } }, icon('check', 16), 'Confirmer'),
    h('button', { class: 'btn danger', onclick: async () => { await api('/api/revert', {}); toast('Retour à l’état précédent'); refresh(); } }, 'Annuler')));
  if (st.simulate) out.push(h('div', { class: 'banner info' }, icon('help', 22), h('div', {}, h('b', {}, 'Mode simulation'), h('div', { class: 'muted' }, st.admin ? 'Bastion a été lancé avec l’option --simulate : rien n’est appliqué au système.' : 'Bastion n’a pas les droits administrateur : rien n’est appliqué au système. Relancez-le avec le lanceur (« lancer_windows.bat » ou « lancer_linux.sh ») pour agir pour de vrai.'))));
  for (const a of S.alerts) out.push(h('div', { class: 'banner bad' }, icon('alert', 22), h('div', {}, h('b', {}, 'Nouvelle application en communication : ' + a.name), h('div', { class: 'muted mono small' }, `${a.app} → ${a.raddr}:${a.rport}`)), h('div', { class: 'grow' }),
    h('button', { class: 'btn sm', onclick: () => resolveAlert(a, 'allow') }, icon('allow', 14), 'Autoriser'), h('button', { class: 'btn sm danger', onclick: () => resolveAlert(a, 'block') }, icon('block', 14), 'Bloquer'), h('button', { class: 'btn sm ghost', onclick: () => resolveAlert(a, 'ignore') }, 'Ignorer')));
  el.replaceChildren(...out);
}
async function resolveAlert(a, decision) { await api('/api/alerts/resolve', { app: a.app, decision }); S.alerts = S.alerts.filter(x => x.app !== a.app); if (decision !== 'ignore') toast('Règle créée. Pensez à « Appliquer ».', 'ok'); await refresh(); }

async function applyNow() {
  const r = await api('/api/apply', {});
  if (!r.ok) { openModal({ title: 'Échec de l’application', body: h('div', {}, h('p', {}, 'Le système a refusé la configuration ; l’état précédent a été rétabli.'), h('pre', { class: 'code' }, r.errors.join('\n'))), buttons: [{ label: 'Fermer', fn: () => true }] }); }
  else toast(r.warnings.length ? `Appliqué (${r.warnings.length} avertissement(s))` : 'Règles appliquées', 'ok');
  await refresh();
}
async function previewModal() {
  const r = await api('/api/preview');
  openModal({ title: 'Commandes générées', wide: true, body: h('div', {}, h('p', { class: 'muted' }, 'Voici exactement ce que Bastion enverra au pare-feu du système lors d’un « Appliquer ».'), r.warnings.map(w => h('div', { class: 'banner warn' }, icon('alert', 18), w)), h('pre', { class: 'code' }, r.text)), buttons: [{ label: 'Fermer', fn: () => true }] });
}

/* ------------------------------------------------------------ vue : tableau de bord */
function viewDash() {
  const st = S.st; const en = st.rules.filter(r => r.enabled); const al = en.filter(r => r.action === 'allow').length; const bl = en.length - al;
  const est = S.conn.filter(c => c.state === 'ESTABLISHED').length;
  const blocked = S.log ? S.log.rows.filter(x => x.action === 'bloqué').length : '—';
  const pol = (p, d) => h('span', { class: 'tag ' + ((d === 'in' ? p === 'block' : p === 'allow') ? (d === 'in' ? 'allow' : 'allow') : 'block') }, (p === 'block' ? 'Bloqué par défaut' : 'Autorisé par défaut'));
  const apps = {}; S.conn.filter(c => c.state === 'ESTABLISHED' && c.name).forEach(c => apps[c.name] = (apps[c.name] || 0) + 1);
  const top = Object.entries(apps).sort((a, b) => b[1] - a[1]).slice(0, 6); const max = top.length ? top[0][1] : 1;
  const stat = (ic, cls, v, l) => h('div', { class: 'card stat' }, h('div', { class: 'ico ' + cls }, icon(ic)), h('div', { class: 'v' }, v), h('div', { class: 'l' }, l));
  return h('div', { class: 'grid' },
    h('div', { class: 'grid g4' }, stat('shield', st.active ? 'g' : 'r', st.active ? 'Actif' : 'Inactif', st.applied_at ? 'Appliqué à ' + st.applied_at : 'Rien d’appliqué dans cette session'),
      stat('allow', 'g', al, 'Règles d’autorisation actives'), stat('block', 'r', bl, 'Règles de blocage actives'), stat('conn', 'b', est, 'Connexions établies'), stat('log', 'p', blocked, 'Paquets bloqués (journal)')),
    h('div', { class: 'grid g2' },
      h('div', { class: 'card' }, h('h3', {}, 'Circulation du trafic'), h('p', { class: 'hint' }, 'Le pare-feu examine chaque paquet entre Internet et votre machine.'),
        h('div', { class: 'diagram nowrap-d' }, h('div', { class: 'node' }, icon('zones', 22), h('small', {}, 'Internet')), h('div', { class: 'arrow' }, '↓ entrant', h('br'), pol(st.settings.policy_in, 'in'), h('br'), '↑ sortant', h('br'), pol(st.settings.policy_out, 'out')),
          h('div', { class: 'node', style: 'border-color:var(--accent)' }, icon('shield', 22), h('small', {}, 'Bastion')), h('div', { class: 'arrow' }, '→'), h('div', { class: 'node' }, icon('pc', 22), h('small', {}, 'Ce PC'))),
        h('div', { class: 'row small muted' }, h('span', {}, 'Mode furtif : ', h('b', {}, st.settings.stealth ? 'oui' : 'non')), h('span', {}, 'Zones : ', h('b', {}, st.zones.length)), h('span', {}, 'Profil : ', h('b', {}, st.active_profile || 'aucun')))),
      h('div', { class: 'card' }, h('h3', {}, 'Applications les plus actives'), h('p', { class: 'hint' }, 'Connexions établies par programme.'),
        top.length ? h('div', { class: 'flow' }, top.map(([n, c]) => h('div', {}, h('div', { style: 'display:flex;justify-content:space-between' }, h('span', {}, n), h('span', { class: 'muted' }, c)), h('div', { class: 'bar' }, h('i', { style: `width:${Math.max(6, c / max * 100)}%` }))))) : h('div', { class: 'muted' }, 'Aucune connexion établie détectée.'))),
    st.warnings.length ? h('div', { class: 'card' }, h('h3', {}, 'Points d’attention'), st.warnings.map(w => h('div', { class: 'banner warn', style: 'margin:8px 0 0' }, icon('alert', 18), w))) : null,
    h('div', { class: 'card' }, h('h3', {}, 'Actions rapides'), h('div', { class: 'row', style: 'margin-top:8px' },
      h('button', { class: 'btn', onclick: () => ruleModal(null, async v => addRule(v, true).then(ok => ok), 'Nouvelle règle') }, icon('plus', 16), 'Nouvelle règle'),
      h('button', { class: 'btn', onclick: libraryModal }, icon('book', 16), 'Bibliothèque de règles'),
      h('button', { class: 'btn', onclick: () => { S.view = 'help'; renderAll(); } }, icon('help', 16), 'Ouvrir l’aide et les exemples'),
      h('button', { class: 'btn danger', onclick: () => confirmBox('Retirer toutes les règles Bastion ?', 'Le pare-feu Bastion sera retiré du système (vos règles restent enregistrées dans l’application).', 'Retirer', async () => { await api('/api/disable', {}); toast('Règles Bastion retirées'); refresh(); }, 'danger') }, 'Désactiver Bastion'))));
}

/* ------------------------------------------------------------ vue : règles */
function ruleRow(r, i, total, list) {
  const st = S.st.status[r.id] || ''; const warn = st.startsWith('ignorée');
  const [di, dl] = DIR_ICON[r.direction];
  const ports = [r.local_ports ? h('div', {}, h('span', { class: 'faint small' }, 'local '), r.local_ports) : null, r.remote_ports ? h('div', {}, h('span', { class: 'faint small' }, 'distant '), r.remote_ports) : null, r.icmp_type ? h('div', {}, 'type ' + r.icmp_type + (r.icmp_code ? '/' + r.icmp_code : '')) : null];
  const addr = [r.mac ? h('div', {}, h('span', { class: 'faint small' }, 'MAC '), r.mac) : null, r.remote_ip ? h('div', {}, h('span', { class: 'faint small' }, 'dist. '), r.remote_ip) : null, r.local_ip ? h('div', {}, h('span', { class: 'faint small' }, 'loc. '), r.local_ip) : null];
  const mv = d => async () => { const rules = [...S.st.rules]; const j = i + d; [rules[i], rules[j]] = [rules[j], rules[i]]; S.hl = r.id; await commit({ rules }); };
  return h('tr', { class: (r.enabled ? '' : 'off ') + (S.hl === r.id ? 'hl' : '') },
    h('td', { class: 'faint nowrap' }, i + 1), h('td', {}, sw(r.enabled, async v => { const rules = S.st.rules.map(x => x.id === r.id ? { ...x, enabled: v } : x); await commit({ rules }); })),
    h('td', { style: 'min-width:170px' }, h('b', {}, r.name), r.comment ? h('div', { class: 'faint small' }, r.comment) : null, warn ? h('div', {}, h('span', { class: 'tag warn', title: st }, icon('alert', 12), 'non appliquée')) : null),
    h('td', {}, h('span', { class: 'tag ' + r.action }, icon(r.action === 'allow' ? 'allow' : 'block', 14), r.action === 'allow' ? 'Autoriser' : 'Bloquer')),
    h('td', { class: 'nowrap' }, h('span', { style: 'display:inline-flex;gap:6px;align-items:center', title: dl }, icon(di, 16), dl)),
    h('td', {}, h('span', { class: 'tag neutral' }, r.protocol === 'any' ? 'TOUS' : r.protocol.toUpperCase())), h('td', { class: 'mono small' }, ports), h('td', { class: 'mono small' }, addr),
    h('td', { class: 'small', style: 'max-width:220px;word-break:break-all' }, r.app || r.user || h('span', { class: 'faint' }, '—')),
    h('td', { class: 'nowrap' }, h('button', { class: 'icon-btn', title: 'Monter', disabled: i === 0, onclick: mv(-1) }, icon('up', 16)), h('button', { class: 'icon-btn', title: 'Descendre', disabled: i === total - 1, onclick: mv(1) }, icon('down', 16)),
      h('button', { class: 'icon-btn', title: 'Modifier', onclick: () => ruleModal(r, async v => { const rules = S.st.rules.map(x => x.id === r.id ? v : x); S.hl = r.id; return commit({ rules }); }) }, icon('edit', 16)),
      h('button', { class: 'icon-btn', title: 'Dupliquer', onclick: async () => { const rules = [...S.st.rules]; const c = { ...r, id: Math.random().toString(36).slice(2, 10), name: r.name + ' (copie)' }; rules.splice(i + 1, 0, c); S.hl = c.id; await commit({ rules }); } }, icon('copy', 16)),
      h('button', { class: 'icon-btn bad', title: 'Supprimer', onclick: () => confirmBox('Supprimer la règle ?', `« ${r.name} » sera supprimée de la liste.`, 'Supprimer', async () => { await commit({ rules: S.st.rules.filter(x => x.id !== r.id) }); }, 'danger') }, icon('trash', 16))));
}
function viewRules(filterApps) {
  const all = S.st.rules; const list = all.map((r, i) => [r, i]).filter(([r]) => filterApps ? (r.app || r.user) : true);
  const isWin = S.st.os === 'windows';
  const head = h('div', { style: 'display:flex;gap:10px;margin-bottom:14px;flex-wrap:wrap' },
    filterApps ? h('button', { class: 'btn primary', onclick: () => appModal() }, icon('plus', 16), isWin ? 'Ajouter une application' : 'Ajouter un compte utilisateur')
      : h('button', { class: 'btn primary', onclick: () => ruleModal(null, v => addRule(v, true).then(ok => ok), 'Nouvelle règle') }, icon('plus', 16), 'Nouvelle règle'),
    h('button', { class: 'btn', onclick: libraryModal }, icon('book', 16), 'Bibliothèque'), h('div', { class: 'grow' }),
    h('span', { class: 'muted small', style: 'align-self:center' }, filterApps ? 'Règles liées à un ' + (isWin ? 'programme' : 'compte') : 'Politique par défaut : entrée ' + (S.st.settings.policy_in === 'block' ? 'bloquée' : 'autorisée') + ' · sortie ' + (S.st.settings.policy_out === 'block' ? 'bloquée' : 'autorisée')));
  const note = filterApps && !isWin ? h('div', { class: 'banner info' }, icon('alert', 20), h('div', {}, h('b', {}, 'Linux : filtrage par compte utilisateur'), h('div', { class: 'muted' }, 'Le pare-feu Linux (nftables) ne reconnaît pas les programmes mais les comptes. Pour isoler une application, lancez-la sous un compte dédié puis bloquez ce compte ici.'))) : null;
  const tbl = list.length ? h('div', { class: 'tbl-wrap' }, h('table', {}, h('thead', {}, h('tr', {}, ['#', 'Actif', 'Nom', 'Action', 'Sens', 'Proto', 'Ports', 'Adresses', filterApps ? (isWin ? 'Programme' : 'Utilisateur') : 'Programme / compte', ''].map(t => h('th', {}, t)))),
    h('tbody', {}, list.map(([r, i]) => ruleRow(r, i, all.length)))))
    : h('div', { class: 'card empty' }, h('div', { style: 'font-size:16px;margin-bottom:6px' }, 'Aucune règle ici pour l’instant'), 'Créez-en une ou piochez dans la bibliothèque.');
  S.hl = null;
  return h('div', {}, note, head, tbl, !filterApps ? h('p', { class: 'muted small' }, S.st.os === 'linux' ? 'Les règles sont lues de haut en bas : la première qui correspond à un paquet décide de son sort.' : 'Sous Windows, un blocage l’emporte toujours sur une autorisation, quel que soit l’ordre.') : null);
}
function appModal() {
  const isWin = S.st.os === 'windows';
  ruleModal(isWin ? { name: '', action: 'allow', direction: 'both', protocol: 'any' } : { name: '', action: 'block', direction: 'out', protocol: 'any' }, v => { if (!v.app && !v.user) return false; return addRule(v, true).then(ok => ok); }, isWin ? 'Nouvelle règle d’application' : 'Nouvelle règle par compte');
}

/* ------------------------------------------------------------ vue : zones */
function zoneModal(z) {
  const editing = !!(z && z.id);
  const nm = h('input', { type: 'text', value: z ? z.name : '', placeholder: 'Ex. : Réseau maison' });
  const ad = h('input', { type: 'text', value: z ? z.addresses : '', placeholder: 'Ex. : 192.168.1.0/24, 10.0.0.5' });
  const tr = h('select', {}, [['trusted', 'Zone de confiance — tout autoriser'], ['blocked', 'Zone bloquée — tout refuser']].map(([v, l]) => h('option', { value: v, selected: z && z.trust === v }, l)));
  const err = h('div', { class: 'err' });
  openModal({
    title: editing ? 'Modifier la zone' : 'Nouvelle zone', body: h('div', {}, h('div', { class: 'field' }, h('label', {}, 'Nom'), nm), h('div', { class: 'field' }, h('label', {}, 'Adresses / réseaux'), ad, h('span', { class: 'help' }, 'IP, réseau CIDR (192.168.1.0/24) ou plage (10.0.0.1-10.0.0.50), séparés par des virgules.')), h('div', { class: 'field' }, h('label', {}, 'Type'), tr), err),
    buttons: [{ label: 'Annuler', cls: 'ghost', fn: () => true }, {
      label: 'Enregistrer', cls: 'primary', close: false, fn: async (close) => {
        const nz = { id: editing ? z.id : Math.random().toString(36).slice(2, 10), name: nm.value, addresses: ad.value, trust: tr.value, enabled: editing ? z.enabled : true };
        const zones = editing ? S.st.zones.map(x => x.id === z.id ? nz : x) : [...S.st.zones, nz];
        const r = await api('/api/save', { zones }); if (!r.ok) { err.textContent = Object.values(r.errors).join('\n'); return false; } close(); await refresh();
      }
    }]
  });
}
function viewZones() {
  const zs = S.st.zones;
  return h('div', {}, h('div', { style: 'display:flex;gap:10px;margin-bottom:14px' }, h('button', { class: 'btn primary', onclick: () => zoneModal() }, icon('plus', 16), 'Nouvelle zone'), h('button', { class: 'btn', onclick: () => zoneModal({ name: 'Réseau local', addresses: '192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12', trust: 'trusted', enabled: true, id: null }) }, 'Ajouter mon réseau local (modèle)')),
    zs.length ? h('div', { class: 'tbl-wrap' }, h('table', {}, h('thead', {}, h('tr', {}, ['Actif', 'Nom', 'Type', 'Adresses', ''].map(t => h('th', {}, t)))), h('tbody', {}, zs.map(z => h('tr', { class: z.enabled ? '' : 'off' },
      h('td', {}, sw(z.enabled, async v => { await commit({ zones: zs.map(x => x.id === z.id ? { ...x, enabled: v } : x) }); })), h('td', {}, h('b', {}, z.name)),
      h('td', {}, h('span', { class: 'tag ' + (z.trust === 'trusted' ? 'allow' : 'block') }, z.trust === 'trusted' ? 'Confiance' : 'Bloquée')), h('td', { class: 'mono small' }, z.addresses),
      h('td', { class: 'nowrap' }, h('button', { class: 'icon-btn', onclick: () => zoneModal(z) }, icon('edit', 16)), h('button', { class: 'icon-btn bad', onclick: () => commit({ zones: zs.filter(x => x.id !== z.id) }) }, icon('trash', 16))))))))
      : h('div', { class: 'card empty' }, 'Aucune zone. Une zone de confiance laisse passer tout le trafic d’un réseau (ex. votre réseau maison) avant l’examen des règles.'),
    h('p', { class: 'muted small' }, 'Les zones sont examinées avant les règles : les zones bloquées d’abord, puis les zones de confiance.'));
}

/* ------------------------------------------------------------ vue : connexions */
function connRows() {
  const f = S.connFilter; const q = f.q.toLowerCase();
  return S.conn.filter(c => (!f.state || c.state === f.state || (f.state === 'LISTEN' && c.state === 'LISTEN')) && (!f.proto || c.proto.startsWith(f.proto)) &&
    (!q || [c.name, c.exe, c.laddr, c.raddr, String(c.lport), String(c.rport), String(c.pid)].join(' ').toLowerCase().includes(q)))
    .sort((a, b) => (a.state === 'ESTABLISHED' ? 0 : 1) - (b.state === 'ESTABLISHED' ? 0 : 1) || (a.name || '').localeCompare(b.name || '')).slice(0, 400);
}
function connRule(c) {
  const tcp = c.proto.startsWith('tcp'); const listen = c.state === 'LISTEN' || !c.raddr;
  const base = listen ? { name: `Bloquer le port ${c.lport}`, action: 'block', direction: 'in', protocol: tcp ? 'tcp' : 'udp', local_ports: String(c.lport) }
    : { name: `Bloquer ${c.name || c.raddr}`, action: 'block', direction: 'out', protocol: tcp ? 'tcp' : 'udp', remote_ip: c.raddr, remote_ports: String(c.rport) };
  if (S.st.os === 'windows' && c.exe && !listen) base.app = c.exe;
  ruleModal(base, v => addRule(v, true).then(ok => ok), 'Créer une règle depuis cette connexion');
}
function fillConn() {
  const tb = document.getElementById('conn-body'); if (!tb) return; const rows = connRows();
  tb.replaceChildren(...(rows.length ? rows.map(c => h('tr', {}, h('td', {}, h('span', { class: 'tag neutral' }, c.proto.toUpperCase())), h('td', { class: 'mono small' }, `${c.laddr}:${c.lport}`), h('td', { class: 'mono small' }, c.raddr ? `${c.raddr}:${c.rport}` : '—'),
    h('td', {}, c.state ? h('span', { class: 'tag ' + (c.state === 'ESTABLISHED' ? 'allow' : 'neutral') }, c.state) : ''), h('td', { class: 'muted' }, c.pid || ''), h('td', {}, c.name || h('span', { class: 'faint' }, '—'), c.exe ? h('div', { class: 'faint small', style: 'word-break:break-all' }, c.exe) : null),
    h('td', {}, h('button', { class: 'btn sm', onclick: () => connRule(c) }, icon('block', 13), 'Règle…')))) : [h('tr', {}, h('td', { colspan: 7, class: 'empty' }, 'Aucune connexion ne correspond.'))]));
  const n = document.getElementById('conn-n'); if (n) n.textContent = rows.length + ' ligne(s)';
}
function viewConn() {
  const f = S.connFilter;
  const sel = (k, opts) => h('select', { style: 'width:auto', onchange: e => { f[k] = e.target.value; fillConn(); } }, opts.map(([v, l]) => h('option', { value: v, selected: f[k] === v }, l)));
  const wrap = h('div', {}, h('div', { style: 'display:flex;gap:10px;margin-bottom:14px;flex-wrap:wrap;align-items:center' },
    h('input', { type: 'text', placeholder: 'Filtrer (programme, IP, port…)', value: f.q, style: 'max-width:300px', oninput: e => { f.q = e.target.value; fillConn(); } }), sel('state', [['', 'Tous les états'], ['ESTABLISHED', 'Établies'], ['LISTEN', 'En écoute']]), sel('proto', [['', 'TCP + UDP'], ['tcp', 'TCP'], ['udp', 'UDP']]), h('div', { class: 'grow' }), h('span', { class: 'muted small', id: 'conn-n' }), h('span', { class: 'muted small' }, 'Actualisation automatique')),
    h('div', { class: 'tbl-wrap' }, h('table', {}, h('thead', {}, h('tr', {}, ['Proto', 'Local', 'Distant', 'État', 'PID', 'Programme', ''].map(t => h('th', {}, t)))), h('tbody', { id: 'conn-body' }))));
  setTimeout(fillConn, 0); return wrap;
}

/* ------------------------------------------------------------ vue : journal */
function viewLog() {
  const wrap = h('div', {}, h('div', { style: 'display:flex;gap:10px;margin-bottom:14px;align-items:center' },
    h('button', { class: 'btn ' + (S.logTab === 'paquets' ? 'primary' : ''), onclick: () => { S.logTab = 'paquets'; renderView(); } }, 'Paquets'), h('button', { class: 'btn ' + (S.logTab === 'events' ? 'primary' : ''), onclick: () => { S.logTab = 'events'; renderView(); } }, 'Événements Bastion'),
    h('div', { class: 'grow' }), h('button', { class: 'btn', onclick: async () => { S.log = await api('/api/log'); renderView(); } }, 'Actualiser')), h('div', { id: 'log-body' }));
  setTimeout(async () => { if (!S.log) S.log = await api('/api/log'); fillLog(); }, 0); return wrap;
}
function fillLog() {
  const el = document.getElementById('log-body'); if (!el || !S.log) return; const L = S.log;
  if (S.logTab === 'events') { el.replaceChildren(L.events.length ? h('div', { class: 'tbl-wrap' }, h('table', {}, h('thead', {}, h('tr', {}, ['Heure', 'Type', 'Message'].map(t => h('th', {}, t)))), h('tbody', {}, L.events.map(e => h('tr', {}, h('td', { class: 'nowrap mono small' }, e.t), h('td', {}, h('span', { class: 'tag neutral' }, e.kind)), h('td', {}, e.msg)))))) : h('div', { class: 'card empty' }, 'Aucun événement.')); return; }
  setKids(el, L.demo ? h('div', { class: 'banner info' }, icon('alert', 18), 'Données de démonstration (mode simulation) : elles montrent à quoi ressemblera le journal.') : null, L.note ? h('div', { class: 'banner warn' }, icon('alert', 18), L.note) : null,
    L.rows.length ? h('div', { class: 'tbl-wrap' }, h('table', {}, h('thead', {}, h('tr', {}, ['Heure', 'Action', 'Proto', 'Source', 'Destination', 'Règle / info'].map(t => h('th', {}, t)))), h('tbody', {}, L.rows.map(x => h('tr', {}, h('td', { class: 'nowrap mono small' }, x.t), h('td', {}, h('span', { class: 'tag ' + (x.action === 'bloqué' ? 'block' : 'allow') }, x.action)), h('td', {}, x.proto), h('td', { class: 'mono small' }, x.src + (x.sport ? ':' + x.sport : '')), h('td', { class: 'mono small' }, x.dst + (x.dport ? ':' + x.dport : '')), h('td', { class: 'small' }, x.info)))))) : h('div', { class: 'card empty' }, 'Aucun paquet journalisé pour l’instant.'));
}

/* ------------------------------------------------------------ bibliothèque */
function libraryModal() {
  const groups = {}; S.lib.forEach(e => (groups[e.group] = groups[e.group] || []).push(e));
  const body = h('div', {}, h('p', { class: 'muted' }, 'Des règles prêtes à l’emploi (comme la bibliothèque de Look \u2019n\u2019 Stop). Cliquez sur « Ajouter » : la règle rejoint votre liste, il reste à « Appliquer ».'), Object.entries(groups).map(([g, items]) => [h('div', { class: 'lib-group' }, g), items.map(e => exampleCard(e))]));
  openModal({ title: 'Bibliothèque de règles', body, wide: true, buttons: [{ label: 'Fermer', fn: () => true }] });
}
function exampleCard(e, closeFn) {
  const r = e.rule; const ic = r.action === 'allow' ? ['allow', 'g'] : ['block', 'r'];
  return h('div', { class: 'ex' }, h('div', { class: 'ico ' + ic[1] }, icon(ic[0])), h('div', { class: 'tx' }, h('b', {}, e.title), h('p', {}, e.desc), h('div', { class: 'sentence small' }, describe(r))),
    h('button', { class: 'btn sm', onclick: async () => { await addRule(r, true); } }, icon('plus', 13), 'Ajouter'));
}

/* ------------------------------------------------------------ vue : profils */
function viewProf() {
  const st = S.st; const nm = h('input', { type: 'text', placeholder: 'Nom du profil (ex. Maison, Lycée, Strict)', style: 'max-width:320px' });
  const file = h('input', { type: 'file', accept: '.json,application/json', style: 'display:none', onchange: ev => { const f = ev.target.files[0]; if (!f) return; const rd = new FileReader(); rd.onload = () => importModal(rd.result); rd.readAsText(f); ev.target.value = ''; } });
  return h('div', { class: 'grid g2' },
    h('div', { class: 'card' }, h('h3', {}, 'Profils'), h('p', { class: 'hint' }, 'Un profil mémorise vos règles, zones et réglages. Passez de « Maison » à « Strict » en un clic, puis appliquez.'),
      h('div', { style: 'display:flex;gap:8px;margin-bottom:12px' }, nm, h('button', { class: 'btn primary', onclick: async () => { if (!nm.value.trim()) return toast('Donnez un nom', 'bad'); await api('/api/profile', { op: 'save', name: nm.value }); toast('Profil enregistré', 'ok'); refresh(); } }, 'Enregistrer l’état actuel')),
      st.profiles.length ? st.profiles.map(p => h('div', { class: 'opt' }, h('div', { class: 't' }, h('b', {}, p), p === st.active_profile ? h('span', { class: 'tag allow' }, 'Actif') : null), h('button', { class: 'btn sm', onclick: () => confirmBox('Charger le profil ?', `Vos règles actuelles seront remplacées par celles de « ${p} » (pensez à les enregistrer avant).`, 'Charger', async () => { await api('/api/profile', { op: 'load', name: p }); toast('Profil chargé — cliquez sur Appliquer', 'ok'); refresh(); }) }, 'Charger'), h('button', { class: 'icon-btn bad', onclick: async () => { await api('/api/profile', { op: 'delete', name: p }); refresh(); } }, icon('trash', 16)))) : h('div', { class: 'muted' }, 'Aucun profil enregistré.')),
    h('div', { class: 'card' }, h('h3', {}, 'Bibliothèque, import et export'), h('p', { class: 'hint' }, 'Partagez vos règles avec un collègue ou sauvegardez-les dans un fichier.'),
      h('div', { style: 'display:flex;flex-direction:column;gap:10px;align-items:flex-start' },
        h('button', { class: 'btn', onclick: libraryModal }, icon('book', 16), 'Ouvrir la bibliothèque de règles'),
        h('button', { class: 'btn', onclick: async () => { const d = await api('/api/export'); const a = h('a', { href: URL.createObjectURL(new Blob([JSON.stringify(d, null, 2)], { type: 'application/json' })), download: 'regles-bastion.json' }); document.body.append(a); a.click(); a.remove(); } }, icon('export', 16), 'Exporter mes règles (.json)'),
        h('button', { class: 'btn', onclick: () => file.click() }, icon('import', 16), 'Importer des règles (.json)'), file)));
}
function importModal(text) {
  let data; try { data = JSON.parse(text); } catch { return toast('Fichier invalide', 'bad'); }
  const go = mode => async () => { const r = await api('/api/import', { rules: data.rules || [], zones: data.zones || [], mode }); if (!r.ok) toast(r.error, 'bad'); else toast(r.count + ' règle(s) importée(s)', 'ok'); refresh(); };
  openModal({ title: 'Importer des règles', body: h('p', {}, `${(data.rules || []).length} règle(s) et ${(data.zones || []).length} zone(s) trouvée(s). Les ajouter à votre liste, ou tout remplacer ?`), buttons: [{ label: 'Annuler', cls: 'ghost', fn: () => true }, { label: 'Remplacer', cls: 'danger', fn: go('replace') }, { label: 'Ajouter', cls: 'primary', fn: go('append') }] });
}

/* ------------------------------------------------------------ vue : options */
async function setSetting(k, v) { await commit({ settings: { [k]: v } }); }
function viewOpt() {
  const s = S.st.settings; const sel = (k, opts) => h('select', { onchange: e => setSetting(k, e.target.value) }, opts.map(([v, l]) => h('option', { value: v, selected: s[k] === v }, l)));
  const opt = (t, d, ctl) => h('div', { class: 'opt' }, h('div', { class: 't' }, h('b', {}, t), h('span', {}, d)), ctl);
  return h('div', { class: 'grid g2' },
    h('div', { class: 'card' }, h('h3', {}, 'Filtrage'), h('p', { class: 'hint' }, 'Ce qui se passe quand aucune règle ne correspond.'),
      opt('Trafic entrant par défaut', 'Bloqué : seules vos règles ouvrent des ports (recommandé).', sel('policy_in', [['block', 'Bloquer'], ['allow', 'Autoriser']])),
      opt('Trafic sortant par défaut', 'Autorisé : confortable. Bloqué : mode strict, il faudra autoriser web et DNS.', sel('policy_out', [['allow', 'Autoriser'], ['block', 'Bloquer']])),
      opt('Mode furtif', 'Les paquets bloqués sont ignorés sans réponse et le ping entrant est refusé : votre PC semble absent du réseau.', sw(s.stealth, v => setSetting('stealth', v))),
      opt('Toujours autoriser la boucle locale', 'Indispensable : les programmes de votre PC dialoguent entre eux (127.0.0.1).', sw(s.loopback, v => setSetting('loopback', v))),
      opt('Règles réseau de base (Linux)', 'DHCP et découverte IPv6 : sans elles, la connexion peut ne pas s’établir quand l’entrée est bloquée.', sw(s.base_rules, v => setSetting('base_rules', v)))),
    h('div', { class: 'card' }, h('h3', {}, 'Sécurité et suivi'),
      opt('Retour automatique', 'Après « Appliquer », les anciennes règles reviennent seules si vous ne confirmez pas (0 = désactivé).', h('input', { type: 'number', min: 0, max: 300, value: s.rollback_seconds, onchange: e => setSetting('rollback_seconds', +e.target.value) })),
      opt('Journaliser les paquets bloqués', 'Alimente l’onglet Journal.', sw(s.log_blocked, v => setSetting('log_blocked', v))),
      S.st.alerts_supported ? opt('Alertes nouvelles applications', 'Une bannière apparaît quand un programme sans règle ouvre une connexion (Windows).', sw(s.alerts, v => setSetting('alerts', v))) : null,
      opt('Mot de passe de l’interface', s.has_password ? 'Un mot de passe protège l’accès à Bastion.' : 'Aucun mot de passe : toute personne ouvrant le lien local peut modifier les règles.', h('button', { class: 'btn', onclick: passwordModal }, icon('lock', 16), s.has_password ? 'Modifier / retirer' : 'Définir')),
      s.has_password ? opt('Verrouiller maintenant', 'Redemande le mot de passe.', h('button', { class: 'btn', onclick: async () => { await api('/api/lock', {}); S.locked = true; boot(); } }, 'Verrouiller')) : null));
}
function passwordModal() {
  const old = h('input', { type: 'password', placeholder: 'Mot de passe actuel' }), nw = h('input', { type: 'password', placeholder: 'Nouveau mot de passe (vide = supprimer)' }); const err = h('div', { class: 'err' });
  openModal({ title: 'Mot de passe', body: h('div', {}, S.st.settings.has_password ? h('div', { class: 'field' }, old) : null, h('div', { class: 'field' }, nw, h('span', { class: 'help' }, '4 caractères minimum. Il n’est jamais stocké en clair.')), err), buttons: [{ label: 'Annuler', cls: 'ghost', fn: () => true }, { label: 'Valider', cls: 'primary', close: false, fn: async (close) => { const r = await api('/api/password', { old: old.value, new: nw.value }); if (!r.ok) { err.textContent = r.error; return false; } close(); toast('Mot de passe mis à jour', 'ok'); refresh(); } }] });
}

/* ------------------------------------------------------------ vue : aide */
const LIBT = t => S.libAll.find(e => e.title === t);
function ex(title) { const e = LIBT(title); if (!e) return null; if (e.os && e.os !== S.st.os) return null; return exampleCard(e); }
function callout(kind, ...c) { return h('div', { class: 'banner ' + kind }, icon(kind === 'ok' ? 'check' : kind === 'info' ? 'help' : 'alert', 20), h('div', {}, c)); }
function helpSections() {
  const isWin = S.st.os === 'windows';
  return [
    ['demarrage', 'Démarrage rapide', () => [h('p', {}, 'Bastion filtre ce qui entre et sort de votre ordinateur grâce au pare-feu du système (', isWin ? 'Pare-feu Windows Defender' : 'nftables', '). Vous décrivez des règles, Bastion les traduit et les applique.'),
      h('ol', {}, h('li', {}, 'Ouvrez ', h('b', {}, 'Filtrage Internet'), ' : une liste de règles est déjà présente. Ajoutez-en depuis la ', h('b', {}, 'Bibliothèque'), ' ou avec ', h('b', {}, 'Nouvelle règle'), '.'), h('li', {}, 'Cliquez sur ', h('b', {}, 'Appliquer'), ' (en haut à droite). Rien n’est actif tant que vous n’avez pas appliqué.'), h('li', {}, 'Vérifiez que votre connexion fonctionne, puis ', h('b', {}, 'Confirmer'), '. Sans confirmation, l’ancien état revient tout seul après quelques secondes.'), h('li', {}, 'Surveillez ', h('b', {}, 'Connexions'), ' et ', h('b', {}, 'Journal'), ' pour voir ce qui est autorisé ou bloqué.')),
      callout('info', h('b', {}, 'Astuce : '), 'le bouton « Aperçu des commandes » montre exactement ce qui sera envoyé au système. Pratique pour apprendre.')]],
    ['regle', 'Comprendre une règle', () => [h('p', {}, 'Une règle est une phrase : « Quoi ? Dans quel sens ? Pour qui ? Que faire ? ». Le texte « En clair » de l’éditeur la relit pour vous.'),
      h('div', { class: 'diagram' }, h('div', { class: 'node' }, 'Serveur distant', h('small', {}, 'port distant ex. 443')), h('div', { class: 'arrow' }, '⇄ sortant : vous visitez', h('br'), '⇄ entrant : on vous visite'), h('div', { class: 'node', style: 'border-color:var(--accent)' }, 'Votre PC', h('small', {}, 'port local ex. 80'))),
      h('ul', {}, h('li', {}, h('b', {}, 'Sens'), ' — entrant (quelqu’un se connecte à vous), sortant (vous vous connectez), ou les deux.'), h('li', {}, h('b', {}, 'Protocole'), ' — TCP (web, mail, SSH), UDP (DNS, jeux, voix), ICMP (ping).'), h('li', {}, h('b', {}, 'Port local / distant'), ' — pour un serveur chez vous, le port local est celui que vous ouvrez (80). Pour visiter un site, le port distant est celui du site (443).'), h('li', {}, h('b', {}, 'Adresses'), ' — une IP (8.8.8.8), un réseau (192.168.1.0/24) ou une plage (10.0.0.1-10.0.0.50). Vide = tout le monde.'), h('li', {}, h('b', {}, 'Action'), ' — autoriser ou bloquer.')),
      callout('warn', h('b', {}, 'L’ordre compte' + (isWin ? ' (sauf sous Windows)' : '') + '. '), isWin ? 'Le pare-feu Windows fait toujours gagner un blocage sur une autorisation. Bastion le signale.' : 'La première règle qui correspond décide. Mettez les exceptions précises AVANT les règles générales : « autoriser SSH depuis mon réseau » avant « bloquer SSH pour tous ».')]],
    ['ouverts', 'Exemples : ports ouverts', () => [h('p', {}, 'Ouvrir un port, c’est laisser entrer des connexions vers un service qui tourne chez vous. N’ouvrez que ce dont vous avez besoin, et limitez à votre réseau quand c’est possible.'), ex('Serveur web local (80/443)'), ex('SSH depuis le réseau local seulement'), ex('Home Assistant (8123) depuis le LAN'), ex('Serveur Minecraft (25565)'), ex('Plage de ports (exemple 5000-5100)')]],
    ['fermes', 'Exemples : ports fermés', () => [h('p', {}, 'Fermer un port, c’est refuser les connexions vers un service. Avec l’entrée bloquée par défaut, tout est déjà fermé ; ces règles servent à verrouiller explicitement un service sensible (et à journaliser les tentatives).'), ex('Bloquer Telnet (23)'), ex('Bloquer le partage Windows (135, 139, 445)'), ex('Bloquer le Bureau à distance (3389)'), ex('Bloquer BitTorrent (6881-6889)'), ex('Bloquer une adresse IP')]],
    ['apps', 'Exemples : applications autorisées ou bloquées', () => [isWin ? h('p', {}, 'Sous Windows, une règle peut viser un programme précis (son chemin complet). Utilisez l’onglet ', h('b', {}, 'Applications'), ' ou le bouton « Règle… » dans Connexions, qui pré-remplit le chemin.') : h('p', {}, 'Sous Linux, nftables ne reconnaît pas les programmes mais les comptes. La méthode : lancer une application sous un compte dédié, puis autoriser ou bloquer ce compte.'),
      ex('Autoriser Firefox (Windows)'), ex('Autoriser Chrome (Windows)'), ex('Bloquer un programme (Windows)'), ex('Bloquer Internet à un utilisateur (Linux)'), ex('Autoriser le compte www-data à sortir sur le web (Linux)'),
      callout('info', 'Stratégie « liste blanche » : passez le trafic sortant en « Bloquer » (Options), puis autorisez uniquement DNS, web et vos programmes de confiance.')]],
    ['mac', 'Filtrer par adresse MAC', () => [h('p', {}, 'L’adresse MAC identifie la carte réseau d’un appareil de votre réseau local (ex. AA:BB:CC:DD:EE:FF). Utile pour bloquer ou autoriser un appareil précis même si son adresse IP change.'), ex('Bloquer un appareil par son adresse MAC'), ex('SSH autorisé uniquement depuis mon PC (MAC)'), h('ul', {}, h('li', {}, h('b', {}, 'Où la trouver : '), 'commande ', h('span', { class: 'mono' }, isWin ? 'arp -a' : 'ip neigh'), ' (appareils vus récemment) ou réglages Wi-Fi de l’appareil.'), h('li', {}, h('b', {}, 'Limite : '), 'l’adresse MAC n’existe que sur le réseau local ; elle ne traverse pas un routeur.'), h('li', {}, isWin ? 'Sous Windows, Bastion convertit la MAC en adresses IP d’après la table ARP au moment d’« Appliquer » : l’appareil doit être présent, et il faut réappliquer si son IP change.' : 'Sous Linux, en entrée la MAC est comparée directement (fiable). En sortie, Bastion la convertit en IP via la table de voisinage au moment d’« Appliquer ».'))]],
    ['icmp', 'Ping et ICMP', () => [h('p', {}, 'Le ping utilise ICMP type 8. Autoriser votre ping sortant permet de tester le réseau ; refuser le ping entrant rend votre machine discrète.'), ex('Autoriser mon ping sortant'), ex('Refuser le ping entrant'), ex('ICMP type 3 code 4 (fragmentation)')]],
    ['zones', 'Zones de confiance', () => [h('p', {}, 'Une zone regroupe des adresses auxquelles vous faites confiance (votre réseau maison) ou pas du tout. Les zones passent avant les règles : une zone de confiance laisse tout passer entre vous et ces adresses.'), h('div', { class: 'ex' }, h('div', { class: 'ico b' }, icon('zones')), h('div', { class: 'tx' }, h('b', {}, 'Réseau maison en confiance'), h('p', {}, 'Dans Zones, « Ajouter mon réseau local (modèle) » crée 192.168.0.0/16, 10.0.0.0/8 et 172.16.0.0/12.')))]],
    ['politique', 'Politique par défaut et mode furtif', () => [h('p', {}, 'La politique par défaut s’applique à ce qu’aucune règle ne traite.'), h('ul', {}, h('li', {}, h('b', {}, 'Classique (recommandé) : '), 'entrant bloqué, sortant autorisé. Vos programmes fonctionnent, personne ne peut entrer sans règle.'), h('li', {}, h('b', {}, 'Strict : '), 'entrant et sortant bloqués. Il faut autoriser DNS, web et chaque service utile.')), h('p', {}, h('b', {}, 'Mode furtif : '), 'les paquets refusés sont ignorés sans réponse. Un scanneur de ports ne voit rien, comme si la machine n’existait pas. Désactivé, le pare-feu répond « refusé », ce qui est plus pratique pour diagnostiquer.')]],
    ['appliquer', 'Appliquer, confirmer, revenir en arrière', () => [h('p', {}, 'Vos modifications sont enregistrées au fil de l’eau mais ne touchent le système qu’au clic sur ', h('b', {}, 'Appliquer'), '. Un compte à rebours demande ensuite de confirmer. Si vous vous êtes coupé d’Internet, ne faites rien : l’état précédent revient seul.'), h('ul', {}, h('li', {}, 'Le délai se règle dans Options (0 pour désactiver).'), h('li', {}, h('b', {}, 'Désactiver Bastion'), ' (Tableau de bord) retire toutes ses règles du système.'), h('li', {}, isWin ? 'Sous Windows, les règles restent après un redémarrage.' : 'Sous Linux, nftables oublie les règles au redémarrage : lancez « sudo python3 pare_feu.py --apply » au démarrage (voir le LISEZMOI).'))]],
    ['journal', 'Journal et alertes', () => [h('p', {}, 'Le Journal affiche les paquets bloqués (journal du noyau sous Linux, fichier pfirewall.log sous Windows) et l’historique des actions de Bastion.'), isWin ? h('p', {}, 'Les alertes signalent un programme sans règle qui ouvre une connexion : choisissez Autoriser, Bloquer ou Ignorer. La détection se fait quelques secondes après la première connexion.') : h('p', {}, 'Sous Linux, cochez « Journaliser » dans une règle pour tracer ses paquets.')]],
    ['os', 'Windows et Linux : différences', () => [h('div', { class: 'tbl-wrap' }, h('table', {}, h('thead', {}, h('tr', {}, ['', 'Windows', 'Linux'].map(t => h('th', {}, t)))), h('tbody', {}, [['Moteur', 'Pare-feu Windows (netsh)', 'nftables'], ['Filtrage par programme', 'Oui (chemin de l’exécutable)', 'Non — par compte utilisateur'], ['Ordre des règles', 'Le blocage l’emporte toujours', 'Première correspondance'], ['Persistance', 'Automatique', 'À réappliquer au démarrage'], ['Alertes nouvelles applications', 'Oui', 'Non'], ['Droits requis', 'Administrateur', 'root (sudo)']].map(r => h('tr', {}, r.map((c, i) => h('td', { class: i === 0 ? 'muted' : '' }, c)))))))]],
    ['depannage', 'Dépannage : j’ai perdu Internet', () => [h('ol', {}, h('li', {}, 'Attendez la fin du compte à rebours sans confirmer : l’état précédent revient.'), h('li', {}, 'Sinon, Tableau de bord → ', h('b', {}, 'Désactiver Bastion'), '.'), h('li', {}, 'Si vous bloquez le trafic sortant par défaut, vérifiez les règles DNS (UDP 53) et Web (TCP 80/443).'), h('li', {}, 'Consultez le Journal : la dernière ligne « bloqué » désigne souvent le coupable.')), callout('ok', 'Dernier recours Linux : ', h('span', { class: 'mono' }, 'sudo nft delete table inet bastion'), isWin ? ' · Windows : ' : '', isWin ? h('span', { class: 'mono' }, 'netsh advfirewall reset') : null)]],
    ['glossaire', 'Glossaire', () => [h('div', { class: 'tbl-wrap' }, h('table', {}, h('tbody', {}, [['TCP / UDP', 'Deux façons d’échanger des données. TCP vérifie la livraison (web, mail), UDP va vite (DNS, jeux, voix).'], ['ICMP', 'Messages de contrôle réseau (le ping).'], ['Port', 'Numéro (1–65535) qui désigne un service sur une machine : 80 web, 443 web chiffré, 22 SSH, 53 DNS.'], ['CIDR', '192.168.1.0/24 = les 256 adresses de 192.168.1.0 à 192.168.1.255. /16 = 65 536 adresses.'], ['Plage', 'Écrite « début-fin » : 5000-5100 (ports) ou 10.0.0.1-10.0.0.50 (adresses).'], ['Entrant / sortant', 'Entrant : on se connecte à vous. Sortant : vous vous connectez.'], ['Drop / reject', 'Drop ignore le paquet en silence ; reject répond « refusé ».']].map(([a, b]) => h('tr', {}, h('td', { class: 'nowrap' }, h('b', {}, a)), h('td', {}, b))))))]],
  ];
}
function viewHelp() {
  const secs = helpSections();
  const toc = h('div', { class: 'toc' }, secs.map(([id, t]) => h('a', { href: '#' + id, class: S.helpSec === id ? 'on' : '', onclick: e => { e.preventDefault(); S.helpSec = id; document.getElementById('h-' + id).scrollIntoView({ behavior: 'smooth' }); document.querySelectorAll('.toc a').forEach(a => a.classList.toggle('on', a.getAttribute('href') === '#' + id)); } }, t)));
  return h('div', { class: 'help-wrap' }, toc, h('div', {}, secs.map(([id, t, fn]) => h('section', { class: 'help-sec card', id: 'h-' + id, style: 'margin-bottom:16px' }, h('h2', {}, t), fn()))));
}

/* ------------------------------------------------------------ assemblage */
function renderView() {
  const el = document.getElementById('view'); if (!el) return; const v = S.view;
  const sc = document.querySelector('.main') ? window.scrollY : 0;
  el.replaceChildren(v === 'dash' ? viewDash() : v === 'rules' ? viewRules(false) : v === 'apps' ? viewRules(true) : v === 'zones' ? viewZones() : v === 'conn' ? viewConn() : v === 'log' ? viewLog() : v === 'prof' ? viewProf() : v === 'opt' ? viewOpt() : viewHelp());
  window.scrollTo(0, sc);
}
function renderAll() {
  const app = document.getElementById('app');
  if (!document.getElementById('view')) app.replaceChildren(h('div', { class: 'shell' }, h('aside', { class: 'side', id: 'side' }), h('main', { class: 'main' }, h('div', { class: 'topbar', id: 'top' }), h('div', { id: 'banners' }), h('div', { id: 'view' }))));
  renderSide(); renderTop(); renderBanners(); renderView();
}
async function poll() {
  try {
    if (S.locked) return;
    const prev = S.st; S.st = await api('/api/state');
    if (S.st.alerts_supported) S.alerts = await api('/api/alerts');
    if (S.view === 'conn' || S.view === 'dash') { S.conn = (await api('/api/connections')).rows; }
    renderSide(); renderTop(); renderBanners();
    if (S.view === 'conn') fillConn();
    if (S.view === 'dash' && !document.querySelector('.overlay')) { if (!S.logT || Date.now() - S.logT > 10000) { S.log = await api('/api/log'); S.logT = Date.now(); } renderView(); }
  } catch (e) { }
}
async function boot() {
  const app = document.getElementById('app');
  const ses = await fetch('/api/session', { headers: { 'X-Bastion': '1' }, credentials: 'same-origin' }).then(r => r.json()).catch(() => null);
  if (!ses) { app.replaceChildren(h('div', { class: 'lock' }, h('div', { class: 'card' }, h('h3', {}, 'Accès refusé'), h('p', { class: 'muted' }, 'Relancez Bastion pour obtenir un lien d’accès valide.')))); return; }
  if (!ses.unlocked) {
    const pw = h('input', { type: 'password', placeholder: 'Mot de passe', autofocus: true }); const err = h('div', { class: 'err' });
    const go = async () => { const r = await fetch('/api/login', { method: 'POST', headers: { 'X-Bastion': '1', 'Content-Type': 'application/json' }, credentials: 'same-origin', body: JSON.stringify({ password: pw.value }) }).then(r => r.json()); if (r.ok) { S.locked = false; S.st = null; document.getElementById('app').replaceChildren(); init(); } else err.textContent = r.error; };
    pw.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
    app.replaceChildren(h('div', { class: 'lock' }, h('div', { class: 'card' }, h('div', { class: 'logo', style: 'margin:0 auto 12px;width:52px;height:52px;border-radius:14px;background:linear-gradient(135deg,var(--accent),var(--accent2));display:grid;place-items:center' }, icon('lock', 26)), h('h3', {}, 'Bastion est verrouillé'), h('div', { class: 'field', style: 'margin-top:14px' }, pw), h('button', { class: 'btn primary', style: 'width:100%;justify-content:center', onclick: go }, 'Déverrouiller'), err)));
    return;
  }
  init();
}
let timer = null;
async function init() {
  S.locked = false; S.st = await api('/api/state'); S.lib = await api('/api/library'); S.libAll = await api('/api/library/all');
  if (S.st.alerts_supported) S.alerts = await api('/api/alerts');
  document.getElementById('app').replaceChildren(); renderAll();
  clearInterval(timer); timer = setInterval(poll, 2000);
}
boot();
