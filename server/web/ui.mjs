// HTML for the public site and the admin panel. The Manager's own style sheet
// (manager/app/style.css) carries the look; pg.css adds the few pieces it lacks.

export const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

const MARK = `<svg viewBox="0 0 28 28" aria-hidden="true"><rect width="28" height="28" rx="6" fill="#0F5F4B"/><rect x="7" y="6" width="14" height="16" rx="2" fill="none" stroke="#F2F8F5" stroke-width="1.6"/><circle cx="14" cy="12.5" r="2.4" fill="none" stroke="#F2F8F5" stroke-width="1.6"/><path d="M14 15v4" stroke="#F2F8F5" stroke-width="1.6" stroke-linecap="round"/></svg>`;

export function doc(title, body, { script = '' } = {}) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title><link rel="icon" href="/assets/favicon.svg"><link rel="stylesheet" href="/assets/manager.css"><link rel="stylesheet" href="/assets/pg.css"></head>
<body>${body}${script ? `<script>${script}</script>` : ''}</body></html>`;
}

export const pill = (state) => ({
  active: '<span class="pill sealed"><i></i>Active</span>',
  blocked: '<span class="pill exposed"><i></i>Blocked</span>',
  pending: '<span class="pill"><i></i>Waiting</span>',
  unconfirmed: '<span class="pill"><i></i>E-mail not confirmed</span>',
}[state] ?? `<span class="pill">${esc(state)}</span>`);

export const ago = (t) => {
  if (!t) return '—';
  const s = Math.floor(Date.now() / 1000) - t;
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return new Date(t * 1000).toISOString().slice(11, 16);
  const d = Math.floor(s / 86400);
  return d === 1 ? 'yesterday' : `${d} days ago`;
};
export const date = (t) => (t ? new Date(t * 1000).toISOString().replace('T', ' ').slice(0, 16) + ' UTC' : '—');

// ---- public site ------------------------------------------------------------------------------
function publicShell(cfg, main) {
  return `<header class="pg-top"><div class="masthead pg-wrap"><a class="pg-brand" href="/">${MARK}<b>HEM Playground</b><span>${esc(cfg.domain)}</span></a>
<nav class="row"><a href="https://docs.encedo.com/hem-api">API reference</a><a href="https://github.com/encedo/hem-sdk-js">hem-sdk-js</a></nav></div></header>
<main class="pg-wrap pg-main">${main}</main>
<footer class="note pg-foot">Encedo HEM Playground · a test environment · nothing here is a real module</footer>`;
}

export function registerPage(cfg, { values = {}, error = null } = {}) {
  const v = { prefix: '', email: '', variant: 'PPA', ...values };
  const main = `<div class="page-head"><p class="eyebrow">Virtual module</p><h1>A module of your own, under your own name, in a minute.</h1>
<p class="pg-lede">A virtual HEM answers the same REST API as a PPA, so the Manager, hem-sdk-js and hem-api-tester work against it unchanged.</p></div>
<div class="pg-split">
<form class="card lifted" method="post" action="/register">
<div class="card-head"><span>New module</span><span class="v">2 fields</span></div>
<div class="card-body">
${error ? `<p class="notice risk">${esc(error)}</p>` : ''}
<div class="field"><label for="prefix">Prefix</label>
<div class="affix"><input id="prefix" name="prefix" value="${esc(v.prefix)}" required pattern="[a-z0-9][a-z0-9-]{1,30}[a-z0-9]" autocomplete="off" spellcheck="false" aria-describedby="prefix-hint"><span>.${esc(cfg.domain)}</span></div>
<p id="prefix-hint" class="hint" aria-live="polite"></p>
<p class="hint">3 to 32 characters: a–z, 0–9 and hyphens. It becomes the module's address and cannot be changed.</p></div>
<div class="field"><label for="email">E-mail</label><input id="email" name="email" type="email" value="${esc(v.email)}" required>
<p class="hint">${cfg.mode === 'auto' ? 'The address the administrator can reach you at.' : 'Where the confirmation goes, and the address the administrator can reach you at.'}</p></div>
<fieldset class="field pg-choices"><legend class="name">Variant</legend>
<label class="choice"><input type="radio" name="variant" value="PPA"${v.variant !== 'EPA' ? ' checked' : ''}><span class="mono">PPA</span><span>drives, audit log, uploads — what the Manager is built for</span></label>
<label class="choice"><input type="radio" name="variant" value="EPA"${v.variant === 'EPA' ? ' checked' : ''}><span class="mono">EPA</span><span>the cloud variant: no drives, no uploads</span></label>
</fieldset>
<div class="row"><button class="button" type="submit">Register the module</button><span class="note">It starts out of the box: not personalised.</span></div>
</div></form>
<dl class="pg-aside">
<div class="item"><dt>What you get</dt><dd>An address with a TLS certificate, the 1.3.x API with real cryptography — including ML-KEM, ML-DSA and X-Wing — and the Manager to run it.</dd></div>
<div class="item"><dt>What it costs</dt><dd class="risk">Keys live in a database on a shared server, not in a secure element. Never put a real key or a real secret in it.</dd></div>
<div class="item"><dt>What it is not</dt><dd>It is not genuine: its device certificate comes from the playground's own test CA, not from Encedo's.</dd></div>
<div class="item"><dt>How long it lives</dt><dd>Until it is deleted, or ${cfg.idleDays ? `${cfg.idleDays} days without a request` : 'for as long as the playground runs'}. The administrator can block or reset it at any time.</dd></div>
</dl></div>`;
  const script = `const i=document.getElementById('prefix'),h=document.getElementById('prefix-hint');let t;
i.addEventListener('input',()=>{clearTimeout(t);const p=i.value.trim().toLowerCase();if(!p){h.textContent='';return}t=setTimeout(async()=>{try{const r=await fetch('/check?prefix='+encodeURIComponent(p));const j=await r.json();if(i.value.trim().toLowerCase()!==p)return;h.textContent=j.message;h.className='hint '+(j.free?'ok':'risk')}catch{}},250)});`;
  return doc('HEM Playground', publicShell(cfg, main), { script });
}

export function registeredPage(cfg, m) {
  const url = `https://${m.prefix}.${cfg.domain}`;
  const mgr = `https://manager.${cfg.domain}/?hem=${encodeURIComponent(url)}`;
  const main = `<div class="page-head"><p class="eyebrow">Module registered</p><h1>${esc(m.prefix)}.${esc(cfg.domain)} is answering, and still in its box.</h1>
<p>Personalise it in the Manager to choose its passwords; until then only the out-of-the-box endpoints answer.</p></div>
<div class="card"><div class="card-head"><span class="v">${esc(m.prefix)}</span>${pill('active')}</div>
<dl class="status-grid">
<div><dt>Address</dt><dd class="mono">${esc(url)}</dd></div>
<div><dt>Variant</dt><dd class="mono">${esc(m.variant)}</dd></div>
<div><dt>Personalised</dt><dd class="pending">Not yet</dd></div>
<div><dt>Owner</dt><dd class="mono">${esc(m.email)}</dd></div>
<div><dt>Registered</dt><dd class="mono">${date(m.created)}</dd></div>
<div><dt>Expires</dt><dd>${cfg.idleDays ? `After ${cfg.idleDays} days without a request` : 'Never'}</dd></div>
</dl></div>
<ol class="steps">
<li class="step"><span class="step-n">01</span><div class="stack-s"><h2>Personalise it in the Manager.</h2><p class="soft">The Manager opens on this module and walks through the out-of-the-box setup: a user password, a master password and the 24 words.</p><div><a class="button" href="${esc(mgr)}">Open in the Manager</a></div><p class="note">${esc(mgr)}</p></div></li>
<li class="step"><span class="step-n">02</span><div class="stack-s"><h2>Or drive it from code.</h2><p class="soft">hem-sdk-js takes the address as it would a module on the desk.</p>
<pre class="blob">import { HEM } from './hem-sdk.js';
const hem = new HEM('${esc(url)}');
console.log(await hem.getStatus());</pre></div></li>
<li class="step"><span class="step-n">03</span><div class="stack-s"><h2>Or run hem-api-tester against it.</h2><p class="soft">The tester personalises the module itself, so run it on a module still in its box, or have it reset first.</p>
<pre class="blob">$cfg_epa_domain = "${esc(m.prefix)}.${esc(cfg.domain)}";</pre></div></li>
</ol>`;
  return doc(`${m.prefix} · HEM Playground`, publicShell(cfg, main));
}

export function messagePage(cfg, eyebrow, heading, text, extra = '') {
  const main = `<section class="card lifted pg-narrow"><div class="card-body"><p class="eyebrow">${esc(eyebrow)}</p><h1>${esc(heading)}</h1><p class="soft">${text}</p>${extra}</div></section>`;
  return doc(heading, publicShell(cfg, main));
}

// ---- admin ------------------------------------------------------------------------------------
export function adminShell(cfg, active, main, { count = 0, user = '' } = {}) {
  const nav = (href, label, key, c = '') => `<a href="${href}"${active === key ? ' class="active" aria-current="page"' : ''}>${label}${c !== '' ? ` <span class="pg-count">${c}</span>` : ''}</a>`;
  return doc('Playground admin', `<div class="app">
<aside class="sidebar"><div class="brand">${MARK}<div class="name"><b>Playground admin</b><span>admin.${esc(cfg.domain)}</span></div></div>
<nav class="nav">${nav('/', 'Modules', 'modules', count)}${nav('/settings', 'Settings', 'settings')}</nav>
<div class="sidebar-foot"><span>Signed in as <span class="host">${esc(user)}</span></span><span>Registration: <span class="host">${esc(cfg.modeLabel)}</span></span><a href="/logout">Sign out</a></div></aside>
<main class="main">${main}</main></div>`);
}

export function signinPage(cfg, { error = null, oidc = true } = {}) {
  return doc('Admin sign-in', `<div class="app centered"><div class="signin">
<div class="brand">${MARK}<div class="name"><b>Playground admin</b><span>admin.${esc(cfg.domain)}</span></div></div>
<form class="card lifted" method="post" action="/login"><div class="card-head"><span>Playground administration</span><span class="v">Signed out</span></div>
<div class="card-body"><p class="eyebrow">Administrator</p><h1>Sign in to see every virtual module.</h1>
${error ? `<p class="notice risk">${esc(error)}</p>` : ''}
${oidc ? `<a class="button" href="/auth/oidc">Sign in with Encedo</a><p class="note">With your own HEM at ${esc(cfg.oidcHost)}; this panel never sees a password.</p>
<div class="pg-or note"><span></span>or with a password<span></span></div>` : ''}
<div class="field"><label for="u">User</label><input id="u" name="user" autocomplete="username" required></div>
<div class="field"><label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password" required></div>
<button class="button plain" type="submit">Sign in with the password</button>
<p class="note">Either way, only accounts on the administrator list get in. Five wrong tries lock this address out for 15 minutes.</p>
</div></form></div></div>`);
}
