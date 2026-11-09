// The panel, at admin.<domain> (administrators) and account.<domain> (owners): sign-in, modules, settings.

import { esc, pill, ago, date, adminShell, signinPage, linkSentPage, prefixScript } from './ui.mjs';
import * as auth from './auth.mjs';
import { MODE_LABEL } from '../registry.mjs';

const NUM = ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten', 'eleven', 'twelve', 'thirteen', 'fourteen', 'fifteen', 'sixteen', 'seventeen', 'eighteen', 'nineteen', 'twenty'];
const word = (n, cap = false) => { const w = NUM[n] ?? String(n); return cap ? w[0].toUpperCase() + w.slice(1) : w; };
const plural = (n, one, many) => (n === 1 ? one : many);

function moduleUrl(cfg, p) { return `https://${p}.${cfg.domain}`; }
function managerUrl(cfg, p) { return `https://manager.${cfg.domain}/?hem=${encodeURIComponent(moduleUrl(cfg, p))}`; }
const actForm = (prefix, action, label, csrf, cls = 'plain') => `<form method="post" action="/m/${esc(prefix)}/${action}"><input type="hidden" name="csrf" value="${esc(csrf)}"><button class="button small ${cls}" type="submit">${label}</button></form>`;

export function modulesPage(cfg, sess, mods, query, create = {}) {
  const csrf = auth.csrfToken(sess);
  const waiting = mods.filter((m) => m.state === 'pending');
  const counts = { all: mods.length, active: mods.filter((m) => m.state === 'active').length, pending: waiting.length, blocked: mods.filter((m) => m.state === 'blocked').length, unconfirmed: mods.filter((m) => m.state === 'unconfirmed').length };
  const filter = ['active', 'pending', 'blocked', 'unconfirmed'].includes(query.get('state')) ? query.get('state') : 'all';
  const q = (query.get('q') ?? '').trim().toLowerCase();
  const shown = mods.filter((m) => (filter === 'all' || m.state === filter) && (!q || m.prefix.includes(q) || m.email.toLowerCase().includes(q)))
    .sort((a, b) => (b.lastReq || b.created) - (a.lastReq || a.created));
  const owner = sess.role !== 'admin';
  const head = owner ? (mods.length === 0 ? 'No module is registered with your address.' : mods.length === 1 ? 'One module is yours.' : `${word(mods.length, true)} modules are yours.`)
    : mods.length === 0 ? 'No modules yet.' : `${word(mods.length, true)} ${plural(mods.length, 'module', 'modules')}${waiting.length ? `, ${word(waiting.length)} waiting for you` : ''}.`;
  const room = !(cfg.modulesPerEmail > 0 && mods.length >= cfg.modulesPerEmail);
  const lede = owner ? (mods.length ? `Open one to reboot it, put it back in its box or give its prefix up.${room ? ' Add another under the list.' : ''}` : 'Add one under the list.')
    : mods.length === 0 ? `The first one appears here as soon as someone registers at ${esc(cfg.domain)}.`
    : `${word(counts.active, true)} ${plural(counts.active, 'answers', 'answer')} requests${counts.blocked ? `, ${word(counts.blocked)} ${plural(counts.blocked, 'is', 'are')} blocked` : ''}${counts.unconfirmed ? `, ${word(counts.unconfirmed)} ${plural(counts.unconfirmed, 'waits', 'wait')} for an e-mail to be confirmed` : ''}. Registration is ${esc(MODE_LABEL[cfg.mode])}.`;
  const seg = (key, label) => `<a href="/?state=${key}${q ? `&q=${encodeURIComponent(q)}` : ''}"${filter === key ? ' class="on"' : ''}>${label} ${counts[key]}</a>`;
  const needs = !owner && waiting.length ? `<section class="card needs"><div class="card-head"><span>Needs you</span><span>${waiting.length} ${plural(waiting.length, 'registration', 'registrations')}</span></div>
<div class="table-wrap"><table><thead><tr><th>Prefix</th><th>E-mail</th><th>Variant</th><th>Confirmed</th><th></th></tr></thead><tbody>
${waiting.map((m) => `<tr><td class="mono">${esc(m.prefix)}</td><td class="mono">${esc(m.email)}</td><td class="mono">${esc(m.variant)}</td><td class="mono">${date(m.confirmed)}</td>
<td><div class="acts">${actForm(m.prefix, 'approve', 'Approve', csrf, '')}${actForm(m.prefix, 'reject', 'Reject', csrf)}</div></td></tr>`).join('')}
</tbody></table></div></section>` : '';
  // an owner's modules are all theirs: no Owner column for them
  const rows = shown.map((m) => `<tr><td class="mono"><a href="/m/${esc(m.prefix)}">${esc(m.prefix)}</a></td>${owner ? '' : `<td class="mono">${esc(m.email)}</td>`}<td class="mono">${esc(m.variant)}</td>
<td>${pill(m.state)}</td><td>${m.inited ? 'Yes' : 'Not yet'}</td><td class="mono">${m.keys}</td><td class="mono">${ago(m.lastReq)}</td>
<td><div class="acts">${m.state === 'active' ? `<a class="button small plain" href="${esc(managerUrl(cfg, m.prefix))}">Open in the Manager</a>` : ''}</div></td></tr>`).join('');
  const main = `<div class="page-head"><p class="eyebrow">Modules</p><h1>${head}</h1><p>${lede}</p></div>${needs}
<section class="card"><div class="card-head"><span>All modules</span><span class="v">${mods.length}</span></div>
<form class="toolbar" method="get" action="/"><input type="search" name="q" value="${esc(q)}" placeholder="${owner ? 'Prefix' : 'Prefix or e-mail'}" aria-label="Search modules"><input type="hidden" name="state" value="${esc(filter)}">
<div class="seg" role="group" aria-label="Filter by state">${seg('all', 'All')}${seg('active', 'Active')}${seg('pending', 'Waiting')}${seg('blocked', 'Blocked')}${counts.unconfirmed ? seg('unconfirmed', 'Unconfirmed') : ''}</div></form>
${shown.length ? `<div class="table-wrap"><table><thead><tr><th>Prefix</th>${owner ? '' : '<th>Owner</th>'}<th>Variant</th><th>State</th><th>Personalised</th><th>Keys</th><th>Last request</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`
    : `<div class="card-body"><p class="soft">${mods.length ? 'Nothing matches.' : 'Nothing registered yet.'}</p></div>`}
${owner ? addRow(cfg, sess, mods, create) : ''}
<div class="card-foot"><span>${shown.length} of ${mods.length}, newest request first</span></div></section>
${owner ? '' : createCard(cfg, sess, create)}`;
  return adminShell(cfg, 'modules', main, { count: mods.length, user: sess.u, role: sess.role, script: owner ? prefixScript('a-prefix', 'a-hint') : prefixScript('c-prefix', 'c-hint') });
}

export function modulePage(cfg, sess, m, { dev, boot, log, keys, statusJson, count }) {
  const csrf = auth.csrfToken(sess);
  const p = m.prefix;
  const st = m.state === 'active' ? (dev.inited ? 'is personalised and answering.' : 'is answering, still in its box.') : m.state === 'blocked' ? 'is blocked: every request gets 503.' : m.state === 'pending' ? 'waits for your approval.' : 'waits for its owner to confirm the e-mail.';
  const reqs = (log ?? []);
  const errs = reqs.filter((r) => r.s >= 400).length;
  const block = m.state === 'blocked' ? ['unblock', 'Unblock', 'Requests are answered again. Keys and settings were kept.'] : ['block', 'Block', 'Every request answers 503 until it is unblocked. Keys and settings stay.'];
  const main = `<a class="note" href="/">← ${sess.role === 'admin' ? 'All modules' : 'My modules'}</a>
<div class="page-head"><p class="eyebrow">Module · ${esc(p)}</p><h1>${esc(p)}.${esc(cfg.domain)} ${st}</h1></div>
<section class="card"><div class="card-head"><span class="v">${esc(p)}</span>${pill(m.state)}</div>
<dl class="status-grid">
<div><dt>Address</dt><dd class="mono">${esc(moduleUrl(cfg, p))}</dd></div>
<div><dt>Owner</dt><dd class="mono">${esc(m.email)}</dd></div>
<div><dt>Variant</dt><dd class="mono">${esc(m.variant)} · ${esc(statusJson.fwv)}</dd></div>
<div><dt>Personalised</dt><dd class="mono">${dev.inited ? `${date(dev.inited).slice(0, 10)} · user "${esc(dev.cfg?.user)}"` : 'Not yet'}</dd></div>
<div><dt>Keys</dt><dd class="mono">${keys} of ${cfg.keysPerModule}</dd></div>
<div><dt>Policy</dt><dd class="mono">${esc((dev.cfg?.policy ?? []).join(', ') || '—')}</dd></div>
<div><dt>Session since</dt><dd class="mono">${date(Math.floor(boot.started / 1000))} (boot ${boot.n})</dd></div>
<div><dt>Requests kept</dt><dd class="mono">${reqs.length} · ${errs} errors</dd></div>
<div><dt>Registered</dt><dd class="mono">${date(m.created).slice(0, 10)}</dd></div>
</dl><p class="status-note">The record holds no passwords: like a real module it keeps only the public keys the passwords derive, so an administrator cannot sign in as the owner.</p></section>
<div class="grid-2">
<section class="card"><div class="card-head"><span>Enter it</span></div>
<div class="act"><div><h2>Open in the Manager</h2><p>The owner's password is still needed; the Manager asks for it as it would on a PPA.</p></div><a class="button" href="${esc(managerUrl(cfg, p))}">Open in the Manager</a></div>
<div class="act"><div><h2>Raw status</h2><p>What GET /api/system/status and /version answer now.</p></div><a class="button plain" href="/m/${esc(p)}/status.json">Show JSON</a></div>
${m.state === 'pending' && sess.role === 'admin' ? `<div class="act"><div><h2>Approve</h2><p>The module starts answering at once.</p></div>${actForm(p, 'approve', 'Approve', csrf, '')}</div>` : ''}
</section>
<section class="card"><div class="card-head"><span>Change its state</span></div>
<div class="act"><div><h2>Reboot</h2><p>New session key: every token issued so far stops working, as after a power cycle.</p></div>${actForm(p, 'reboot', 'Reboot', csrf)}</div>
${sess.role === 'admin' ? `<div class="act"><div><h2>${block[1]}</h2><p>${block[2]}</p></div>${actForm(p, block[0], block[1], csrf)}</div>` : ''}
<div class="act"><div><h2>Reset to the box</h2><p class="risk">Keys, settings and logs are erased; the address stays and the module waits to be personalised again.</p></div>${actForm(p, 'reset', 'Reset', csrf, 'exposed')}</div>
<div class="act"><div><h2>${sess.role === 'admin' ? 'Delete' : 'Give it up'}</h2><p class="risk">The module and its address go. The prefix is free for anyone after that.</p></div>${actForm(p, 'delete', sess.role === 'admin' ? 'Delete' : 'Give it up', csrf, 'exposed')}</div>
</section></div>
<section class="card"><div class="card-head"><span>Last requests</span><span class="v">the last ${cfg.logKeep}, no bodies</span></div>
${reqs.length ? `<div class="table-wrap"><table class="compact"><thead><tr><th>Time</th><th>Method</th><th>Path</th><th>Status</th><th>ms</th><th>Origin</th></tr></thead><tbody>
${reqs.slice(0, 50).map((r) => `<tr><td class="mono">${new Date(r.t * 1000).toISOString().slice(11, 19)}</td><td class="mono">${esc(r.m)}</td><td class="mono">${esc(r.p)}</td><td class="mono${r.s >= 400 ? ' err' : ''}">${r.s}</td><td class="mono">${r.ms}</td><td class="mono">${esc(r.o || '—')}</td></tr>`).join('')}
</tbody></table></div>` : '<div class="card-body"><p class="soft">No request yet.</p></div>'}
<div class="card-foot"><span>${Math.min(50, reqs.length)} of ${reqs.length}</span><a href="/m/${esc(p)}/log.jsonl">Download as JSON lines</a></div></section>`;
  return adminShell(cfg, 'modules', main, { count, user: sess.u, role: sess.role });
}

/** Administrators: the .env's (fixed) and those added here, each removable. */
function adminsCard(csrf, fixed, added, me, error, value) {
  const extra = added.filter((e) => !fixed.includes(e));
  const remove = (e) => `<form method="post" action="/admins/remove"><input type="hidden" name="csrf" value="${esc(csrf)}"><input type="hidden" name="email" value="${esc(e)}"><button class="button small plain" type="submit">Remove</button></form>`;
  const row = (e, from, act) => `<tr><td>${esc(e)}${e === me.toLowerCase() ? ' <span class="soft">(you)</span>' : ''}</td><td class="soft">${from}</td><td><div class="acts">${act}</div></td></tr>`;
  const rows = [...fixed.map((e) => row(e, 'Server .env', '')), ...extra.map((e) => row(e, 'Added here', remove(e)))].join('');
  return `<section class="card" id="admins"><div class="card-head"><span>Administrators</span><span class="v">${fixed.length + extra.length}</span></div>
<div class="table-wrap"><table class="compact"><thead><tr><th>Address</th><th>From</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>
<form class="card-body stack-s" method="post" action="/admins"><input type="hidden" name="csrf" value="${esc(csrf)}">
${error ? `<p class="notice risk">${esc(error)}</p>` : ''}
<div class="pg-form-row pg-end"><div class="field pg-grow"><label for="admin-email">Add an administrator</label><input id="admin-email" name="email" type="email" placeholder="name@example.com" value="${esc(value)}" autocapitalize="none" autocorrect="off" required></div>
<button class="button" type="submit">Add</button></div>
<p class="hint">An administrator signs in at admin. and sees every module, their own among them; the address no longer signs in at account. A change counts at once: someone signed in with the old role signs in again. The addresses in the server's .env stay administrators whatever is done here.</p>
</form></section>
`;
}

export function settingsPage(cfg, sess, s, { count, saved = false, error = null, mailOk, envAdmins = [], adminError = null, adminValue = '' }) {
  const csrf = auth.csrfToken(sess);
  const head = { auto: 'Anyone can register a module, and it answers at once.', email: 'A module answers once its owner confirms the e-mail.', approve: 'A module answers once its e-mail is confirmed and you approve it.' }[s.mode];
  const choice = (v, title, text) => `<label class="choice block"><input type="radio" name="mode" value="${v}"${s.mode === v ? ' checked' : ''}${v !== 'auto' && !mailOk ? ' disabled' : ''}><span><b>${title}</b><p class="soft">${text}</p></span></label>`;
  const num = (name, label, hint = '') => `<div class="field"><label for="${name}">${label}</label><input id="${name}" name="${name}" inputmode="numeric" value="${esc(s[name])}">${hint ? `<p class="hint">${hint}</p>` : ''}</div>`;
  const main = `<div class="page-head"><p class="eyebrow">Settings</p><h1>${head}</h1><p>A change applies to registrations from now on; modules already waiting stay in the list until approved or rejected.</p></div>
${saved ? '<p class="notice safe">The settings are saved.</p>' : ''}${error ? `<p class="notice risk">${esc(error)}</p>` : ''}
<form method="post" action="/settings" class="stack-l"><input type="hidden" name="csrf" value="${esc(csrf)}">
<section class="card"><div class="card-head"><span>Registration</span><span class="v">${esc(MODE_LABEL[s.mode])}</span></div><div class="card-body">
<fieldset class="pg-choices"><legend class="note">How a new module goes live</legend>
${choice('auto', 'Automatic', 'Live as soon as the form is sent. No e-mail is needed.')}
${choice('email', 'E-mail confirmation', `Live when the owner opens the link sent to them.${mailOk ? '' : ' Needs mail to be set up below.'}`)}
${choice('approve', 'E-mail and approval', 'Live when the e-mail is confirmed and an administrator approves it under Needs you.')}
</fieldset></div></section>
<section class="card"><div class="card-head"><span>Limits</span></div><div class="card-body"><div class="form-grid pg-limits">
${num('modulesPerEmail', 'Modules per e-mail', '0 means no limit.')}${num('keysPerModule', 'Keys per module', 'What /api/keymgmt answers 409 above.')}${num('rpm', 'Requests per minute', 'Per module; over it, 429.')}
${num('idleDays', 'Delete after idle days', '0 keeps modules for ever.')}${num('logKeep', 'Requests kept per module')}
</div>
<p class="hint">Prefixes nobody may register are under <a href="/reserved">Reserved prefixes</a>.</p>
</div></section>
<section class="card"><div class="card-head"><span>Options</span></div><div class="card-body stack">
<label class="choice block"><input type="checkbox" name="notifyNew"${s.notifyNew ? ' checked' : ''}><span><b>Tell the administrators of new modules</b><p class="soft">An e-mail with the prefix and the owner's address when a module is registered, and another when its owner confirms the e-mail, so abuse shows. Not for modules made here.${mailOk ? '' : ' Without mail set up the message only goes to the server log.'}</p></span></label>
<p class="hint">More options will come here.</p>
</div></section>
<section class="card"><div class="card-head"><span>Mail</span><span class="v">${mailOk ? 'set up' : 'not set up'}</span></div><div class="card-body">
<p class="hint">Mail settings live in the server's .env (SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, MAIL_FROM), not here, so a password never sits in the database.${mailOk ? '' : ' Without them only automatic registration is offered.'}</p></div></section>
<div class="row"><button class="button" type="submit">Save the settings</button><a class="button plain" href="/settings">Discard changes</a></div>
</form>
${adminsCard(csrf, envAdmins, s.admins ?? [], sess.u, adminError, adminValue)}`;
  return adminShell(cfg, 'settings', main, { count, user: sess.u, role: sess.role });
}

export { signinPage, linkSentPage };

// ---- reserved prefixes --------------------------------------------------------------------
import { SYSTEM_RESERVED, RESERVED_KINDS, patternMatches } from '../registry.mjs';

export function reservedPage(cfg, sess, list, mods, query, { count, done = null, error = null } = {}) {
  const csrf = auth.csrfToken(sess);
  const kind = RESERVED_KINDS[query.get('kind')] ? query.get('kind') : 'all';
  const shown = list.filter((r) => kind === 'all' || r.kind === kind);
  const counts = Object.fromEntries(Object.keys(RESERVED_KINDS).map((k) => [k, list.filter((r) => r.kind === k).length]));
  const seg = (k, label, n) => `<a href="/reserved?kind=${k}"${kind === k ? ' class="on"' : ''}>${label} ${n}</a>`;
  const hits = (p) => mods.filter((m) => patternMatches(p, m.prefix)).map((m) => m.prefix);
  const rows = shown.map((r) => {
    const h = hits(r.pattern);
    return `<tr><td class="mono">${esc(r.pattern)}</td><td><span class="pill">${esc(RESERVED_KINDS[r.kind] ?? r.kind)}</span></td><td>${esc(r.note || '—')}</td>
<td class="mono">${date(r.added).slice(0, 10)}</td><td class="mono${h.length ? ' risk' : ''}">${h.length ? esc(h.slice(0, 3).join(', ')) + (h.length > 3 ? ` +${h.length - 3}` : '') : '—'}</td>
<td><div class="acts"><form method="post" action="/reserved/remove"><input type="hidden" name="csrf" value="${esc(csrf)}"><input type="hidden" name="pattern" value="${esc(r.pattern)}"><button class="button small plain" type="submit">Release</button></form></div></td></tr>`;
  }).join('');
  const total = list.length + SYSTEM_RESERVED.length;
  const main = `<div class="page-head"><p class="eyebrow">Reserved prefixes</p><h1>${word(total, true)} names and patterns are held back from registration.</h1>
<p>Someone who asks for one is told it is not available, never why. Brand and premium names can still be given out by you, under Modules.</p></div>
${done ? `<p class="notice safe">${esc(done)}</p>` : ''}${error ? `<p class="notice risk">${esc(error)}</p>` : ''}
<section class="card"><div class="card-head"><span>Reserve</span><span class="v">one per line</span></div>
<form class="card-body" method="post" action="/reserved"><input type="hidden" name="csrf" value="${esc(csrf)}">
<div class="pg-form-row">
<div class="field pg-grow"><label for="patterns">Prefixes or patterns</label><textarea id="patterns" name="patterns" rows="3" class="mono" required placeholder="acme&#10;encedo*&#10;*word*"></textarea>
<p class="hint">a–z, 0–9, hyphens; <span class="mono">*</span> stands for anything: <span class="mono">encedo*</span> holds every prefix starting with it, <span class="mono">*word*</span> every one containing it.</p></div>
<div class="stack-s pg-side">
<div class="field"><label for="kind">Kind</label><select id="kind" name="kind">${Object.entries(RESERVED_KINDS).map(([k, l]) => `<option value="${k}">${l}</option>`).join('')}</select></div>
<div class="field"><label for="note">Note</label><input id="note" name="note" maxlength="200" placeholder="who asked, why"></div>
</div></div>
<div><button class="button" type="submit">Reserve them</button></div></form></section>
<section class="card"><div class="card-head"><span>Held back</span><span class="v">${list.length}</span></div>
<div class="toolbar"><span class="note">Names that already belong to a module stay with it; the column says which.</span>
<div class="seg" role="group" aria-label="Filter by kind">${seg('all', 'All', list.length)}${Object.entries(RESERVED_KINDS).map(([k, l]) => seg(k, l, counts[k])).join('')}</div></div>
${shown.length ? `<div class="table-wrap"><table><thead><tr><th>Pattern</th><th>Kind</th><th>Note</th><th>Added</th><th>Existing modules</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`
    : `<div class="card-body"><p class="soft">${list.length ? 'None of this kind.' : 'Nothing reserved yet beyond the names below.'}</p></div>`}</section>
<section class="card"><div class="card-head"><span>Held by the playground</span><span class="v">fixed</span></div>
<div class="card-body"><p class="soft">The sites and the DNS names of the certificate. They can not be released or given out.</p>
<p class="mono pg-taglist">${SYSTEM_RESERVED.map(esc).join(' · ')}</p></div></section>`;
  return adminShell(cfg, 'reserved', main, { count, user: sess.u, role: sess.role });
}

/**
 * An owner adds a module under the list: the e-mail is the one they signed in with,
 * so there is nothing to confirm. Folded to a + until it is wanted.
 */
function addRow(cfg, sess, mods, { values = {}, error = null } = {}) {
  const csrf = auth.csrfToken(sess);
  const v = { prefix: '', variant: 'PPA', ...values };
  const limit = cfg.modulesPerEmail;
  const full = limit > 0 && mods.length >= limit;
  if (full) return `<div class="pg-add"><p class="note">${word(limit, true)} ${plural(limit, 'module is', 'modules are')} the most one address may have here. Give one up to add another.</p></div>`;
  return `<details class="pg-add"${error || !mods.length ? ' open' : ''}><summary><span class="pg-plus" aria-hidden="true">+</span>Add a module</summary>
<form method="post" action="/add"><input type="hidden" name="csrf" value="${esc(csrf)}">
${error ? `<p class="notice risk">${esc(error)}</p>` : ''}
<div class="pg-form-row">
<div class="field"><label for="a-prefix">Prefix</label><div class="affix"><input id="a-prefix" name="prefix" value="${esc(v.prefix)}" required autocomplete="off" autocapitalize="none" autocorrect="off" spellcheck="false" aria-describedby="a-hint"><span>.${esc(cfg.domain)}</span></div></div>
<div class="field"><label for="a-variant">Variant</label><select id="a-variant" name="variant"><option${v.variant !== 'EPA' ? ' selected' : ''}>PPA</option><option${v.variant === 'EPA' ? ' selected' : ''}>EPA</option></select></div>
<div class="field"><span class="name" aria-hidden="true">&nbsp;</span><button class="button" type="submit">Add</button></div>
</div>
<p id="a-hint" class="hint" aria-live="polite">3 to 32 characters: a–z, 0–9 and hyphens. Registered to ${esc(sess.u)}${cfg.mode === 'approve' ? '; the administrator approves it before it answers' : ''}.</p>
</form></details>`;
}

export function createCard(cfg, sess, { values = {}, error = null } = {}) {
  const csrf = auth.csrfToken(sess);
  const v = { prefix: '', email: '', variant: 'PPA', ...values };
  return `<section class="card" id="create"><div class="card-head"><span>Create a module</span><span class="v">for someone</span></div>
<form class="card-body" method="post" action="/create"><input type="hidden" name="csrf" value="${esc(csrf)}">
${error ? `<p class="notice risk">${esc(error)}</p>` : ''}
<div class="pg-form-row">
<div class="field"><label for="c-prefix">Prefix</label><div class="affix"><input id="c-prefix" name="prefix" value="${esc(v.prefix)}" required autocomplete="off" autocapitalize="none" autocorrect="off" spellcheck="false" aria-describedby="c-hint"><span>.${esc(cfg.domain)}</span></div><p id="c-hint" class="hint" aria-live="polite"></p></div>
<div class="field pg-grow"><label for="c-email">Owner e-mail</label><input id="c-email" name="email" type="email" value="${esc(v.email)}" required></div>
<div class="field"><label for="c-variant">Variant</label><select id="c-variant" name="variant"><option${v.variant !== 'EPA' ? ' selected' : ''}>PPA</option><option${v.variant === 'EPA' ? ' selected' : ''}>EPA</option></select></div>
</div>
<div class="row"><button class="button" type="submit">Create the module</button><span class="note">Live at once, outside the per-address limit. Brand and premium prefixes can be given out here; the playground's own names can not.</span></div>
</form></section>`;
}

/** Passkeys: the signed-in address's own, added on this device and removed one by one. */
export function passkeysPage(cfg, sess, keys, { count, script }) {
  const csrf = auth.csrfToken(sess);
  const rows = keys.map((k) => `<tr><td>${esc(k.name)}</td><td class="soft">${date(k.created)}</td><td class="soft">${k.used ? ago(k.used) : 'never'}</td>
<td><div class="acts"><form method="post" action="/passkey/remove"><input type="hidden" name="csrf" value="${esc(csrf)}"><input type="hidden" name="id" value="${esc(k.id)}"><button class="button small plain" type="submit">Remove</button></form></div></td></tr>`).join('');
  const main = `<div class="page-head"><p class="eyebrow">Passkeys</p><h1>Sign in with Touch ID, Windows Hello or your phone.</h1>
<p>A passkey signs in as ${esc(sess.u)} without a link. It stays on the device or in its keychain; the playground keeps only its public key. A sign-in link by e-mail still works.</p></div>
<section class="card"><div class="card-head"><span>Your passkeys</span><span class="v">${keys.length}</span></div>
${keys.length ? `<div class="table-wrap"><table class="compact"><thead><tr><th>Device</th><th>Added</th><th>Last used</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>` : '<div class="card-body"><p class="soft">None yet.</p></div>'}
<div class="card-body stack-s"><div><button class="button" type="button" id="pk-add">Add a passkey on this device</button></div>
<p class="notice risk" id="pk-note" hidden></p>
<p class="hint">Each change is mailed to ${esc(sess.u)}.</p></div></section>`;
  return adminShell(cfg, 'passkeys', main, { count, user: sess.u, role: sess.role, script: `${script}
const b = document.getElementById('pk-add'), n = document.getElementById('pk-note');
if (!window.PublicKeyCredential) { b.disabled = true; n.textContent = 'This browser cannot make passkeys.'; n.hidden = false; }
b.onclick = () => pkAdd(${JSON.stringify(csrf)}, n);` });
}
