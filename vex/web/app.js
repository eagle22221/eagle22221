'use strict';
/* vex web interface. Everything shown comes from untrusted files, so
   text is only ever inserted with textContent, never as HTML. Styles are
   set through the CSSOM (never style="" attributes), so the strict
   Content-Security-Policy holds. */

const VEX_VERSION = '0.1.0';
const $ = (id) => document.getElementById(id);

// A small inline SVG icon that points at a <symbol> in index.html's sprite.
// Presentation only — no external requests, CSP-safe.
const SVGNS = 'http://www.w3.org/2000/svg';
function icon(name, cls) {
  const el = document.createElementNS(SVGNS, 'svg');
  el.setAttribute('class', 'ico' + (cls ? ' ' + cls : ''));
  el.setAttribute('viewBox', '0 0 24 24');
  el.setAttribute('aria-hidden', 'true');
  const use = document.createElementNS(SVGNS, 'use');
  use.setAttribute('href', '#i-' + name);
  el.appendChild(use);
  return el;
}

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === 'class') el.className = value;
    else if (key === 'text') el.textContent = value;
    else if (key === 'style') Object.assign(el.style, value);
    else if (key.startsWith('on')) el.addEventListener(key.slice(2), value);
    else if (key in el && key !== 'list') el[key] = value;
    else el.setAttribute(key, value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

// The same for SVG elements (charts, the file tile): attributes only.
function svg(tag, attrs, ...children) {
  const el = document.createElementNS(SVGNS, tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key.startsWith('on')) el.addEventListener(key.slice(2), value);
    else el.setAttribute(key, String(value));
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

// append()/replaceChildren() would print a literal "null" for skipped children
const present = (children) => children.flat().filter((c) => c !== null && c !== undefined && c !== false);
function add(parent, ...children) { parent.append(...present(children)); }
function fill(parent, ...children) { parent.replaceChildren(...present(children)); }

// --- state ------------------------------------------------------------------
// Several files can be open at once, one per tab. Everything that belongs to
// a file lives on its tab; state.path, state.info, state.view and the rest
// read and write the active tab, so the views below need not know about tabs.

const FILE_KEYS = ['path', 'kind', 'name', 'info', 'layout', 'view', 'code', 'bytes', 'archivePath',
  'modify', 'split', 'decode', 'loadMs', 'status', 'error', 'stringsPreset'];

function blankFile(path, kind, name) {
  return {
    path, kind, name, info: null, layout: null,
    view: kind === 'binary' ? 'overview' : 'assets',
    code: { at: null, history: [], filter: '' },
    bytes: { offset: 0 },
    archivePath: kind === 'archive' ? path : null,
    modify: {}, split: null, decode: null,
    loadMs: null, status: path ? 'loading' : 'idle', error: null, stringsPreset: null,
  };
}

const NO_FILE = blankFile(null, null, '');
const state = { token: '', tabs: [], tab: null, codeShow: null };
for (const key of FILE_KEYS) {
  Object.defineProperty(state, key, {
    get() { return (state.tab || NO_FILE)[key]; },
    set(value) { (state.tab || NO_FILE)[key] = value; },
    enumerable: true,
  });
}

// --- server calls -----------------------------------------------------------

async function api(name, params, options) {
  const opts = options || {};
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params || {})) {
    if (v !== undefined && v !== null && v !== '') qs.set(k, v);
  }
  const res = await fetch(`/api/${name}?${qs}`, {
    method: opts.method || 'GET',
    headers: { 'X-Vex-Token': state.token },
    body: opts.body,
  });
  if (!res.ok) {
    let message = res.statusText;
    try { message = (await res.json()).error || message; } catch (e) { /* not JSON */ }
    const error = new Error(message);
    error.status = res.status;
    throw error;
  }
  return opts.raw ? res.blob() : res.json();
}

function toast(message, isError) {
  const el = $('toast');
  el.textContent = message;
  el.className = 'toast' + (isError ? ' is-error' : '');
  el.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { el.hidden = true; }, isError ? 9000 : 4500);
}

const fail = (error) => toast(error.message || String(error), true);

function bytesText(n) {
  if (n === null || n === undefined) return '';
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let value = n / 1024, i = 0;
  while (value >= 1024 && i < units.length - 1) { value /= 1024; i++; }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[i]}`;
}

const hex = (n) => '0x' + n.toString(16);
const hexU = (n) => '0x' + n.toString(16).toUpperCase();
const grouped = (n) => Number(n).toLocaleString('en-US');

function busy(text) { return h('p', { class: 'busy', text: text || 'Working…' }); }

function debounce(fn, ms) {
  let timer;
  return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), ms); };
}

function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = h('a', { href: url, download: filename });
  add(document.body, a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

function suggestOutput(path, word) {
  const slash = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'));
  const dot = path.lastIndexOf('.');
  return dot > slash ? `${path.slice(0, dot)}.${word}${path.slice(dot)}` : `${path}.${word}`;
}

async function copyText(text, label) {
  let ok = false;
  try {
    await navigator.clipboard.writeText(text);
    ok = true;
  } catch (e) {
    const area = h('textarea', { class: 'sr-only', value: text, readOnly: true, 'aria-hidden': 'true' });
    add(document.body, area);
    area.select();
    try { ok = document.execCommand('copy'); } catch (err) { ok = false; }
    area.remove();
  }
  if (ok) toast(`Copied the ${label} to the clipboard.`);
  else toast('The clipboard is not available here. Select the text and copy it instead.', true);
}

// A small in-page dialog that asks for a path: resolves to the text, or null.
function ask(title, note, value, okLabel) {
  const dialog = $('ask-dialog');
  $('ask-title').textContent = title;
  $('ask-note').textContent = note;
  $('ask-input').value = value;
  $('ask-ok').textContent = okLabel || 'Save';
  return new Promise((resolve) => {
    const form = $('ask-form');
    const finish = (result) => {
      form.removeEventListener('submit', onSubmit);
      $('ask-cancel').removeEventListener('click', onCancel);
      dialog.removeEventListener('cancel', onCancel);
      if (dialog.open) dialog.close();
      resolve(result);
    };
    const onSubmit = (e) => { e.preventDefault(); finish($('ask-input').value.trim() || null); };
    const onCancel = () => finish(null);
    form.addEventListener('submit', onSubmit);
    $('ask-cancel').addEventListener('click', onCancel);
    dialog.addEventListener('cancel', onCancel);
    dialog.showModal();
    $('ask-input').focus();
  });
}

// --- popover menus ------------------------------------------------------------
// One menu open at a time; Escape or a click elsewhere closes it, arrow keys
// move between its items.

let openMenu = null;

function closeMenu(returnFocus) {
  if (!openMenu) return;
  const { button, panel } = openMenu;
  panel.hidden = true;
  button.setAttribute('aria-expanded', 'false');
  openMenu = null;
  if (returnFocus) button.focus();
}

function toggleMenu(button, panel) {
  if (openMenu && openMenu.button === button) { closeMenu(); return; }
  closeMenu();
  panel.hidden = false;
  button.setAttribute('aria-expanded', 'true');
  openMenu = { button, panel };
  const first = panel.querySelector('[role="menuitem"]:not([disabled]), button:not([disabled]), input:not([disabled])');
  if (first) first.focus();
}

// A button with a drop-down list of actions: [{ label, icon, run, hint }].
function menuButton(label, iconName, items, extraClass) {
  const panel = h('div', { class: 'popover', role: 'menu', hidden: true, 'aria-label': label });
  const button = h('button', {
    type: 'button', class: 'btn' + (extraClass ? ' ' + extraClass : ''), 'aria-haspopup': 'menu', 'aria-expanded': 'false',
    onclick: () => toggleMenu(button, panel),
  }, iconName ? icon(iconName) : null, label, icon('chevdown', 'btn-caret'));
  for (const item of items) {
    add(panel, h('button', {
      type: 'button', class: 'menu-item', role: 'menuitem', 'aria-current': item.current ? 'page' : null,
      onclick: () => { closeMenu(); item.run(); },
    }, icon(item.icon), h('span', { text: item.label }), item.hint ? h('small', { text: item.hint }) : null));
  }
  return h('div', { class: 'menu-wrap' }, button, panel);
}

document.addEventListener('click', (e) => {
  if (openMenu && !openMenu.panel.contains(e.target) && !openMenu.button.contains(e.target)) closeMenu();
});
document.addEventListener('keydown', (e) => {
  if (!openMenu) return;
  if (e.key === 'Escape') { e.preventDefault(); closeMenu(true); return; }
  if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
  const items = [...openMenu.panel.querySelectorAll('[role="menuitem"]:not([disabled])')];
  if (!items.length) return;
  e.preventDefault();
  const at = items.indexOf(document.activeElement);
  const next = e.key === 'ArrowDown' ? (at + 1) % items.length : (at - 1 + items.length) % items.length;
  items[next].focus();
});

// --- views registry ---------------------------------------------------------
// The order is the sidebar's: Overview, then the Analysis, Resources and
// Advanced groups. `side` is the longer name the sidebar shows.

const VIEWS = {
  overview: { label: 'Overview', group: null, render: renderOverview, kinds: ['binary'], icon: 'overview' },
  techniques: { label: 'Techniques', group: 'analysis', render: renderTechniques, kinds: ['binary'], icon: 'techniques' },
  code: { label: 'Code', side: 'Code (Disassembly)', group: 'analysis', render: renderCode, kinds: ['binary'], icon: 'code' },
  strings: { label: 'Strings', group: 'analysis', render: renderStrings, kinds: ['binary'], icon: 'strings' },
  imports: { label: 'Imports', group: 'analysis', render: renderImports, kinds: ['binary'], icon: 'imports' },
  exports: { label: 'Exports', group: 'analysis', render: renderExports, kinds: ['binary'], icon: 'exports' },
  sections: { label: 'Sections', group: 'analysis', render: renderSections, kinds: ['binary'], icon: 'sections' },
  bytes: { label: 'Bytes', side: 'Bytes (Hex)', group: 'analysis', render: renderBytes, kinds: ['binary'], icon: 'bytes' },
  assets: { label: 'Assets', group: 'resources', render: renderAssets, kinds: ['binary', 'archive', 'folder'], icon: 'assets' },
  entropy: { label: 'Entropy', group: 'advanced', render: renderEntropy, kinds: ['binary'], icon: 'entropy' },
  split: { label: 'Split', group: 'advanced', render: renderSplit, kinds: ['binary'], icon: 'split' },
  decode: { label: 'Decode', group: 'advanced', render: renderDecode, kinds: ['binary'], icon: 'decode' },
  modify: { label: 'Modify', side: 'Patching / Modify', group: 'advanced', render: renderModify, kinds: ['binary'], icon: 'modify' },
};
const NAV_GROUPS = [
  { id: 'analysis', title: 'Analysis' },
  { id: 'resources', title: 'Resources' },
  { id: 'advanced', title: 'Advanced' },
];
// The row of view tabs under the file header; the tools (Split, Decode,
// Modify) join it while one of them is open.
const TAB_ROW = ['overview', 'sections', 'code', 'strings', 'imports', 'exports', 'bytes', 'entropy', 'techniques', 'assets'];
const TOOLS = ['split', 'decode', 'modify', 'assets'];

const viewAllowed = (id) => Boolean(state.path) && VIEWS[id].kinds.includes(state.kind);

function renderNav() {
  const nav = $('nav');
  fill(nav);
  if (!state.path) {
    add(nav, h('div', { class: 'nav-empty' },
      h('p', { text: 'No file is open yet. Open a program, a game folder or an asset pack to explore it.' }),
      h('button', { type: 'button', class: 'btn btn-primary btn-small', onclick: openDialog }, icon('open'), 'Open File')));
    return;
  }
  const item = (id, extra) => h('button', {
    type: 'button', class: 'nav-item' + (extra ? ' ' + extra : ''),
    'aria-current': state.view === id ? 'page' : null,
    onclick: () => show(id),
  }, icon(VIEWS[id].icon, 'nav-ico'), h('span', { class: 'nav-label', text: VIEWS[id].side || VIEWS[id].label }));
  if (viewAllowed('overview')) add(nav, item('overview', 'nav-home'));
  for (const group of NAV_GROUPS) {
    const ids = Object.keys(VIEWS).filter((id) => VIEWS[id].group === group.id && viewAllowed(id));
    if (!ids.length) continue;
    add(nav, h('div', { class: 'nav-group', role: 'group', 'aria-label': group.title },
      h('p', { class: 'nav-title', text: group.title }), ids.map((id) => item(id))));
  }
}

function renderViewTabs() {
  const row = $('viewtabs');
  fill(row);
  if (!state.path || state.status !== 'ready') { row.hidden = true; return; }
  const ids = TAB_ROW.filter(viewAllowed);
  if (!ids.includes(state.view) && viewAllowed(state.view)) ids.push(state.view);
  for (const id of ids) {
    add(row, h('button', {
      type: 'button', class: 'viewtab', 'aria-current': state.view === id ? 'page' : null,
      onclick: () => show(id),
    }, icon(VIEWS[id].icon), VIEWS[id].label));
  }
  row.hidden = false;
  // keep the current view's tab in sight when the row scrolls sideways
  const active = row.querySelector('[aria-current="page"]');
  if (active && row.scrollWidth > row.clientWidth) {
    const left = active.offsetLeft - 8;
    const right = active.offsetLeft + active.offsetWidth + 8 - row.clientWidth;
    row.scrollLeft = Math.min(Math.max(row.scrollLeft, right), left);
  }
}

let renderSerial = 0;
let viewObservers = [];

async function show(view) {
  if (!state.path || !VIEWS[view] || !viewAllowed(view)) return;
  const changed = state.view !== view;
  state.view = view;
  state.codeShow = null;
  closeSidebar();
  renderNav();
  renderViewTabs();
  if (state.status !== 'ready') return;          // the load in progress shows it when done
  for (const observer of viewObservers) observer.disconnect();
  viewObservers = [];
  const main = $('main');
  const serial = ++renderSerial;
  if (changed) {
    const scroller = $('scroller');
    const tabs = $('viewtabs');
    if (scroller.scrollTop > tabs.offsetTop) scroller.scrollTop = tabs.offsetTop - 8;
  }
  fill(main, busy('Loading…'));
  const box = h('div', { class: `view view-${view}` });
  try {
    await VIEWS[view].render(box);
  } catch (error) {
    fill(box, h('p', { class: 'notice is-error', text: error.message }));
  }
  if (serial === renderSerial) fill(main, box);
}

// --- tabs, file header and status bar -----------------------------------------

function fileTypeTile(info, kind, path) {
  if (kind === 'folder') return 'DIR';
  if (kind === 'archive') {
    const ext = extension(path || '');
    return (ext || 'PAK').slice(0, 4).toUpperCase();
  }
  if (!info) return '…';
  if (info.format === 'PE') return info.kind === 'dll' ? 'DLL' : info.kind === 'driver' ? 'SYS' : 'EXE';
  if (info.kind === 'shared library') return 'SO';
  if (info.kind === 'relocatable') return 'O';
  if (info.kind === 'core') return 'CORE';
  return 'ELF';
}

const formatName = (info) => `${info.format}${info.bits}`;
const platformName = (info) => `${info.format === 'ELF' ? 'Linux' : 'Windows'} ${formatName(info)}`;
const typeText = (info) => `${info.format === 'ELF' ? 'Linux' : 'Windows'} ${info.kind}, ${info.bits}-bit ${info.arch}`;

let svgSerial = 0;
function fileDoc() {
  const id = 'doc-grad-' + (++svgSerial);
  return svg('svg', { class: 'filedoc', viewBox: '0 0 52 64', 'aria-hidden': 'true' },
    svg('defs', {}, svg('linearGradient', { id, x1: '0', y1: '0', x2: '0.4', y2: '1' },
      svg('stop', { offset: '0', class: 'doc-stop-a' }), svg('stop', { offset: '1', class: 'doc-stop-b' }))),
    svg('path', { d: 'M9 1.5h23.5L50.5 19.5V56a6.5 6.5 0 0 1-6.5 6.5H9A6.5 6.5 0 0 1 2.5 56V8A6.5 6.5 0 0 1 9 1.5z', fill: `url(#${id})`, class: 'doc-body' }),
    svg('path', { d: 'M32.5 1.5v12a6 6 0 0 0 6 6h12z', class: 'doc-fold' }),
    svg('path', { d: 'M11 20h15M11 26.5h22M11 33h18', class: 'doc-lines' }));
}

function renderTabs() {
  const box = $('filetabs');
  fill(box);
  for (const tab of state.tabs) {
    const active = tab === state.tab;
    add(box, h('div', { class: 'filetab' + (active ? ' is-active' : '') + (tab.status === 'loading' ? ' is-loading' : ''), role: 'presentation' },
      h('button', {
        type: 'button', class: 'filetab-open', role: 'tab', 'aria-selected': active ? 'true' : 'false',
        title: tab.path, onclick: () => switchTab(tab),
      }, icon('file'), h('span', { class: 'filetab-name', text: tab.name })),
      h('button', {
        type: 'button', class: 'filetab-close', 'aria-label': `Close ${tab.name}`, title: 'Close',
        onclick: () => closeTab(tab),
      }, icon('close'))));
  }
}

function renderFileHead() {
  const head = $('filehead');
  fill(head);
  if (!state.path) { head.hidden = true; return; }
  const info = state.info;
  const binary = state.kind === 'binary';
  const badges = [];
  if (binary && info) {
    badges.push(h('span', { class: 'badge' }, icon(info.format === 'PE' ? 'windows' : 'terminal', info.format === 'PE' ? 'ico-windows' : ''), platformName(info)));
    badges.push(h('span', { class: 'badge' }, icon('code'), info.arch));
    badges.push(h('span', { class: 'badge', title: `${grouped(info.size)} bytes` }, icon('report'), bytesText(info.size)));
  } else if (!binary) {
    badges.push(h('span', { class: 'badge' }, icon(state.kind === 'folder' ? 'open' : 'assets'), state.kind === 'folder' ? 'Game folder' : 'Asset pack'));
  }
  const actions = h('div', { class: 'filehead-actions' },
    h('button', { type: 'button', class: 'btn btn-primary', onclick: openDialog }, icon('open'), 'Open File'),
    h('button', { type: 'button', class: 'btn', onclick: refreshFile, disabled: state.status === 'loading' }, icon('refresh'), 'Refresh'),
    binary ? menuButton('Export Report', 'report', [
      { label: 'Markdown report', hint: '.md', icon: 'report', run: () => exportReport('md') },
      { label: 'JSON data', hint: '.json', icon: 'code', run: () => exportReport('json') },
    ]) : null,
    binary ? menuButton('Tools', null, TOOLS.map((id) => ({
      label: VIEWS[id].side || VIEWS[id].label, icon: VIEWS[id].icon, current: state.view === id, run: () => show(id),
    }))) : null);
  if (binary && state.status !== 'ready') for (const b of actions.querySelectorAll('.menu-wrap .btn')) b.disabled = true;
  add(head,
    h('div', { class: 'filetile', 'aria-hidden': 'true' }, fileDoc(), h('span', { class: 'filetile-label', text: fileTypeTile(info, state.kind, state.path) })),
    h('div', { class: 'filehead-text' },
      h('h1', { class: 'filehead-name', text: state.name }),
      h('div', { class: 'filehead-path', text: state.path, title: state.path }),
      badges.length ? h('div', { class: 'badges' }, badges) : null),
    actions);
  head.hidden = false;
}

function statusItem(iconName, text, cls) {
  return h('span', { class: 'status-item' + (cls ? ' ' + cls : '') }, icon(iconName), h('span', { text }));
}

function renderStatus() {
  const bar = $('statusbar');
  fill(bar);
  if (!state.path) {
    add(bar, statusItem('sparkle', 'Ready', 'status-state'), statusItem('open', 'Open a file to begin'));
    return;
  }
  if (state.status === 'loading') {
    add(bar, statusItem('clock', `Analysing ${state.name}…`, 'status-state is-busy'));
    return;
  }
  if (state.status === 'error') {
    add(bar, statusItem('close', 'Could not analyse this file', 'status-state is-error'), statusItem('file', state.name));
    return;
  }
  const info = state.info;
  const right = h('div', { class: 'status-right' },
    state.loadMs !== null ? statusItem('clock', `${(state.loadMs / 1000).toFixed(2)} s`) : null,
    info ? statusItem('chip', bytesText(info.size)) : null,
    info ? statusItem(info.format === 'PE' ? 'windows' : 'terminal', `${formatName(info)} (${info.arch})`)
      : statusItem(state.kind === 'folder' ? 'open' : 'assets', state.kind === 'folder' ? 'Game folder' : 'Asset pack'));
  add(bar, statusItem('check', 'Analysis complete', 'status-state'), statusItem('file', state.name), right);
}

function renderChrome() {
  renderTabs();
  renderNav();
  renderFileHead();
  renderViewTabs();
  renderStatus();
  $('goto').hidden = state.kind !== 'binary' || state.status !== 'ready';
  document.title = state.path ? `${state.name} · vex` : 'vex';
}

function switchTab(tab) {
  if (tab === state.tab) return;
  closeMenu();
  state.tab = tab;
  state.codeShow = null;
  renderChrome();
  $('scroller').scrollTop = 0;
  if (tab.status === 'ready') show(tab.view);
  else if (tab.status === 'error') showLoadError();
  else fill($('main'), busy(`Reading ${tab.name}…`));
}

function closeTab(tab) {
  const at = state.tabs.indexOf(tab);
  if (at < 0) return;
  state.tabs.splice(at, 1);
  if (tab !== state.tab) { renderTabs(); return; }
  const next = state.tabs[Math.min(at, state.tabs.length - 1)] || null;
  state.tab = null;
  if (next) { switchTab(next); return; }
  renderChrome();
  renderWelcome();
}

function showLoadError() {
  fill($('main'), h('div', { class: 'notice is-error' },
    h('strong', { text: `vex could not read ${state.name}. ` }), state.error || '',
    ' ', h('button', { class: 'link', type: 'button', text: 'Try again', onclick: refreshFile })));
}

// Read (or re-read) the active tab's file: the info and layout every view
// uses, timed for the status bar.
async function loadFile() {
  const tab = state.tab;
  if (!tab) return;
  const started = performance.now();
  tab.status = 'loading';
  tab.error = null;
  renderChrome();
  fill($('main'), busy(`Reading ${tab.name}…`));
  if (tab.kind === 'binary') {
    try {
      const [info, layout] = await Promise.all([api('info', { path: tab.path }), api('layout', { path: tab.path })]);
      tab.info = info;
      tab.layout = layout;
    } catch (error) {
      tab.status = 'error';
      tab.error = error.message;
      tab.loadMs = null;
      if (state.tab === tab) { renderChrome(); showLoadError(); }
      return;
    }
  }
  tab.loadMs = performance.now() - started;
  tab.status = 'ready';
  if (state.tab !== tab) { renderTabs(); return; }
  renderChrome();
  show(tab.view);
}

function refreshFile() {
  if (!state.tab) return;
  forgetEntropy(state.path);
  state.codeShow = null;
  loadFile();
}

// --- opening things ---------------------------------------------------------

async function openPath(path) {
  let opened;
  try {
    opened = await api('open', { path });
  } catch (error) { fail(error); return; }
  const existing = state.tabs.find((t) => t.path === opened.path);
  if (existing) { switchTab(existing); return; }
  if (opened.kind === 'unknown') {
    try {
      await api('archive/list', { path: opened.path, limit: 1 });
      opened.kind = 'archive';
    } catch (error) {
      toast(`${opened.name} is not a Linux/Windows program or an asset pack vex can read.`, true);
      return;
    }
  }
  const name = opened.path.split(/[\\/]/).filter(Boolean).pop() || opened.path;
  const tab = blankFile(opened.path, opened.kind, name);
  state.tabs.push(tab);
  state.tab = tab;
  state.codeShow = null;
  $('scroller').scrollTop = 0;
  await loadFile();
}

async function uploadFile(file) {
  toast(`Reading ${file.name}…`);
  try {
    const saved = await api('upload', { name: file.name }, { method: 'POST', body: file });
    await openPath(saved.path);
  } catch (error) { fail(error); }
}

async function browse(dir) {
  let listing;
  try {
    listing = await api('browse', { dir });
  } catch (error) { fail(error); return; }
  $('path-input').value = listing.path;
  const places = $('places');
  fill(places,
    listing.parent ? h('button', { type: 'button', class: 'btn btn-small', text: 'Up one folder', onclick: () => browse(listing.parent) }) : null,
    h('button', { type: 'button', class: 'btn btn-small', text: 'Home', onclick: () => browse(listing.home) }),
    listing.roots.map((root) => h('button', { type: 'button', class: 'btn btn-small', text: root, onclick: () => browse(root) })),
    h('button', { type: 'button', class: 'btn btn-small', text: 'Open this folder as a game', onclick: () => { $('open-dialog').close(); openPath(listing.path); } }),
  );
  const box = $('browser');
  fill(box);
  if (!listing.entries.length) add(box, h('p', { class: 'pane-note', text: 'This folder is empty.' }));
  const sep = listing.path.includes('\\') ? '\\' : '/';
  for (const entry of listing.entries) {
    const full = listing.path.endsWith(sep) ? listing.path + entry.name : listing.path + sep + entry.name;
    const kindText = { folder: 'Folder', binary: 'Program', archive: 'Pack', unknown: '' }[entry.kind] || '';
    add(box, h('button', {
      type: 'button', role: 'option',
      onclick: () => {
        if (entry.is_dir) browse(full);
        else { $('open-dialog').close(); openPath(full); }
      },
    },
    h('span', { class: `kind kind-${entry.kind}`, text: kindText }),
    h('span', { text: entry.name }),
    h('span', { class: 'size', text: entry.is_dir ? '' : bytesText(entry.size) })));
  }
}

function welcomeCard(title, text, ...rest) {
  return h('div', { class: 'welcome' }, h('section', { class: 'box welcome-hero' },
    h('img', { class: 'welcome-mark', src: '/static/logo.svg', alt: '', width: 64, height: 64 }),
    h('h1', { text: title }), h('p', { text }), rest));
}

function renderWelcome() {
  const drop = h('div', { class: 'drop' },
    h('strong', { text: 'Drop a program, game file or asset pack here' }),
    h('span', { class: 'muted', text: 'Linux (ELF) and Windows (EXE, DLL) programs; ZIP, PAK, WAD, PCK, ASAR and RPA packs.' }),
    h('button', { type: 'button', class: 'btn btn-primary', onclick: openDialog }, icon('open'), 'Open File'));
  fill($('main'), welcomeCard('Take a program apart and see how it works',
    'vex reads a compiled program without running it and shows what is inside: its layout, the code, the text it contains and the functions it borrows from the system. It can also open game asset packs and save modified copies.',
    drop,
    h('ol', { class: 'steps' },
      h('li', {}, h('span', {}, h('b', { text: 'Open something' }), 'Pick a program, or a game folder to find its engine and asset packs.')),
      h('li', {}, h('span', {}, h('b', { text: 'Read the overview' }), 'What kind of file it is, how it is protected and which libraries it needs.')),
      h('li', {}, h('span', {}, h('b', { text: 'Follow a thread' }), 'Find an interesting string, see which code uses it, then read that function.')))));
}

function openDialog() {
  closeMenu();
  const dialog = $('open-dialog');
  if (!dialog.open) dialog.showModal();
  const start = state.path ? state.path.replace(/[\\/][^\\/]*$/, '') : '';
  browse(state.kind === 'folder' ? state.path : start);
}

// --- file map ---------------------------------------------------------------

const KIND_NAMES = {
  headers: 'Headers', code: 'Code', data: 'Data', meta: 'Tables / debug info',
  overlay: 'Appended data', padding: 'Padding',
};

// Names vex gives regions itself ("headers", "symbol table") read better
// capitalised; section names are shown exactly as the file spells them.
const regionName = (region) => (/^[a-z][a-z ]*$/.test(region.name) && region.kind !== 'code' && region.kind !== 'data'
  ? region.name.replace(/\b[a-z]/g, (c) => c.toUpperCase()) : region.name);

function boxHead(iconName, title, extra, iconClass) {
  return h('div', { class: 'box-head' }, icon(iconName, 'box-ico' + (iconClass ? ' ' + iconClass : '')), h('h3', { text: title }), extra);
}

function mapCard(layout) {
  const strip = h('div', { class: 'map-strip' });
  const readout = h('span', { class: 'map-readout', 'aria-live': 'polite', text: 'Select a region to see its bytes' });
  const kinds = new Map();
  for (const region of layout.regions) {
    if (!kinds.has(region.kind)) kinds.set(region.kind, []);
    kinds.get(region.kind).push(region.name);
    const describe = `${regionName(region)}: offset ${hex(region.offset)}, ${bytesText(region.size)}`;
    const button = h('button', {
      type: 'button', class: `region kind-${region.kind}`, title: describe,
      'aria-label': describe, style: { flexGrow: String(Math.max(region.size, 1)), flexBasis: '0' },
      onmouseenter: () => { readout.textContent = describe; },
      onfocus: () => { readout.textContent = describe; },
      onclick: () => { state.bytes = { offset: region.offset }; show('bytes'); },
    });
    if (region.kind !== 'padding' && region.size / layout.size > 0.06) add(button, h('span', { class: 'region-label', text: regionName(region) }));
    add(strip, button);
  }
  // a label is shown only where its region is wide enough to hold all of it
  const fitLabels = new ResizeObserver(() => {
    for (const label of strip.querySelectorAll('.region-label')) {
      label.hidden = false;
      label.hidden = label.scrollWidth > label.clientWidth + 1;
    }
  });
  fitLabels.observe(strip);
  viewObservers.push(fitLabels);
  const scale = h('div', { class: 'map-scale', 'aria-hidden': 'true' });
  for (const fraction of [0, 0.25, 0.5, 0.75, 1]) {
    add(scale, h('span', {
      class: 'tick' + (fraction === 1 ? ' tick-end' : ''),
      text: hexU(Math.round(layout.size * fraction)),
      style: { left: `${fraction * 100}%` },
    }));
  }
  const legend = h('div', { class: 'map-legend' });
  for (const kind of Object.keys(KIND_NAMES)) {
    if (!kinds.has(kind)) continue;
    const names = kinds.get(kind);
    const detail = (kind === 'code' || kind === 'data') && names.length
      ? ` (${names.slice(0, 3).join(', ')}${names.length > 3 ? ', …' : ''})` : '';
    add(legend, h('span', { class: 'legend-item' }, h('span', { class: `swatch kind-${kind}` }), KIND_NAMES[kind] + detail));
  }
  return h('section', { class: 'box ov-map', 'aria-label': 'File layout, drawn to scale' },
    h('div', { class: 'map' },
      h('div', { class: 'map-main' }, boxHead('layout', 'Binary Layout (Memory Map)', readout), strip, scale),
      legend));
}

// --- entropy ----------------------------------------------------------------
// GET /api/entropy?path=P&points=N -> { size, block, overall, points: [{ offset, entropy }] }
// in bits per byte (0-8). An older server answers 404 (or fails): the charts
// are then left out and the overall figure from /api/info is shown alone.

let entropyRoute = true;
const entropyCache = new Map();

function entropyData(points) {
  if (!entropyRoute || !state.path) return Promise.resolve(null);
  const key = `${state.path}\n${points}`;
  if (!entropyCache.has(key)) {
    const request = api('entropy', { path: state.path, points }).then((data) =>
      (data && Array.isArray(data.points) && data.points.length ? data : null)
    ).catch((error) => {
      entropyCache.delete(key);
      if (error.status === 404 && /unknown API endpoint/i.test(error.message)) entropyRoute = false;
      if (error.status === 404 || error.status >= 500 || !error.status) return null;
      throw error;
    });
    entropyCache.set(key, request);
  }
  return entropyCache.get(key);
}

function forgetEntropy(path) {
  for (const key of [...entropyCache.keys()]) if (key.startsWith(path + '\n')) entropyCache.delete(key);
}

// Draw the chart when its box has a size, and again whenever that changes.
function chartBox(cls, draw, attrs) {
  const el = h('div', Object.assign({ class: 'chart ' + (cls || '') }, attrs || {}));
  let width = 0;
  const observer = new ResizeObserver((entries) => {
    const w = Math.round(entries[0].contentRect.width);
    if (w > 0 && w !== width) { width = w; draw(el, w, el.clientHeight); }
  });
  observer.observe(el);
  viewObservers.push(observer);
  return el;
}

let chartSerial = 0;

function drawEntropy(el, data, W, H, opts) {
  const large = Boolean(opts.large);
  const pad = { l: 34, r: 10, t: 10, b: large ? 40 : 6 };
  const iw = Math.max(10, W - pad.l - pad.r);
  const ih = Math.max(10, H - pad.t - pad.b);
  const size = Math.max(1, data.size || 1);
  const pts = data.points;
  const n = pts.length;
  const centre = pts.map((p, i) => {
    const end = i + 1 < n ? pts[i + 1].offset : size;
    return p.offset + Math.max(0, end - p.offset) / 2;
  });
  const X = (offset) => pad.l + (offset / size) * iw;
  const Y = (e) => pad.t + (1 - Math.max(0, Math.min(8, e)) / 8) * ih;
  const id = 'ent-' + (++chartSerial);
  const xs = centre.map(X);
  const ys = pts.map((p) => Y(p.entropy));
  const line = xs.map((x, i) => `${i ? 'L' : 'M'}${x.toFixed(1)} ${ys[i].toFixed(1)}`).join(' ');
  const area = n ? `${line} L${xs[n - 1].toFixed(1)} ${Y(0)} L${xs[0].toFixed(1)} ${Y(0)} Z` : '';

  const root = svg('svg', { viewBox: `0 0 ${W} ${H}`, width: W, height: H, role: 'img',
    'aria-label': `Entropy across the file, ${n} blocks of ${data.block} bytes; overall ${data.overall.toFixed(2)} of 8` },
  svg('defs', {},
    svg('linearGradient', { id: id + '-line', gradientUnits: 'userSpaceOnUse', x1: pad.l, y1: 0, x2: pad.l + iw, y2: 0 },
      svg('stop', { offset: '0', class: 'stop-teal' }), svg('stop', { offset: '1', class: 'stop-violet' })),
    svg('linearGradient', { id: id + '-fade', x1: '0', y1: '0', x2: '0', y2: '1' },
      svg('stop', { offset: '0', class: 'stop-fade-a' }), svg('stop', { offset: '1', class: 'stop-fade-b' })),
    svg('mask', { id: id + '-mask' }, svg('rect', { x: 0, y: 0, width: W, height: H, fill: `url(#${id}-fade)` }))));

  if (large && opts.regions) {
    for (const region of opts.regions) {
      if (region.kind === 'padding') continue;
      const x0 = X(region.offset);
      const w = Math.max(1, X(region.offset + region.size) - x0);
      add(root, svg('rect', { class: `band band-${region.kind}`, x: x0, y: pad.t, width: w, height: ih }));
      if (w > 46) add(root, svg('text', { class: 'band-label', x: x0 + 4, y: pad.t + ih + 30 }, regionName(region)));
    }
  }
  for (const v of [0, 2, 4, 6, 8]) {
    add(root, svg('line', { class: v === 0 ? 'axis-line' : 'grid-line', x1: pad.l, x2: pad.l + iw, y1: Y(v), y2: Y(v) }),
      svg('text', { x: pad.l - 8, y: Y(v) + 4, 'text-anchor': 'end' }, v.toFixed(1)));
  }
  add(root, svg('line', { class: 'axis-line', x1: pad.l, x2: pad.l, y1: pad.t, y2: pad.t + ih }));
  if (large) {
    add(root, svg('line', { class: 'limit-line', x1: pad.l, x2: pad.l + iw, y1: Y(7.2), y2: Y(7.2) }),
      svg('text', { class: 'limit-text', x: pad.l + iw - 4, y: Y(7.2) - 6, 'text-anchor': 'end' }, 'above 7.2: compressed or encrypted'));
    for (const f of [0, 0.25, 0.5, 0.75, 1]) {
      add(root, svg('text', { x: pad.l + f * iw, y: pad.t + ih + 15, 'text-anchor': f === 0 ? 'start' : f === 1 ? 'end' : 'middle' }, hexU(Math.round(size * f))));
    }
  }
  if (n) {
    add(root, svg('path', { d: area, fill: `url(#${id}-line)`, class: 'chart-area', mask: `url(#${id}-mask)` }),
      svg('path', { d: line, stroke: `url(#${id}-line)`, class: 'chart-line' }));
    if (n <= 80) for (let i = 0; i < n; i++) add(root, svg('circle', { class: 'chart-dot', cx: xs[i], cy: ys[i], r: large ? 3.2 : 2.8, fill: `url(#${id}-line)` }));
  }

  if (opts.onPick && n) {
    const guide = svg('line', { class: 'guide', x1: 0, x2: 0, y1: pad.t, y2: pad.t + ih, visibility: 'hidden' });
    const dot = svg('circle', { class: 'hover-dot', r: 5, cx: 0, cy: 0, visibility: 'hidden' });
    const mark = (i) => {
      el.dataset.index = String(i);
      for (const node of [guide, dot]) node.setAttribute('visibility', 'visible');
      guide.setAttribute('x1', xs[i]); guide.setAttribute('x2', xs[i]);
      dot.setAttribute('cx', xs[i]); dot.setAttribute('cy', ys[i]);
      if (opts.onHover) opts.onHover(pts[i], i);
    };
    const nearest = (clientX) => {
      const rect = root.getBoundingClientRect();
      const x = (clientX - rect.left) * (W / rect.width);
      let best = 0;
      for (let i = 1; i < n; i++) if (Math.abs(xs[i] - x) < Math.abs(xs[best] - x)) best = i;
      return best;
    };
    add(root, guide, dot, svg('rect', {
      x: pad.l, y: pad.t, width: iw, height: ih, fill: 'transparent',
      onmousemove: (e) => mark(nearest(e.clientX)),
      onclick: (e) => opts.onPick(pts[nearest(e.clientX)]),
    }));
    el.onkeydown = (e) => {
      let i = el.dataset.index === undefined ? -1 : Number(el.dataset.index);
      if (e.key === 'ArrowRight') i = Math.min(n - 1, i + 1);
      else if (e.key === 'ArrowLeft') i = Math.max(0, i < 0 ? 0 : i - 1);
      else if (e.key === 'Home') i = 0;
      else if (e.key === 'End') i = n - 1;
      else if (e.key === 'Enter' && i >= 0) { opts.onPick(pts[i]); return; } else return;
      e.preventDefault();
      mark(i);
    };
    if (el.dataset.index !== undefined && Number(el.dataset.index) < n) mark(Number(el.dataset.index));
  }
  fill(el, root);
}

function entropyBig(value, note) {
  return h('div', { class: 'entropy-big' },
    h('span', { class: 'entropy-big-label', text: 'Entropy' }),
    h('span', { class: 'entropy-big-value' }, value.toFixed(2), h('small', { text: '/ 8' })),
    note ? h('span', { class: 'entropy-big-note', text: note }) : null);
}

function goToOffset(offset) {
  state.bytes = { offset: Math.max(0, Math.floor(offset / 16) * 16) };
  show('bytes');
}

async function renderEntropy(box) {
  const info = state.info;
  add(box, h('div', { class: 'view-head' }, h('h2', { text: 'Entropy' }),
    h('p', { text: 'How random the bytes are, block by block, from 0 (all the same) to 8 bits per byte. Packed, compressed or encrypted data sits near 8; code and text much lower. Point at the chart to read a block, click it to see its bytes.' })));
  const [data, sections] = await Promise.all([
    entropyData(480),
    api('sections', { path: state.path }).catch(() => []),
  ]);
  const sectionTable = sections.length ? h('section', { class: 'box' },
    boxHead('sections', 'Entropy by section'),
    h('div', { class: 'box-body' }, h('table', { class: 'table-plain' },
      h('thead', {}, h('tr', {}, ['Section', 'File offset', 'Size', 'Entropy'].map((t, i) => h('th', { scope: 'col', text: t, class: i === 1 || i === 2 ? 'num' : '' })))),
      h('tbody', {}, sections.map((s) => h('tr', {},
        h('td', { class: 'mono strong' }, h('button', { class: 'link', type: 'button', text: s.name || '(unnamed)', onclick: () => goToOffset(s.offset) })),
        h('td', { class: 'num mono', text: hex(s.offset) }),
        h('td', { class: 'num', text: bytesText(s.size) }),
        h('td', {}, h('div', { class: 'bar-cell' },
          h('span', { class: 'meter' + (s.entropy > 7.2 ? ' is-high' : '') }, h('i', { style: { width: `${(s.entropy / 8) * 100}%` } })),
          h('span', { class: 'mono', text: s.entropy.toFixed(2) }))))))))) : null;

  if (!data) {
    add(box, h('p', { class: 'notice', text: 'This vex server does not offer the block-by-block entropy chart. The figures below come from the whole file and from each section.' }),
      h('div', { class: 'stack' }, h('div', { class: 'entropy-stats' }, entropyBig(info.entropy, info.entropy > 7.2 ? 'Likely packed or encrypted' : 'Whole file')), sectionTable));
    return;
  }
  let highest = data.points[0];
  for (const p of data.points) if (p.entropy > highest.entropy) highest = p;
  const hot = data.points.filter((p) => p.entropy > 7.2).length;
  const readout = h('div', { class: 'entropy-readout', 'aria-live': 'polite' },
    h('span', { text: 'Point at the chart, or focus it and use the arrow keys.' }));
  const chart = chartBox('chart-large', (el, w, hgt) => drawEntropy(el, data, w, hgt, {
    large: true, regions: state.layout ? state.layout.regions : null,
    onHover: (p, i) => fill(readout,
      h('span', {}, 'Block ', h('b', { text: `${i + 1} of ${data.points.length}` })),
      h('span', {}, 'Offset ', h('b', { text: hexU(p.offset) })),
      h('span', {}, 'Entropy ', h('b', { text: p.entropy.toFixed(2) })),
      h('span', { class: 'muted', text: 'Click or press Enter to see these bytes' })),
    onPick: (p) => goToOffset(p.offset),
  }), { tabIndex: 0, 'aria-label': 'Entropy chart. Use the arrow keys to move between blocks and Enter to see a block’s bytes.' });
  add(box, h('div', { class: 'stack' },
    h('div', { class: 'entropy-layout' },
      h('section', { class: 'box' }, boxHead('entropy', 'Entropy across the file'),
        h('div', { class: 'box-body' }, readout, chart,
          h('p', { class: 'chart-note', text: `${data.points.length} blocks of ${grouped(data.block)} bytes. Shaded bands show the file’s regions, coloured as in the layout map.` }))),
      h('div', { class: 'entropy-stats' },
        entropyBig(data.overall, data.overall > 7.2 ? 'Likely packed or encrypted' : 'Whole file'),
        h('div', { class: 'stat' }, h('span', { text: 'Highest block' }), h('b', { text: highest.entropy.toFixed(2) }),
          h('button', { class: 'link', type: 'button', text: `at ${hexU(highest.offset)}`, onclick: () => goToOffset(highest.offset) })),
        h('div', { class: 'stat' }, h('span', { text: 'Blocks above 7.2' }), h('b', { text: String(hot) }),
          h('span', { text: hot ? 'May hold compressed or encrypted data' : 'Nothing looks packed or encrypted' })),
        h('div', { class: 'stat' }, h('span', { text: 'Block size' }), h('b', { text: bytesText(data.block) }),
          h('span', { text: `${bytesText(data.size)} in total` })))),
    sectionTable));
}

// --- overview ---------------------------------------------------------------

function securityIcon(row) {
  const value = String(row.value).toLowerCase();
  const yes = !['no', 'none', 'off', 'false', 'absent'].includes(value);
  return h('span', { class: 'state-dot' }, icon(yes ? 'check' : 'close'));
}

function flagBadge(p) {
  const perms = p || '---';
  const w = perms[1] === 'w', x = perms[2] === 'x';
  const any = /[rwx]/.test(perms);
  const cls = w && x ? 'flag flag-wx' : w ? 'flag flag-w' : any ? 'flag' : 'flag flag-none';
  const words = [perms[0] === 'r' ? 'read' : null, w ? 'write' : null, x ? 'run' : null].filter(Boolean).join(', ') || 'not loaded';
  return h('span', { class: cls, text: perms.toUpperCase(), title: words });
}

const BUILD_NAMES = {
  interpreter: 'Loader', compiler: 'Compiler', source_files: 'Source files', soname: 'Library name',
  subsystem: 'Subsystem', linker_version: 'Linker version', dll_name: 'Internal name',
  pdb_path: 'Debug file path', imphash: 'Import hash', rpath: 'RPATH', runpath: 'RUNPATH',
};

function buildDetails(md) {
  const rows = [];
  for (const [key, label] of Object.entries(BUILD_NAMES)) {
    if (md[key] === undefined) continue;
    rows.push([label, Array.isArray(md[key]) ? md[key].join(', ') : String(md[key])]);
  }
  if (md.overlay) rows.push(['Appended data', `${bytesText(md.overlay.size)} after the program, at offset ${hex(md.overlay.offset)}`]);
  return rows;
}

async function renderOverview(box) {
  const info = state.info;
  const md = info.metadata;
  const path = state.path;

  const notes = h('div', { class: 'ov-notes' },
    info.warnings.length ? h('div', { class: 'notice' }, h('strong', { text: 'This file is damaged or unusual. ' }), info.warnings.join(' · ')) : null);
  api('techniques', { path }).then((rows) => {
    if (!rows.length) return;
    notes.prepend(h('p', { class: 'notice' },
      h('strong', { text: `vex found ${rows.length} protection or evasion technique${rows.length === 1 ? '' : 's'}: ` }),
      rows.map((t) => t.title).join(', ') + '. ',
      h('button', { class: 'link', type: 'button', text: 'See the evidence', onclick: () => show('techniques') })));
  }).catch(() => {});
  api('engine', { path }).then((result) => {
    if (!result.matches.length) return;
    const best = result.matches[0];
    add(notes, h('p', { class: 'notice is-ok' },
      `This looks like a ${best.engine} game (${best.confidence} confidence). `,
      h('button', { class: 'link', type: 'button', text: 'See its assets', onclick: () => show('assets') })));
  }).catch(() => {});

  // File Information
  const built = md.timestamp ? ['Built', md.timestamp, false] : ['Build ID', md.build_id || 'not recorded', Boolean(md.build_id)];
  const kv = (label, value, mono) => h('tr', {}, h('th', { scope: 'row', text: label }), h('td', { class: mono ? 'mono' : null }, value));
  const infoCard = h('section', { class: 'box ov-info' }, boxHead('file', 'File Information'),
    h('div', { class: 'box-body' }, h('table', { class: 'kv' }, h('tbody', {},
      kv('File Name', info.name),
      kv('Type', typeText(info)),
      kv('Entry Point', info.entry || 'none'),
      kv('Image Base', info.image_base),
      kv('Size', `${bytesText(info.size)} (${grouped(info.size)} bytes)`),
      kv('Entropy', h('div', { class: 'entropy-cell' },
        h('span', { text: `${info.entropy.toFixed(2)} of 8` + (info.entropy > 7.2 ? ' (packed?)' : '') }),
        h('span', { class: 'meter' + (info.entropy > 7.2 ? ' is-high' : ''), role: 'img', 'aria-label': `${info.entropy.toFixed(2)} of 8` },
          h('i', { style: { width: `${(info.entropy / 8) * 100}%` } })))),
      kv(built[0], built[1], built[2])))));

  // Protections & Security
  const protCard = h('section', { class: 'box ov-prot' }, boxHead('shield', 'Protections & Security', null, 'is-good'),
    h('div', { class: 'box-body' }, h('ul', { class: 'checks' }, info.security_details.map((row) =>
      h('li', {}, h('span', { text: row.label }),
        h('span', { class: `state state-${row.state}` }, securityIcon(row), h('span', { text: row.value })))))));

  // Quick Insights
  const libs = info.libraries;
  const insight = (iconName, title, text, view, iconClass) => h('div', { class: 'insight' },
    h('span', { class: 'insight-ico' + (iconClass ? ' ' + iconClass : '') }, icon(iconName)),
    h('span', { class: 'insight-title', text: title }),
    view ? h('button', { type: 'button', class: 'icon-btn insight-go', 'aria-label': `Show ${VIEWS[view].label}`, title: `Show ${VIEWS[view].label}`, onclick: view === 'strings' ? () => { state.stringsPreset = { tagged: true }; show('strings'); } : () => show(view) }, icon('chevright')) : null,
    h('span', { class: 'insight-text', text, title: text }));
  const stringsRow = insight('quote', 'Notable Strings', 'Looking for links, addresses and paths…', 'strings', 'is-violet');
  api('strings', { path, tagged: 1, limit: 12 }).then((found) => {
    stringsRow.querySelector('.insight-title').textContent = `Notable Strings (${found.total})`;
    const text = found.items.length ? found.items[0].text : 'No links, network addresses or file paths found.';
    const el = stringsRow.querySelector('.insight-text');
    el.textContent = text;
    el.title = found.items.map((s) => s.text).join('\n');
  }).catch(() => { stringsRow.querySelector('.insight-text').textContent = 'Not available.'; });
  const hashRow = (label, value) => [
    h('span', { class: 'hash-name', text: label }),
    h('span', { class: 'hash-value', text: value, title: value }),
    h('button', { type: 'button', class: 'icon-btn copy-btn', 'aria-label': `Copy the ${label} hash`, title: `Copy ${label}`, onclick: () => copyText(value, `${label} hash`) }, icon('copy'))];
  const insightsCard = h('section', { class: 'box ov-insights' }, boxHead('bolt', 'Quick Insights'),
    h('div', { class: 'box-body' },
      insight('library', `Libraries (${libs.length})`, libs.length ? libs.join(', ') : 'None. This program is self-contained.', 'imports'),
      stringsRow,
      h('div', { class: 'insight insight-hashes' },
        h('span', { class: 'insight-ico' }, icon('fingerprint')),
        h('span', { class: 'insight-title', text: 'Hashes' }),
        h('div', { class: 'hashes' }, hashRow('SHA-256', info.hashes.sha256), hashRow('MD5', info.hashes.md5), hashRow('SHA-1', info.hashes.sha1)))));

  // Entropy Analysis
  const entropyBody = h('div', { class: 'box-body entropy-box' }, h('div', { class: 'chart' }), entropyBig(info.entropy));
  const entropyCard = h('section', { class: 'box ov-entropy' },
    boxHead('entropy', 'Entropy Analysis', h('button', { type: 'button', class: 'box-link', onclick: () => show('entropy') }, 'Explore', icon('arrowright'))),
    entropyBody);
  entropyData(48).then((data) => {
    if (!data) { entropyBody.firstChild.remove(); entropyBody.classList.add('is-single'); return; }
    entropyBody.firstChild.replaceWith(chartBox('', (el, w, hgt) => drawEntropy(el, data, w, hgt, {})));
  }).catch(() => { entropyBody.firstChild.remove(); entropyBody.classList.add('is-single'); });

  // Section Overview
  const sectionsBody = h('div', { class: 'box-body' }, busy('Reading the section table…'));
  const sectionsCard = h('section', { class: 'box ov-sections' },
    boxHead('table', 'Section Overview', h('button', { type: 'button', class: 'box-link', onclick: () => show('sections') }, 'View All Sections', icon('arrowright'))),
    sectionsBody);
  api('sections', { path }).then((sections) => {
    if (!sections.length) { fill(sectionsBody, h('p', { class: 'pane-note', text: 'This file has no section table. The Sections view lists its segments.' })); return; }
    const shown = sections.length > 7 ? sections.slice(0, 6) : sections;
    fill(sectionsBody, h('div', { class: 'table-scroll' }, h('table', { class: 'table-plain' },
      h('thead', {}, h('tr', {}, ['Section', 'Virtual Size', 'Raw Size', 'Entropy', 'Flags'].map((t) => h('th', { scope: 'col', text: t })))),
      h('tbody', {}, shown.map((s) => h('tr', {},
        h('td', { class: 'strong' }, h('button', { class: 'link link-plain', type: 'button', text: s.name || '(unnamed)', title: `Show the bytes of ${s.name || 'this section'}`, onclick: () => { state.bytes = { offset: s.offset }; show('bytes'); } })),
        h('td', { class: 'tnum', text: hexU(s.vsize) }),
        h('td', { class: 'tnum', text: hexU(s.size) }),
        h('td', { class: 'tnum', text: s.entropy.toFixed(2) }),
        h('td', {}, flagBadge(s.perms))))))),
    sections.length > shown.length ? h('p', { class: 'chart-note', text: `Showing ${shown.length} of ${sections.length} sections.` }) : null);
  }).catch((error) => fill(sectionsBody, h('p', { class: 'pane-note', text: error.message })));

  const details = buildDetails(md);
  add(box, h('div', { class: 'ov' },
    notes,
    state.layout ? mapCard(state.layout) : null,
    h('div', { class: 'ov-row ov-row-3' }, infoCard, protCard, insightsCard),
    h('div', { class: 'ov-row ov-row-2' }, entropyCard, sectionsCard),
    details.length ? h('section', { class: 'box ov-build' }, boxHead('chip', 'Build Details'),
      h('div', { class: 'box-body build-grid' }, h('table', { class: 'kv' }, h('tbody', {}, details.map(([k, v]) => kv(k, v, true)))))) : null));
}

// --- report -----------------------------------------------------------------
// Export Report builds a Markdown or JSON summary in the page, from the same
// API calls the views make, and downloads it named after the file.

const mdCell = (value) => String(value === null || value === undefined ? '' : value)
  .replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/[\r\n]+/g, ' ').replace(/`/g, 'ʼ');

function mdTable(headers, rows) {
  if (!rows.length) return '_None._\n';
  return [`| ${headers.map(mdCell).join(' | ')} |`, `| ${headers.map(() => '---').join(' | ')} |`,
    ...rows.map((r) => `| ${r.map(mdCell).join(' | ')} |`)].join('\n') + '\n';
}

async function collectReport() {
  const path = state.path;
  const info = state.info;
  const soft = (promise, fallback) => promise.catch(() => fallback);
  const [sections, segments, imports, exports_, techniques, strings, entropy] = await Promise.all([
    soft(api('sections', { path }), []), soft(api('segments', { path }), []),
    soft(api('imports', { path }), []), soft(api('exports', { path }), []),
    soft(api('techniques', { path }), []), soft(api('strings', { path, tagged: 1, limit: 200 }), { items: [], total: 0 }),
    soft(entropyData(64), null),
  ]);
  return {
    generator: `vex ${VEX_VERSION}`, generated: new Date().toISOString(),
    file: info, layout: state.layout, sections, segments, imports, exports: exports_, techniques,
    notable_strings: { total: strings.total, items: strings.items }, entropy,
  };
}

function reportMarkdown(r) {
  const info = r.file;
  const md = info.metadata;
  const out = [];
  out.push(`# vex report: ${info.name}`, '',
    `Generated by ${r.generator} on ${r.generated}. vex reads files without running them.`, '');
  out.push('## File', '', mdTable(['Field', 'Value'], [
    ['Name', info.name], ['Path', info.path], ['Type', typeText(info)],
    ['Size', `${bytesText(info.size)} (${grouped(info.size)} bytes)`],
    ['Entry point', info.entry || 'none'], ['Image base', info.image_base],
    ['Entropy', `${info.entropy.toFixed(2)} of 8`],
    [md.timestamp ? 'Built' : 'Build ID', md.timestamp || md.build_id || 'not recorded'],
    ['SHA-256', info.hashes.sha256], ['SHA-1', info.hashes.sha1], ['MD5', info.hashes.md5],
    ...buildDetails(md),
  ]));
  out.push('## Protections', '', ...info.security_details.map((row) => `- ${row.label}: **${row.value}**${row.state === 'bad' ? ' (weak)' : ''}`), '');
  if (info.warnings.length) out.push('## Warnings', '', ...info.warnings.map((w) => `- ${mdCell(w)}`), '');
  out.push(`## Sections (${r.sections.length})`, '', mdTable(['Name', 'Address', 'Virtual size', 'Raw size', 'File offset', 'Flags', 'Entropy'],
    r.sections.map((s) => [s.name, s.address || '', hexU(s.vsize), hexU(s.size), hex(s.offset), (s.perms || '').toUpperCase(), s.entropy.toFixed(2)])));
  if (r.segments.length) {
    out.push(`## Segments (${r.segments.length})`, '', mdTable(['Type', 'Address', 'Size in file', 'Size in memory', 'File offset', 'Flags'],
      r.segments.map((s) => [s.type, s.address, bytesText(s.size), bytesText(s.vsize), hex(s.offset), (s.perms || '').toUpperCase()])));
  }
  out.push(`## Libraries (${info.libraries.length})`, '', info.libraries.length ? info.libraries.map((l) => `- ${mdCell(l)}`).join('\n') + '\n' : '_None. The program is self-contained._\n');
  out.push(`## Imports (${r.imports.length})`, '', mdTable(['Library', 'Function', 'Slot address'], r.imports.map((i) => [i.library || '', i.name, i.address || ''])));
  out.push(`## Exports (${r.exports.length})`, '', mdTable(['Number', 'Name', 'Address', 'Passed on to'], r.exports.map((e) => [e.ordinal === null ? '' : e.ordinal, e.name, e.address || '', e.forwarder || ''])));
  out.push(`## Techniques (${r.techniques.length})`, '');
  if (!r.techniques.length) out.push('_No notable protection or evasion techniques found._', '');
  for (const t of r.techniques) out.push(`### ${mdCell(t.title)} (${t.confidence} confidence)`, '', mdCell(t.explanation), '', ...t.evidence.map((e) => `- ${mdCell(e)}`), '');
  out.push(`## Notable strings (${r.notable_strings.total})`, '', mdTable(['Address', 'Kind', 'Text'],
    r.notable_strings.items.map((s) => [s.address || `file ${hex(s.offset)}`, s.tags.join(', '), s.text])));
  if (r.entropy) {
    let highest = r.entropy.points[0];
    for (const p of r.entropy.points) if (p.entropy > highest.entropy) highest = p;
    out.push('## Entropy', '', `Overall ${r.entropy.overall.toFixed(2)} bits per byte over ${r.entropy.points.length} blocks of ${grouped(r.entropy.block)} bytes; highest ${highest.entropy.toFixed(2)} at ${hexU(highest.offset)}.`, '');
  }
  return out.join('\n');
}

async function exportReport(kind) {
  if (!state.info) return;
  const name = state.name;
  toast('Building the report…');
  try {
    const report = await collectReport();
    const blob = kind === 'json'
      ? new Blob([JSON.stringify(report, null, 2) + '\n'], { type: 'application/json' })
      : new Blob([reportMarkdown(report)], { type: 'text/markdown' });
    saveBlob(blob, `${name}.vex-report.${kind === 'json' ? 'json' : 'md'}`);
    toast(`Saved ${name}.vex-report.${kind === 'json' ? 'json' : 'md'} to your downloads.`);
  } catch (error) { fail(error); }
}

// --- code -------------------------------------------------------------------

async function goTo(text) {
  state.code.at = text;
  if (state.view === 'code' && state.codeShow) return state.codeShow(text, true);
  return show('code');
}

async function renderCode(box) {
  const fnList = h('ul', { class: 'fn-list' });
  const fnCount = h('span', { class: 'count' });
  const listing = h('div', { class: 'listing' });
  const listingTitle = h('h3', { text: 'Code' });
  const refs = h('div');
  const selectedBox = h('div');
  const back = h('button', { type: 'button', class: 'btn btn-small', text: 'Back', disabled: true });
  let currentFunction = null;

  async function loadFunctions() {
    try {
      const found = await api('functions', { path: state.path, q: state.code.filter, limit: 4000 });
      fnCount.textContent = found.total === found.items.length
        ? `${found.total}` : `${found.items.length} of ${found.total}`;
      fill(fnList, ...found.items.map((fn) => h('li', {},
        h('button', {
          type: 'button', title: `${fn.name} at ${fn.address}, ${fn.size} bytes`,
          'data-address': fn.address,
          'aria-current': fn.address === currentFunction ? 'true' : null,
          onclick: () => showCode(fn.address, true),
        }, h('span', { class: 'fn-name', text: fn.name }), h('span', { class: 'fn-size', text: String(fn.size) })))));
      if (!found.items.length) add(fnList, h('li', {}, h('p', { class: 'pane-note', text: 'No function matches.' })));
    } catch (error) {
      fill(fnList, h('li', {}, h('p', { class: 'pane-note', text: error.message })));
    }
  }

  function markCurrent() {
    for (const button of fnList.querySelectorAll('button')) {
      const on = button.dataset.address === currentFunction;
      if (on) button.setAttribute('aria-current', 'true'); else button.removeAttribute('aria-current');
    }
  }

  function selectInstruction(row, insn) {
    for (const el of listing.querySelectorAll('.is-selected')) el.classList.remove('is-selected');
    row.classList.add('is-selected');
    const size = insn.bytes.length / 2;
    fill(selectedBox, 
      h('p', { class: 'pane-note' }, h('span', { class: 'mono', text: `${insn.address}  ${insn.mnemonic} ${insn.operands}` })),
      h('div', { class: 'actions' },
        h('button', { type: 'button', class: 'btn btn-small', text: 'Disable this instruction', onclick: () => {
          state.modify = { nopAddress: insn.address, nopLength: size };
          show('modify');
        } }),
        h('button', { type: 'button', class: 'btn btn-small', text: 'Edit its bytes', onclick: () => {
          state.modify = { bytesAddress: insn.address, bytesHex: insn.bytes.replace(/(..)(?=.)/g, '$1 ') };
          show('modify');
        } }),
        h('button', { type: 'button', class: 'btn btn-small', text: 'Find uses of this address', onclick: () => loadRefs(insn.address, insn.address) })));
  }

  async function loadRefs(target, title) {
    fill(refs, busy('Searching the code…'));
    try {
      const rows = await api('xrefs', { path: state.path, target });
      if (!rows.length) {
        fill(refs, h('p', { class: 'pane-note', text: `Nothing in the code refers to ${title}.` }));
        return;
      }
      fill(refs, 
        h('p', { class: 'pane-note', text: `${rows.length} place${rows.length === 1 ? '' : 's'} use ${title}` }),
        h('ul', { class: 'xref-list' }, rows.map((x) => h('li', {},
          h('button', { class: 'link', type: 'button', text: x.function || x.address, onclick: () => showCode(x.address, true, 24) }),
          h('span', { class: 'mono', text: `${x.address}  ${x.text}` })))));
    } catch (error) {
      fill(refs, h('p', { class: 'pane-note', text: error.message }));
    }
  }

  async function showCode(at, remember, count) {
    fill(listing, busy('Reading the code… the first time can take a moment for big programs.'));
    let data;
    try {
      data = await api('disasm', { path: state.path, at, count });
    } catch (error) {
      fill(listing, h('p', { class: 'pane-note', text: error.message }));
      return;
    }
    if (remember && state.code.at && state.code.at !== data.address) state.code.history.push(state.code.at);
    state.code.at = data.address;
    back.disabled = !state.code.history.length;
    listingTitle.textContent = data.name ? `${data.name}  (${data.address})` : data.address;
    currentFunction = data.function ? data.function.address : null;
    markCurrent();
    fill(selectedBox, h('p', { class: 'pane-note', text: 'Select an instruction to change it or to find what refers to it.' }));
    fill(listing);
    for (const insn of data.instructions) {
      if (insn.label) add(listing, h('div', { class: 'fn-label', text: insn.label + ':' }));
      const operands = [];
      if (insn.target) {
        operands.push(' ', h('button', { class: 'link', type: 'button', text: insn.operands, title: 'Go to ' + insn.target, onclick: (e) => { e.stopPropagation(); showCode(insn.target, true); } }));
      } else if (insn.operands) {
        operands.push(' ' + insn.operands);
      }
      const comment = insn.comment && insn.refs.length && !insn.target
        ? h('button', { class: 'link insn-comment', type: 'button', text: '; ' + insn.comment, title: 'Show the bytes at ' + insn.refs[0], onclick: (e) => { e.stopPropagation(); state.bytes = { address: insn.refs[0] }; show('bytes'); } })
        : h('span', { class: 'insn-comment', text: insn.comment ? '; ' + insn.comment : '' });
      const row = h('div', { class: 'insn', tabIndex: 0 },
        h('span', { class: 'insn-addr', text: insn.address }),
        h('span', { class: 'insn-bytes', text: insn.bytes.replace(/(..)(?=.)/g, '$1 ') }),
        h('span', { class: 'insn-text' }, h('span', { class: 'mn' + (insn.kind ? ' mn-' + insn.kind : ''), text: insn.mnemonic }), operands),
        comment);
      row.addEventListener('click', () => selectInstruction(row, insn));
      row.addEventListener('keydown', (e) => { if (e.key === 'Enter') selectInstruction(row, insn); });
      add(listing, row);
    }
    loadRefs(data.function ? data.function.address : data.address, data.name || data.address);
  }

  back.addEventListener('click', () => {
    const previous = state.code.history.pop();
    if (previous) { state.code.at = null; showCode(previous, false); }
  });
  state.codeShow = showCode;

  const filter = h('input', {
    type: 'text', class: 'fn-filter', placeholder: 'Filter functions', value: state.code.filter,
    'aria-label': 'Filter functions',
    oninput: debounce((e) => { state.code.filter = e.target.value; loadFunctions(); }, 180),
  });

  add(box, 
    h('div', { class: 'view-head' }, h('h2', { text: 'Code' }),
      h('p', { text: 'The program’s instructions, grouped into functions. Green is a call, amber a jump.' })),
    h('div', { class: 'code-grid' },
      h('section', { class: 'pane' },
        h('div', { class: 'pane-head' }, h('h3', { text: 'Functions' }), fnCount),
        filter, h('div', { class: 'pane-body' }, fnList)),
      h('section', { class: 'pane' },
        h('div', { class: 'pane-head' }, listingTitle, back),
        h('div', { class: 'pane-body' }, listing)),
      h('section', { class: 'pane' },
        h('div', { class: 'pane-head' }, h('h3', { text: 'Used by' })),
        h('div', { class: 'pane-body' }, selectedBox, refs))));

  loadFunctions();
  await showCode(state.code.at || undefined, false);
}

// --- strings ----------------------------------------------------------------

async function renderStrings(box) {
  const preset = state.stringsPreset || {};
  state.stringsPreset = null;
  const options = { q: '', tagged: Boolean(preset.tagged), encoding: 'all', min: 4, shown: 300 };
  const tbody = h('tbody');
  const count = h('span', { class: 'count' });
  const more = h('button', { type: 'button', class: 'btn', text: 'Show more', hidden: true });

  async function findUses(s, cellEl) {
    fill(cellEl, 'Searching…');
    try {
      const rows = await api('xrefs', { path: state.path, target: s.address });
      if (!rows.length) { fill(cellEl, h('span', { class: 'muted', text: 'No code refers to it directly' })); return; }
      fill(cellEl, ...rows.map((x) => h('div', {},
        h('button', { class: 'link', type: 'button', text: x.function || x.address, onclick: () => goTo(x.address) }))));
    } catch (error) { fill(cellEl, h('span', { class: 'muted', text: error.message })); }
  }

  async function load() {
    try {
      const found = await api('strings', {
        path: state.path, q: options.q, tagged: options.tagged ? 1 : '', encoding: options.encoding,
        min: options.min, limit: options.shown,
      });
      count.textContent = `${found.items.length} of ${found.total} strings`;
      more.hidden = found.items.length >= found.total;
      fill(tbody, ...found.items.map((s) => {
        const uses = h('td', {});
        if (s.address) add(uses, h('button', { class: 'link', type: 'button', text: 'Find uses', onclick: () => findUses(s, uses) }));
        return h('tr', {},
          h('td', { class: 'mono' }, s.address
            ? h('button', { class: 'link', type: 'button', text: s.address, onclick: () => { state.bytes = { address: s.address }; show('bytes'); } })
            : h('span', { class: 'muted', text: 'file ' + hex(s.offset) })),
          h('td', { class: 'mono', text: s.section || '' }),
          h('td', { class: 'mono wrap' }, s.text, s.encoding === 'utf16' ? h('span', { class: 'muted', text: '  (wide)' }) : null,
            h('button', { class: 'link str-decode', type: 'button', text: 'Decode', title: 'Open this text in the Decode workbench', onclick: () => openInDecode({ kind: 'text', value: s.text }) })),
          h('td', {}, s.tags.map((t) => h('span', { class: `tag tag-${t}`, text: t }))),
          uses);
      }));
    } catch (error) { fail(error); }
  }
  const reload = debounce(() => { options.shown = 300; load(); }, 200);
  more.addEventListener('click', () => { options.shown += 600; load(); });

  add(box, 
    h('div', { class: 'view-head' }, h('h2', { text: 'Strings' }),
      h('p', { text: 'Readable text stored in the file: messages, file names, web addresses. Often the fastest way in.' })),
    h('div', { class: 'toolbar' },
      h('input', { type: 'text', placeholder: 'Search text', 'aria-label': 'Search text', oninput: (e) => { options.q = e.target.value; reload(); } }),
      h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: options.tagged, onchange: (e) => { options.tagged = e.target.checked; reload(); } }), 'Only links, addresses and paths'),
      h('label', { class: 'check' }, 'Kind',
        h('select', { onchange: (e) => { options.encoding = e.target.value; reload(); } },
          h('option', { value: 'all', text: 'All' }), h('option', { value: 'ascii', text: 'Plain (ASCII)' }), h('option', { value: 'utf16', text: 'Wide (UTF-16)' }))),
      h('label', { class: 'check' }, 'Shortest',
        h('input', { type: 'number', min: 2, max: 64, value: 4, style: { width: '5em' }, onchange: (e) => { options.min = e.target.value || 4; reload(); } })),
      count),
    h('div', { class: 'table-wrap' }, h('table', {},
      h('thead', {}, h('tr', {}, ['Address', 'Section', 'Text', 'Looks like', 'Used by'].map((t) => h('th', { scope: 'col', text: t })))),
      tbody)),
    h('p', {}, more));
  await load();
}

// --- imports & exports ------------------------------------------------------

// --- techniques ---------------------------------------------------------------

function evidenceItem(text) {
  const li = h('li', {}, h('span', { class: 'mono', text }));
  const api_name = /^imports (.+)$/.exec(text);
  if (api_name) {
    const uses = h('span', { class: 'evidence-uses' });
    add(li, h('button', { class: 'link', type: 'button', text: 'Find uses', onclick: async (e) => {
      e.target.remove();
      fill(uses, 'Searching…');
      try {
        const found = await api('xrefs', { path: state.path, target: api_name[1] });
        const calls = found.filter((x) => x.kind !== 'jump' || !(x.function || '').includes('@'));
        fill(uses, ...(calls.length ? calls.map((x) =>
          h('button', { class: 'link', type: 'button', text: x.function || x.address, onclick: () => goTo(x.address) }))
          : [h('span', { class: 'muted', text: 'not called directly' })]));
      } catch (error) { fill(uses, h('span', { class: 'muted', text: error.message })); }
    } }), uses);
  } else if (/^(executable )?section |^entry point/.test(text)) {
    add(li, h('button', { class: 'link', type: 'button', text: 'Show sections', onclick: () => show('sections') }));
  } else if (/^appended data/.test(text)) {
    add(li, h('button', { class: 'link', type: 'button', text: 'Show bytes', onclick: () => {
      const m = /offset (0x[0-9a-f]+)/.exec(text);
      state.bytes = { offset: m ? parseInt(m[1], 16) : 0 };
      show('bytes');
    } }));
  }
  return li;
}

// Show each kind of jump link once per card (e.g. one "Show sections").
function dedupeLinks(items) {
  const seen = new Set();
  for (const li of items) {
    const b = li.querySelector('button');
    if (!b || b.textContent === 'Find uses') continue;
    if (seen.has(b.textContent)) b.remove(); else seen.add(b.textContent);
  }
  return items;
}

async function renderTechniques(box) {
  const rows = await api('techniques', { path: state.path });
  add(box, h('div', { class: 'view-head' }, h('h2', { text: `Techniques (${rows.length})` }),
    h('p', { text: 'Protection and evasion techniques this program uses, with the evidence for each. vex identifies them; it never disables or defeats them.' })));
  if (!rows.length) {
    add(box, h('p', { class: 'notice is-ok', text: 'No notable protection or evasion techniques found: no packing, anti-debugging, VM checks, injection, hooking or driver use.' }));
    return;
  }
  add(box, h('div', { class: 'stack' }, rows.map((t) =>
    h('section', { class: `engine technique is-${t.confidence}` },
      h('h3', {}, t.title, h('span', { class: `confidence conf-${t.confidence}`, text: `${t.confidence} confidence` })),
      h('p', { class: 'technique-why', text: t.explanation }),
      h('ul', { class: 'evidence' }, dedupeLinks(t.evidence.map(evidenceItem)))))));
}

async function renderImports(box) {
  const imports = await api('imports', { path: state.path });
  const rows = [];
  let current;
  for (const imp of imports) {
    if (imp.library !== current) {
      current = imp.library;
      rows.push(h('tr', {}, h('th', { colSpan: 3, scope: 'colgroup', text: current || 'Library not recorded' })));
    }
    const target = imp.library && state.info.format === 'PE' ? `${imp.library}!${imp.name}` : imp.name;
    const note = [imp.version, imp.delayed ? 'loaded on first use' : null].filter(Boolean).join(', ');
    rows.push(h('tr', {},
      h('td', { class: 'mono', text: imp.address || '' }),
      h('td', { class: 'mono wrap' }, imp.name, note ? h('span', { class: 'muted', text: '  ' + note }) : null),
      h('td', {}, h('button', { class: 'link', type: 'button', text: 'Find uses', onclick: async (e) => {
        const cellEl = e.target.parentNode;
        fill(cellEl, 'Searching…');
        try {
          const found = await api('xrefs', { path: state.path, target });
          fill(cellEl, ...(found.length ? found.map((x) => h('div', {},
            h('button', { class: 'link', type: 'button', text: x.function || x.address, onclick: () => goTo(x.address) })))
            : [h('span', { class: 'muted', text: 'Not called directly' })]));
        } catch (error) { fill(cellEl, h('span', { class: 'muted', text: error.message })); }
      } }))));
  }
  add(box, 
    h('div', { class: 'view-head' }, h('h2', { text: `Imports (${imports.length})` }),
      h('p', { text: 'Functions this program borrows from the system and other libraries. They show what it is able to do.' })),
    imports.length ? h('div', { class: 'table-wrap' }, h('table', {},
      h('thead', {}, h('tr', {}, ['Slot address', 'Function', 'Called from'].map((t) => h('th', { scope: 'col', text: t })))),
      h('tbody', {}, rows))) : h('p', { class: 'notice', text: 'This file imports nothing.' }));
}

async function renderExports(box) {
  const exports_ = await api('exports', { path: state.path });
  add(box,
    h('div', { class: 'view-head' }, h('h2', { text: `Exports (${exports_.length})` }),
      h('p', { text: 'Functions this file offers to other programs. Libraries (DLL, .so) list theirs here; most programs export nothing.' })),
    exports_.length ? h('div', { class: 'table-wrap' }, h('table', {},
      h('thead', {}, h('tr', {}, ['Number', 'Address', 'Name', 'Passed on to'].map((t) => h('th', { scope: 'col', text: t })))),
      h('tbody', {}, exports_.map((e) => h('tr', {},
        h('td', { class: 'num mono', text: e.ordinal === null ? '' : String(e.ordinal) }),
        h('td', { class: 'mono' }, e.address ? h('button', { class: 'link', type: 'button', text: e.address, onclick: () => goTo(e.address) }) : ''),
        h('td', { class: 'mono wrap', text: e.name }),
        h('td', { class: 'mono', text: e.forwarder || '' }))))))
      : h('p', { class: 'notice', text: 'This file exports nothing.' }));
}

// --- sections ---------------------------------------------------------------

async function renderSections(box) {
  const [sections, segments] = await Promise.all([
    api('sections', { path: state.path }), api('segments', { path: state.path })]);
  const perms = (p) => [p[0] === 'r' ? 'read' : null, p[1] === 'w' ? 'write' : null, p[2] === 'x' ? 'run' : null].filter(Boolean).join(', ') || 'not loaded';
  add(box, 
    h('div', { class: 'view-head' }, h('h2', { text: `Sections (${sections.length})` }),
      h('p', { text: 'The named parts of the file. Entropy near 8 means compressed or encrypted contents.' })),
    sections.length ? h('div', { class: 'table-wrap' }, h('table', {},
      h('thead', {}, h('tr', {}, ['Name', 'Address', 'Size in file', 'Size in memory', 'File offset', 'Access', 'Entropy'].map((t, i) =>
        h('th', { scope: 'col', text: t, class: i >= 2 && i <= 4 ? 'num' : '' })))),
      h('tbody', {}, sections.map((s) => h('tr', {},
        h('td', { class: 'mono' }, h('button', { class: 'link', type: 'button', text: s.name || '(unnamed)', onclick: () => { state.bytes = { offset: s.offset }; show('bytes'); } })),
        h('td', { class: 'mono', text: s.address || '' }),
        h('td', { class: 'num mono', text: bytesText(s.size) }),
        h('td', { class: 'num mono', text: bytesText(s.vsize) }),
        h('td', { class: 'num mono', text: hex(s.offset) }),
        h('td', {}, h('span', { class: 'perm-cell' }, flagBadge(s.perms), h('span', { class: 'muted', text: perms(s.perms) }))),
        h('td', {}, h('div', { class: 'bar-cell' },
          h('span', { class: 'meter' + (s.entropy > 7.2 ? ' is-high' : '') }, h('i', { style: { width: `${(s.entropy / 8) * 100}%` } })),
          h('span', { class: 'mono', text: s.entropy.toFixed(2) })))))))) :
      h('p', { class: 'notice', text: 'This file has no section table (it was removed). The segments below still describe what gets loaded.' }));
  if (segments.length) {
    add(box, 
      h('div', { class: 'view-head is-sub' }, h('h2', { text: `Segments (${segments.length})` }),
        h('p', { text: 'How Linux maps the file into memory when it starts.' })),
      h('div', { class: 'table-wrap' }, h('table', {},
        h('thead', {}, h('tr', {}, ['Type', 'Address', 'Size in file', 'Size in memory', 'File offset', 'Access'].map((t, i) =>
          h('th', { scope: 'col', text: t, class: i >= 2 && i <= 4 ? 'num' : '' })))),
        h('tbody', {}, segments.map((s) => h('tr', {},
          h('td', { class: 'mono', text: s.type }), h('td', { class: 'mono', text: s.address }),
          h('td', { class: 'num mono', text: bytesText(s.size) }), h('td', { class: 'num mono', text: bytesText(s.vsize) }),
          h('td', { class: 'num mono', text: hex(s.offset) }),
          h('td', {}, h('span', { class: 'perm-cell' }, flagBadge(s.perms), h('span', { class: 'muted', text: perms(s.perms) })))))))));
  }
}

// --- bytes ------------------------------------------------------------------

async function renderBytes(box) {
  const PAGE = 512;
  const view = h('div', { class: 'hex' });
  const where = h('input', { type: 'text', class: 'mono-input', placeholder: 'Address (0x…) or file offset', 'aria-label': 'Address or file offset' });
  const useOffset = h('input', { type: 'checkbox' });

  async function load() {
    const params = { path: state.path, length: PAGE };
    if (state.bytes.address !== undefined && state.bytes.address !== null) params.address = state.bytes.address;
    else params.offset = state.bytes.offset || 0;
    try {
      const dump = await api('hexdump', params);
      state.bytes = { offset: dump.offset };
      where.value = useOffset.checked || !dump.rows.length || !dump.rows[0].address ? hex(dump.offset) : dump.rows[0].address;
      fill(view, ...dump.rows.map((row) => h('div', { class: 'hex-row' },
        h('span', { class: 'hex-off', text: row.offset.toString(16).padStart(8, '0') }),
        h('span', { class: 'hex-addr', text: row.address || '' }),
        h('span', { text: row.hex }),
        h('span', { class: 'hex-ascii', text: row.ascii }))));
    } catch (error) {
      fill(view, h('p', { class: 'pane-note', text: error.message }));
    }
  }
  const jump = (e) => {
    e.preventDefault();
    const text = where.value.trim();
    if (!/^(0x[0-9a-f]+|\d+)$/i.test(text)) { toast('Type a number such as 0x2000 or 8192.', true); return; }
    state.bytes = useOffset.checked ? { offset: Number(text) } : { address: text };
    load();
  };
  const step = (delta) => { state.bytes = { offset: Math.max(0, Math.min(state.info.size - 1, (state.bytes.offset || 0) + delta)) }; load(); };

  add(box, 
    h('div', { class: 'view-head' }, h('h2', { text: 'Bytes' }),
      h('p', { text: 'The raw contents of the file. Left: position in the file and in memory. Right: the same bytes as text.' })),
    h('form', { class: 'toolbar', onsubmit: jump },
      where, h('label', { class: 'check' }, useOffset, 'This is a file offset'),
      h('button', { class: 'btn btn-primary', text: 'Go' }),
      h('button', { type: 'button', class: 'btn', text: 'Previous page', onclick: () => step(-PAGE) }),
      h('button', { type: 'button', class: 'btn', text: 'Next page', onclick: () => step(PAGE) }),
      h('button', { type: 'button', class: 'btn', text: 'Open in Decode', title: 'Decode this range in the Decode workbench', onclick: () => openInDecode({ kind: 'file', offset: state.bytes.offset || 0, length: PAGE }) })),
    h('div', { class: 'pane' }, view));
  await load();
}

// --- assets -----------------------------------------------------------------

const IMAGE_TYPES = { png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', bmp: 'image/bmp', webp: 'image/webp', ico: 'image/x-icon' };
const TEXT_TYPES = ['txt', 'json', 'xml', 'cfg', 'ini', 'lua', 'js', 'py', 'rpy', 'gd', 'tscn', 'tres', 'csv', 'md', 'html', 'css', 'yml', 'yaml', 'toml', 'shader', 'glsl', 'vert', 'frag', 'import', 'manifest', 'def', 'map'];

function extension(name) {
  const dot = name.lastIndexOf('.');
  return dot < 0 ? '' : name.slice(dot + 1).toLowerCase();
}

async function previewBlob(target, blob, name) {
  const ext = extension(name);
  if (IMAGE_TYPES[ext]) {
    const url = URL.createObjectURL(new Blob([blob], { type: IMAGE_TYPES[ext] }));
    fill(target, h('img', { src: url, alt: 'Preview of ' + name, onload: () => URL.revokeObjectURL(url) }));
    return;
  }
  const head = new Uint8Array(await blob.slice(0, 16384).arrayBuffer());
  const printable = head.filter((c) => c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127) || c >= 128).length;
  if (TEXT_TYPES.includes(ext) || (head.length && printable / head.length > 0.97 && !head.includes(0))) {
    fill(target, h('pre', { text: new TextDecoder('utf-8', { fatal: false }).decode(head) + (blob.size > head.length ? '\n…' : '') }));
    return;
  }
  const lines = [];
  for (let i = 0; i < Math.min(head.length, 256); i += 16) {
    const chunk = Array.from(head.slice(i, i + 16));
    lines.push(i.toString(16).padStart(6, '0') + '  ' + chunk.map((c) => c.toString(16).padStart(2, '0')).join(' ').padEnd(48) +
      ' ' + chunk.map((c) => (c >= 32 && c < 127 ? String.fromCharCode(c) : '.')).join(''));
  }
  fill(target, h('p', { class: 'muted', text: 'No preview for this kind of file. First bytes:' }), h('pre', { text: lines.join('\n') }));
}

function renderArchive(box, path) {
  const tbody = h('tbody');
  const summary = h('p', { class: 'muted' });
  const notes = h('div');
  const preview = h('div', { class: 'preview' }, h('p', { class: 'muted', text: 'Select a file to preview it.' }));
  const actions = h('div', { class: 'actions' });
  const options = { q: '', shown: 400 };
  const more = h('button', { type: 'button', class: 'btn', text: 'Show more', hidden: true });
  let writable = false;

  async function select(entry, row) {
    for (const el of tbody.querySelectorAll('.is-selected')) el.classList.remove('is-selected');
    row.classList.add('is-selected');
    fill(actions);
    if (entry.encrypted) {
      fill(preview, h('p', { class: 'notice', text: 'This file is encrypted. vex does not decrypt protected content.' }));
      return;
    }
    fill(preview, busy('Reading…'));
    let blob;
    try {
      blob = await api('archive/file', { path, name: entry.name }, { raw: true });
    } catch (error) { fill(preview, h('p', { class: 'notice is-error', text: error.message })); return; }
    await previewBlob(preview, blob, entry.name);
    const picker = h('input', { type: 'file', hidden: true, onchange: async () => {
      const file = picker.files[0];
      if (!file) return;
      const out = await ask('Save the modified pack', 'A complete new pack is written here. The original is not changed.', suggestOutput(path, 'modded'));
      if (!out) return;
      try {
        const done = await api('archive/replace', { path, name: entry.name, out }, { method: 'POST', body: file });
        toast(`Replaced ${entry.name}. Saved ${done.out}`);
      } catch (error) { fail(error); }
    } });
    fill(actions, 
      h('button', { type: 'button', class: 'btn btn-small', text: 'Save a copy of this file', onclick: () => saveBlob(blob, entry.name.split('/').pop()) }),
      writable ? h('button', { type: 'button', class: 'btn btn-small', text: 'Replace with my file…', onclick: () => picker.click() }) : null,
      picker);
  }

  async function load() {
    try {
      const found = await api('archive/list', { path, q: options.q, limit: options.shown });
      writable = found.writable;
      summary.textContent = `${found.format} pack, ${found.count} files` + (found.writable ? '' : ' (read-only: vex cannot rebuild this kind)');
      fill(notes, ...found.notes.map((n) => h('p', { class: 'notice', text: n })));
      more.hidden = found.items.length >= found.total;
      fill(tbody, ...found.items.map((entry) => {
        const row = h('tr', { tabIndex: 0 },
          h('td', { class: 'mono wrap', text: entry.name }),
          h('td', { class: 'num mono', text: bytesText(entry.size) }),
          h('td', { text: [entry.compressed ? 'compressed' : null, entry.encrypted ? 'encrypted' : null].filter(Boolean).join(', ') }));
        row.addEventListener('click', () => select(entry, row));
        row.addEventListener('keydown', (e) => { if (e.key === 'Enter') select(entry, row); });
        return row;
      }));
    } catch (error) {
      fill(tbody);
      summary.textContent = '';
      fill(notes, h('p', { class: 'notice is-error', text: error.message }));
    }
  }
  more.addEventListener('click', () => { options.shown += 800; load(); });

  add(box, 
    h('div', { class: 'view-head' }, h('h2', { text: 'Files in this pack' }), summary),
    notes,
    h('div', { class: 'toolbar' },
      h('input', { type: 'text', placeholder: 'Filter by name', 'aria-label': 'Filter by name', oninput: debounce((e) => { options.q = e.target.value; options.shown = 400; load(); }, 200) }),
      h('button', { type: 'button', class: 'btn', text: 'Extract everything to a folder…', onclick: async () => {
        const dest = await ask('Extract everything', 'Folder to extract into. It is created if it does not exist.', path + '_extracted', 'Extract');
        if (!dest) return;
        try {
          const done = await api('archive/extract', { path, dest }, { method: 'POST' });
          toast(`Extracted ${done.count} files to ${done.dest}`);
        } catch (error) { fail(error); }
      } })),
    h('div', { class: 'split' },
      h('div', {}, h('div', { class: 'table-wrap' }, h('table', {},
        h('thead', {}, h('tr', {}, h('th', { scope: 'col', text: 'Name' }), h('th', { scope: 'col', class: 'num', text: 'Size' }), h('th', { scope: 'col', text: 'Stored' }))),
        tbody)), h('p', {}, more)),
      h('div', { class: 'pane' }, h('div', { class: 'pane-head' }, h('h3', { text: 'Preview' })), preview, actions)));
  return load();
}

async function renderResources(box) {
  let found;
  try { found = await api('resources', { path: state.path }); } catch (error) { return; }
  if (!found.items.length) return;
  const preview = h('div', { class: 'preview' }, h('p', { class: 'muted', text: 'Select a resource to preview it.' }));
  const actions = h('div', { class: 'actions' });
  const tbody = h('tbody');

  async function select(res, row) {
    for (const el of tbody.querySelectorAll('.is-selected')) el.classList.remove('is-selected');
    row.classList.add('is-selected');
    fill(preview, busy('Reading…'));
    try {
      const isIcon = res.type === 'GROUP_ICON';
      const blob = await api(isIcon ? 'resource/icon' : 'resource/data', { path: state.path, index: res.index }, { raw: true });
      const label = `${res.type}_${res.name.replace('#', '')}`;
      const name = isIcon ? label + '.ico' : res.type === 'MANIFEST' ? label + '.xml' : label + '.bin';
      await previewBlob(preview, blob, name);
      const picker = h('input', { type: 'file', hidden: true, onchange: async () => {
        const file = picker.files[0];
        if (!file) return;
        const out = await ask('Save the modified program', 'A modified copy is written here. The original is not changed.', suggestOutput(state.path, 'modded'));
        if (!out) return;
        try {
          const done = await api('resource/replace', { path: state.path, index: res.index, out }, { method: 'POST', body: file });
          toast(`Replaced ${res.type} ${res.name}. Saved ${done.out}`);
        } catch (error) { fail(error); }
      } });
      fill(actions, 
        h('button', { type: 'button', class: 'btn btn-small', text: 'Save a copy', onclick: () => saveBlob(blob, name) }),
        isIcon ? null : h('button', { type: 'button', class: 'btn btn-small', text: 'Replace with my file…', onclick: () => picker.click() }),
        picker);
    } catch (error) { fill(preview, h('p', { class: 'notice is-error', text: error.message })); }
  }

  for (const res of found.items) {
    const row = h('tr', { tabIndex: 0 },
      h('td', { text: res.type }), h('td', { class: 'mono', text: res.name }),
      h('td', { class: 'num mono', text: String(res.language) }), h('td', { class: 'num mono', text: bytesText(res.size) }));
    row.addEventListener('click', () => select(res, row));
    row.addEventListener('keydown', (e) => { if (e.key === 'Enter') select(res, row); });
    add(tbody, row);
  }
  const version = Object.entries(found.version);
  add(box, h('section', {},
    h('div', { class: 'view-head' }, h('h2', { text: `Built-in resources (${found.items.length})` }),
      h('p', { text: 'Icons, version details and data stored inside this Windows program.' })),
    version.length ? h('ul', { class: 'versions' }, version.map(([k, v]) =>
      h('li', {}, h('span', { class: 'muted', text: k + ': ' }), v))) : null,
    h('div', { class: 'split' },
      h('div', { class: 'table-wrap' }, h('table', {},
        h('thead', {}, h('tr', {}, h('th', { scope: 'col', text: 'Kind' }), h('th', { scope: 'col', text: 'Name' }), h('th', { scope: 'col', class: 'num', text: 'Language' }), h('th', { scope: 'col', class: 'num', text: 'Size' }))),
        tbody)),
      h('div', { class: 'pane' }, h('div', { class: 'pane-head' }, h('h3', { text: 'Preview' })), preview, actions))));
}

async function renderAssets(box) {
  const stack = h('div', { class: 'stack' });
  add(box, stack);
  const archiveBox = h('section');

  function openPack(path) {
    state.archivePath = path;
    fill(archiveBox);
    renderArchive(archiveBox, path);
    archiveBox.scrollIntoView({ block: 'start' });
  }

  let result = { matches: [], packs: [], root: null };
  try { result = await api('engine', { path: state.path }); } catch (error) { /* shown below as "nothing recognised" */ }
  const head = h('div', { class: 'view-head' }, h('h2', { text: 'Game engine and assets' }),
    h('p', { text: result.root ? `Looked in ${result.root}` : '' }));
  const engines = h('section', {}, head);
  if (!result.matches.length) {
    add(engines, h('p', { class: 'muted', text: state.kind === 'archive'
      ? 'Showing the pack you opened.'
      : 'No known game engine recognised here. Asset packs found nearby are listed below.' }));
  }
  for (const match of result.matches) {
    const details = Object.entries(match.details).map(([k, v]) => `${k}: ${v}`).join(', ');
    add(engines, h('div', { class: 'engine' },
      h('h3', {}, match.engine, h('span', { class: 'confidence', text: `${match.confidence} confidence${details ? ' — ' + details : ''}` })),
      h('p', { class: 'muted', text: 'Why:' }), h('ul', {}, match.evidence.map((e) => h('li', { text: e }))),
      h('p', { class: 'muted', text: 'What you can do:' }), h('ul', {}, match.advice.map((a) => h('li', { text: a })))));
  }
  add(stack, engines);

  if (result.packs.length) {
    add(stack, h('section', {},
      h('div', { class: 'view-head' }, h('h2', { text: `Asset packs here (${result.packs.length})` }),
        h('p', { text: 'Packs vex can open. Choose one to browse, extract or replace its files.' })),
      h('div', { class: 'table-wrap' }, h('table', {},
        h('thead', {}, h('tr', {}, h('th', { scope: 'col', text: 'File' }), h('th', { scope: 'col', class: 'num', text: 'Size' }))),
        h('tbody', {}, result.packs.map((pack) => h('tr', {},
          h('td', { class: 'mono wrap' }, h('button', { class: 'link', type: 'button', text: pack.relative, onclick: () => openPack(pack.path) })),
          h('td', { class: 'num mono', text: bytesText(pack.size) }))))))));
  }
  if (state.kind === 'binary' && state.info.format === 'PE') await renderResources(stack);
  add(stack, archiveBox);
  if (state.archivePath) await renderArchive(archiveBox, state.archivePath);
}

// --- split ------------------------------------------------------------------

const SPLIT_GROUPS = [
  { id: 'parts', title: 'Parts' },
  { id: 'embedded', title: 'Embedded files' },
  { id: 'resource', title: 'Resources' },
];
const SPLIT_KIND_NAMES = { embedded: 'Embedded file', resource: 'Resource' };
const SPLIT_COLUMNS = ['Piece', 'Kind', 'File offset', 'Size', 'Address', 'Saved as'];

const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
const own = (object, key) => Object.prototype.hasOwnProperty.call(object, key);

function splitRow(piece) {
  // only the kinds drawn in the file map have a swatch
  const mapped = own(KIND_NAMES, piece.kind);
  const kindName = mapped ? KIND_NAMES[piece.kind] : own(SPLIT_KIND_NAMES, piece.kind) ? SPLIT_KIND_NAMES[piece.kind] : piece.kind;
  return h('tr', { class: piece.path ? null : 'is-unsaved' },
    h('td', { class: 'mono wrap' }, piece.name || '(unnamed)',
      piece.path && piece.note ? h('span', { class: 'piece-note', text: piece.note }) : null),
    h('td', {}, h('span', { class: 'legend-item' },
      mapped ? h('span', { class: `swatch kind-${piece.kind}` }) : null, kindName)),
    h('td', { class: 'num mono' }, h('button', {
      class: 'link', type: 'button', text: hex(piece.offset), title: 'Show the bytes at this offset',
      onclick: () => { state.bytes = { offset: piece.offset }; show('bytes'); },
    })),
    h('td', { class: 'num mono', text: bytesText(piece.size), title: `${piece.size} bytes` }),
    h('td', { class: 'mono', text: piece.address || '' }),
    h('td', { class: 'mono wrap' }, piece.path || h('span', { class: 'muted', text: piece.note || 'not saved' })));
}

function splitTable(pieces) {
  const rows = [];
  for (const group of SPLIT_GROUPS) {
    const members = pieces.filter((p) => (own(SPLIT_KIND_NAMES, p.kind) ? p.kind : 'parts') === group.id);
    if (!members.length) continue;
    rows.push(h('tr', {}, h('th', { colSpan: SPLIT_COLUMNS.length, scope: 'colgroup', text: `${group.title} (${members.length})` })));
    rows.push(...members.map(splitRow));
  }
  return h('div', { class: 'table-wrap' }, h('table', { class: 'pieces' },
    h('thead', {}, h('tr', {}, SPLIT_COLUMNS.map((t, i) =>
      h('th', { scope: 'col', text: t, class: i === 2 || i === 3 ? 'num' : '' })))),
    h('tbody', {}, rows)));
}

async function renderSplit(box) {
  const path = state.path;
  const summary = h('span', { class: 'count', hidden: true });
  const result = h('div', { role: 'status', 'aria-live': 'polite' });
  const body = h('div', {}, busy('Looking for parts and embedded files…'));
  const button = h('button', { type: 'button', class: 'btn btn-primary', text: 'Split into a folder…', disabled: true });

  function showDone(done) {
    fill(result, h('p', { class: 'notice is-ok split-result' },
      h('strong', { text: `Saved ${plural(done.count, 'file')} ` }), `(${bytesText(done.bytes)}) to `,
      h('span', { class: 'mono', text: done.dest }),
      `. ${done.index || 'index.txt'} in that folder lists every piece.`));
  }

  button.addEventListener('click', async () => {
    const dest = await ask('Split into a folder', 'Folder to save the pieces into. It is created if it does not exist; an existing folder must be empty.', path + '_split', 'Split');
    if (!dest) return;
    button.disabled = true;
    fill(result, busy('Saving the pieces…'));
    try {
      const done = await api('split', { path, dest }, { method: 'POST' });
      state.split = { path, done };
      showDone(done);
    } catch (error) {
      fill(result, h('p', { class: 'notice is-error split-result', text: error.message }));
    }
    button.disabled = false;
  });

  add(box,
    h('div', { class: 'view-head' }, h('h2', { text: 'Split into files' }),
      h('p', { text: 'Saves the parts of this program as separate files in a folder. The program itself is not changed and nothing is run.' })),
    h('div', { class: 'toolbar' }, button, summary),
    result,
    body);
  if (state.split && state.split.path === path) showDone(state.split.done);

  // the preview scans the whole file, so the page is shown before it arrives
  api('split', { path }).then((preview) => {
    if (!preview.pieces.length) {
      fill(body, h('p', { class: 'muted', text: 'vex found nothing in this file that it can save separately.' }));
      return;
    }
    summary.textContent = `${plural(preview.count, 'file')}, ${bytesText(preview.bytes)} in total`;
    summary.hidden = false;
    button.disabled = !preview.count;
    fill(body, splitTable(preview.pieces),
      h('p', { class: 'muted split-foot', text: 'An index.txt listing every piece is saved next to them.' }));
  }).catch((error) => {
    fill(body, h('p', { class: 'notice is-error split-result', text: error.message }));
  });
}

// --- modify -----------------------------------------------------------------

async function renderModify(box) {
  const preset = state.modify || {};
  const out = h('input', { type: 'text', class: 'mono-input', value: suggestOutput(state.path, 'patched') });
  const inPlace = h('input', { type: 'checkbox', onchange: () => { out.disabled = inPlace.checked; } });
  const log = h('ul', { class: 'log' });
  const target = () => (inPlace.checked ? state.path : out.value.trim());

  function record(done, what) {
    const lines = (done.patches || [done]).map((p) =>
      `${p.address || 'file ' + hex(p.offset)}: ${p.old} → ${p.new}`);
    log.prepend(h('li', {}, h('strong', { text: what + ' ' }), `Saved ${done.out}`, h('br'), lines.join('; ')));
    toast(`Saved ${done.out}`);
  }
  async function run(name, params, what) {
    const dest = target();
    if (!dest) { toast('Choose where to save the modified copy.', true); return; }
    try {
      record(await api(name, Object.assign({ path: state.path, out: dest }, params), { method: 'POST' }), what);
    } catch (error) { fail(error); }
  }
  const field = (label, input) => h('label', { class: 'field' }, label, input);

  const bytesAt = h('input', { type: 'text', class: 'mono-input', placeholder: '0x401000', value: preset.bytesAddress || '' });
  const bytesHex = h('input', { type: 'text', class: 'mono-input', placeholder: '90 90 eb 05', value: preset.bytesHex || '' });
  const nopAt = h('input', { type: 'text', class: 'mono-input', placeholder: '0x401000', value: preset.nopAddress || '' });
  const nopLen = h('input', { type: 'number', min: 1, value: preset.nopLength || 1 });
  const oldText = h('input', { type: 'text' });
  const newText = h('input', { type: 'text' });
  const textKind = h('select', {}, h('option', { value: 'ascii', text: 'Plain (ASCII)' }), h('option', { value: 'utf16', text: 'Wide (UTF-16)' }));

  add(box, 
    h('div', { class: 'view-head' }, h('h2', { text: 'Modify' }),
      h('p', { text: 'Changes are written to a copy. The file is never run, and its size never changes.' })),
    state.info.security.signed ? h('p', { class: 'notice', text: 'This program is digitally signed. Any change breaks the signature, and Windows will report it as modified.' }) : null,
    h('div', { class: 'stack' },
      h('div', { class: 'card' },
        h('h3', { text: 'Where to save' }),
        h('div', { class: 'form-grid' }, h('div', { class: 'wide' }, field('Save the modified copy as', out))),
        h('label', { class: 'check' }, inPlace, 'Change the original instead (an untouched copy is kept as .bak)')),
      h('form', { class: 'card', onsubmit: (e) => { e.preventDefault(); run('patch/nop', { address: nopAt.value.trim(), length: nopLen.value }, 'Disabled instructions.'); } },
        h('h3', { text: 'Disable instructions' }),
        h('p', { class: 'muted', text: 'Overwrites code with “do nothing” instructions. Pick an instruction in Code and choose “Disable this instruction” to fill this in.' }),
        h('div', { class: 'form-grid' }, field('Address', nopAt), field('Number of bytes', nopLen),
          h('button', { class: 'btn btn-primary', text: 'Disable and save' }))),
      h('form', { class: 'card', onsubmit: (e) => { e.preventDefault(); run('patch/bytes', { address: bytesAt.value.trim(), hex: bytesHex.value }, 'Replaced bytes.'); } },
        h('h3', { text: 'Replace bytes' }),
        h('p', { class: 'muted', text: 'Writes exact byte values at an address. The new bytes overwrite what is there; nothing is inserted.' }),
        h('div', { class: 'form-grid' }, field('Address', bytesAt), field('New bytes (hex)', bytesHex),
          h('button', { class: 'btn btn-primary', text: 'Replace and save' }))),
      h('form', { class: 'card', onsubmit: (e) => { e.preventDefault(); run('patch/string', { old: oldText.value, new: newText.value, encoding: textKind.value }, 'Replaced text.'); } },
        h('h3', { text: 'Replace text' }),
        h('p', { class: 'muted', text: 'Swaps a piece of text everywhere it appears. The new text cannot be longer than the old one.' }),
        h('div', { class: 'form-grid' }, field('Find', oldText), field('Replace with', newText), field('Kind of text', textKind),
          h('button', { class: 'btn btn-primary', text: 'Replace and save' }))),
      h('div', { class: 'card' }, h('h3', { text: 'Changes made this session' }), log)));
  if (!log.children.length) add(log, h('li', { class: 'muted', text: 'Nothing yet.' }));
  state.modify = {};
}

// --- decode -----------------------------------------------------------------

// The source kinds the Input panel offers. The operation catalogue itself is
// never hard-coded here: it is fetched from GET /api/decode/ops at runtime, so
// the C edition can serve this same page and grey out what it does not build.
const DECODE_SOURCE_KINDS = [
  { id: 'text', label: 'Text', hint: 'Type or paste text; sent as UTF-8.' },
  { id: 'hex', label: 'Hex', hint: 'Hex digits. Spaces, newlines, 0x, commas and colons are ignored.' },
  { id: 'base64', label: 'Base64', hint: 'Standard alphabet; padding optional.' },
  { id: 'file', label: 'From this file', hint: 'A byte range of the open program. Nothing is written.' },
];
// Which operation a solver's recovered params belong to, when the names differ.
const DECODE_SOLVER_OP = { caesar: 'rot-n', 'xor-single': 'xor', 'xor-keylen': 'xor', substitution: 'substitution' };

function decodeDefaultSource() {
  return { kind: 'text', value: '', offset: 0, length: (state.info && state.info.size) || 0 };
}

// A step parameter's starting value: its catalogue default, else the first
// choice for a select, else blank. Keeps a required choice from storing "".
function decodeInitParam(p) {
  if (p.default !== undefined && p.default !== null) return String(p.default);
  if (p.choices && p.choices.length) return String(p.choices[0]);
  return '';
}

// Open the workbench pre-filled from another view (Strings text, a Bytes range).
function openInDecode(source) {
  state.decode = { source: Object.assign(decodeDefaultSource(), source), recipe: [], hexdump: false };
  show('decode');
}

function decodeInputSize(src) {
  if (src.kind === 'file') return Math.max(0, Number(src.length) || 0);
  const v = src.value || '';
  if (src.kind === 'hex') return Math.floor(v.replace(/[^0-9a-fA-F]/g, '').length / 2);
  if (src.kind === 'base64') return Math.floor(v.replace(/[^A-Za-z0-9+/_-]/g, '').length * 3 / 4);
  return new TextEncoder().encode(v).length;
}

function decodeSourceBody(src) {
  if (src.kind === 'file') {
    return { kind: 'file', path: state.path, offset: Number(src.offset) || 0, length: Number(src.length) || 0 };
  }
  return { kind: src.kind, value: src.value || '' };
}

function decodeParseOffset(text) {
  text = (text || '').trim();
  if (/^0x[0-9a-fA-F]+$/.test(text)) return parseInt(text, 16);
  if (/^\d+$/.test(text)) return Number(text);
  return 0;
}

function decodeHexdump(hexStr, capBytes) {
  const bytes = [];
  for (let i = 0; i + 1 < hexStr.length && bytes.length < capBytes; i += 2) bytes.push(parseInt(hexStr.slice(i, i + 2), 16));
  const lines = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    lines.push(i.toString(16).padStart(8, '0') + '  ' +
      chunk.map((c) => c.toString(16).padStart(2, '0')).join(' ').padEnd(47) + '  ' +
      chunk.map((c) => (c >= 32 && c < 127 ? String.fromCharCode(c) : '.')).join(''));
  }
  return lines.join('\n');
}

async function renderDecode(box) {
  if (!state.decode) state.decode = { source: decodeDefaultSource(), recipe: [], hexdump: false };
  const D = state.decode;
  if (D.source.kind === 'file' && !D.source.length) D.source.length = (state.info && state.info.size) || 0;

  // The catalogue, fetched at runtime, and a name -> op index built from it.
  let catalogue = { groups: [], solvers: [] };
  const opIndex = {};

  const segGroup = h('div', { class: 'seg-group' });
  const sourceHint = h('p', { class: 'pane-note decode-hint' });
  const sourceFields = h('div', { class: 'decode-source-fields' });
  const sizeReadout = h('span', { class: 'count' });

  const paletteBox = h('div', { class: 'palette' }, busy('Loading operations…'));
  const recipeList = h('div', { class: 'recipe-list' });
  const recipeClear = h('button', { type: 'button', class: 'btn btn-small', text: 'Clear', disabled: true,
    onclick: () => { D.recipe = []; renderRecipe(); runDecode(); } });

  const outMeta = h('div', { class: 'decode-out-meta' });
  const outError = h('div');
  const outBody = h('div', { class: 'decode-out-body' });
  const outSteps = h('div', { class: 'decode-steps' });
  const hexToggle = h('input', { type: 'checkbox', checked: D.hexdump,
    onchange: (e) => { D.hexdump = e.target.checked; showResult(); } });
  const solveBox = h('div', { class: 'solve' });

  let stepNodes = [];
  let lastResult = null;
  const schedule = debounce(runDecode, 260);

  function opParams(name) { const op = opIndex[name]; return (op && op.params) || []; }

  function paramsOut(step) {
    const types = {};
    for (const p of opParams(step.op)) types[p.name] = p.type;
    const out = {};
    for (const [k, v] of Object.entries(step.params || {})) {
      if (v === '' || v === null || v === undefined) continue;
      out[k] = (types[k] === 'number' || types[k] === 'int') ? Number(v) : v;
    }
    return out;
  }

  function recipeBody() { return D.recipe.map((s) => ({ op: s.op, params: paramsOut(s) })); }

  async function runDecode() {
    const serial = ++runDecode.serial;
    let res;
    try {
      res = await api('decode', {}, { method: 'POST', body: JSON.stringify({ source: decodeSourceBody(D.source), recipe: recipeBody() }) });
    } catch (error) {
      if (serial !== runDecode.serial) return;
      lastResult = null;
      fill(outMeta);
      fill(outBody);
      fill(outSteps);
      fill(outError, h('p', { class: 'notice is-error', text: error.message }));
      return;
    }
    if (serial !== runDecode.serial) return;
    lastResult = res;
    showResult();
  }
  runDecode.serial = 0;

  function showResult() {
    for (const n of stepNodes) n.classList.remove('is-failed');
    fill(outError);
    const r = lastResult;
    if (!r) {
      fill(outMeta);
      fill(outBody, h('p', { class: 'pane-note', text: 'Choose a source and add operations to see the result here.' }));
      fill(outSteps);
      return;
    }
    const failedAt = r.ok ? -1 : (r.steps || []).length;
    fill(outMeta,
      h('span', { class: 'count', text: `${r.size} ${r.size === 1 ? 'byte' : 'bytes'} out` }),
      r.looks_like ? h('span', { class: 'count', text: 'looks like ' + r.looks_like }) : null,
      h('label', { class: 'check' }, hexToggle, 'Hex dump'));

    if (D.hexdump) {
      const hexStr = r.hex || '';
      const cap = 8192;
      fill(outBody, h('pre', { class: 'decode-pre mono', text: decodeHexdump(hexStr, cap) || '(no bytes)' }),
        hexStr.length / 2 > cap ? h('p', { class: 'pane-note', text: `Showing the first ${cap} of ${r.size} bytes.` }) : null);
    } else {
      const text = r.text || '';
      const cap = 200000;
      fill(outBody, h('pre', { class: 'decode-pre', text: text.slice(0, cap) || '(empty)' }),
        text.length > cap ? h('p', { class: 'pane-note', text: `Showing the first ${cap} characters.` }) : null);
    }

    fill(outSteps);
    if (D.recipe.length) {
      add(outSteps, h('ol', { class: 'decode-steplist' }, D.recipe.map((s, i) => {
        const done = r.steps && r.steps[i];
        const failed = i === failedAt;
        const note = failed ? 'failed' : done ? bytesText(done.size) : '—';
        return h('li', { class: failed ? 'is-failed' : null },
          h('span', { class: 'decode-step-i', text: String(i + 1) }),
          h('span', { class: 'decode-step-op', text: s.op }),
          h('span', { class: 'decode-step-sz mono', text: note }));
      })));
    }

    if (!r.ok) {
      if (stepNodes[failedAt]) stepNodes[failedAt].classList.add('is-failed');
      const name = D.recipe[failedAt] ? D.recipe[failedAt].op : null;
      fill(outError, h('p', { class: 'notice is-error' },
        name ? h('strong', { text: `Step ${failedAt + 1} (${name}) failed. ` }) : h('strong', { text: 'This recipe failed. ' }),
        r.error || 'Check the source and the operation parameters.'));
    }
  }

  function paramField(step, p) {
    const key = p.name;
    if (step.params[key] === undefined) step.params[key] = decodeInitParam(p);
    const choices = p.choices || ((p.type === 'choice' || p.type === 'select') ? [] : null);
    let input;
    if (choices) {
      input = h('select', { onchange: (e) => { step.params[key] = e.target.value; schedule(); } },
        choices.map((c) => h('option', { value: String(c), text: String(c), selected: String(step.params[key]) === String(c) })));
    } else if (p.type === 'number' || p.type === 'int') {
      input = h('input', { type: 'number', value: step.params[key], oninput: (e) => { step.params[key] = e.target.value; schedule(); } });
    } else {
      input = h('input', { type: 'text', class: 'mono-input', value: step.params[key], placeholder: p.type || 'text', spellcheck: false,
        oninput: (e) => { step.params[key] = e.target.value; schedule(); } });
    }
    return h('label', { class: 'field decode-param' },
      h('span', {}, p.name, p.required ? h('span', { class: 'req', text: ' *' }) : null), input);
  }

  function renderRecipe() {
    stepNodes = [];
    recipeClear.disabled = !D.recipe.length;
    fill(recipeList);
    if (!D.recipe.length) {
      add(recipeList, h('p', { class: 'pane-note', text: 'No operations yet. Pick one from the list above to start a recipe.' }));
      return;
    }
    D.recipe.forEach((step, i) => {
      const op = opIndex[step.op];
      const params = (op && op.params) || [];
      const node = h('div', { class: 'recipe-step' },
        h('div', { class: 'recipe-step-head' },
          h('span', { class: 'recipe-step-n', text: String(i + 1) }),
          h('span', { class: 'recipe-step-name', text: step.op }),
          h('div', { class: 'recipe-step-ctl' },
            h('button', { type: 'button', class: 'btn btn-small', text: 'Up', 'aria-label': `Move ${step.op} up`, disabled: i === 0, onclick: () => moveStep(i, -1) }),
            h('button', { type: 'button', class: 'btn btn-small', text: 'Down', 'aria-label': `Move ${step.op} down`, disabled: i === D.recipe.length - 1, onclick: () => moveStep(i, 1) }),
            h('button', { type: 'button', class: 'btn btn-small', text: 'Remove', 'aria-label': `Remove ${step.op}`, onclick: () => removeStep(i) }))),
        op && op.summary ? h('p', { class: 'recipe-step-sum', text: op.summary }) : null,
        params.length ? h('div', { class: 'recipe-params form-grid' }, params.map((p) => paramField(step, p))) : null);
      stepNodes.push(node);
      add(recipeList, node);
    });
  }

  function addStep(op) {
    const params = {};
    for (const p of op.params || []) params[p.name] = decodeInitParam(p);
    D.recipe.push({ op: op.name, params });
    renderRecipe();
    runDecode();
  }
  function moveStep(i, dir) {
    const j = i + dir;
    if (j < 0 || j >= D.recipe.length) return;
    const t = D.recipe[i]; D.recipe[i] = D.recipe[j]; D.recipe[j] = t;
    renderRecipe();
    runDecode();
  }
  function removeStep(i) { D.recipe.splice(i, 1); renderRecipe(); runDecode(); }

  function renderPalette() {
    fill(paletteBox);
    if (!(catalogue.groups || []).length) {
      add(paletteBox, h('p', { class: 'pane-note', text: 'No operations available.' }));
      return;
    }
    for (const group of catalogue.groups) {
      add(paletteBox, h('div', { class: 'palette-group' },
        h('h4', { class: 'palette-group-title', text: group.name }),
        h('div', { class: 'palette-chips' }, (group.ops || []).map((op) => {
          const unavailable = op.available === false;
          return h('button', {
            type: 'button', class: 'op-chip' + (unavailable ? ' is-unavailable' : ''),
            disabled: unavailable, 'aria-disabled': unavailable ? 'true' : null,
            title: (op.summary || op.name) + (unavailable ? ' — not available in this build' : ''),
            onclick: unavailable ? null : () => addStep(op),
          }, h('span', { class: 'op-chip-name', text: op.name }), unavailable ? h('span', { class: 'op-chip-na', text: 'n/a' }) : null);
        }))));
    }
  }

  function loadCandidate(solver, candidate) {
    const opName = DECODE_SOLVER_OP[solver] || solver;
    const op = opIndex[opName];
    const params = {};
    if (op) for (const p of op.params || []) params[p.name] = decodeInitParam(p);
    for (const [k, v] of Object.entries(candidate.params || {})) params[k] = String(v);
    D.recipe.push({ op: opName, params });
    renderRecipe();
    runDecode();
    toast(`Loaded ${opName} from the ${solver} solver into the recipe.`);
  }

  function showCandidates(target, solver, candidates) {
    if (!candidates.length) { fill(target, h('p', { class: 'pane-note', text: 'No candidates found.' })); return; }
    fill(target, h('ol', { class: 'candidate-list' }, candidates.map((c) => {
      const pct = Math.round((Number(c.score) || 0) * 100);
      const paramStr = Object.entries(c.params || {}).map(([k, v]) => `${k}=${v}`).join(', ');
      return h('li', { class: 'candidate' },
        h('div', { class: 'candidate-head' },
          h('span', { class: 'candidate-score', text: pct + '%' }),
          h('span', { class: 'candidate-params mono', text: paramStr || '(no params)' }),
          h('button', { type: 'button', class: 'btn btn-small', text: 'Load into recipe', onclick: () => loadCandidate(solver, c) })),
        h('pre', { class: 'candidate-text', text: (c.text || '').slice(0, 160) }));
    })));
  }

  function renderSolve() {
    fill(solveBox);
    const solvers = catalogue.solvers || [];
    if (!solvers.length) { add(solveBox, h('p', { class: 'pane-note', text: 'No auto-solvers in this build.' })); return; }
    const select = h('select', {}, solvers.map((s) => h('option', { value: s.name, text: s.name, title: s.summary || '' })));
    const results = h('div', { class: 'candidates' });
    const run = h('button', { type: 'button', class: 'btn btn-small btn-primary', text: 'Find candidates', onclick: async () => {
      run.disabled = true;
      fill(results, busy('Searching the supplied data…'));
      try {
        const res = await api('decode/solve', {}, { method: 'POST', body: JSON.stringify({ source: decodeSourceBody(D.source), name: select.value }) });
        if (!res.ok) fill(results, h('p', { class: 'notice is-error', text: res.error || 'The solver failed.' }));
        else showCandidates(results, select.value, res.candidates || []);
      } catch (error) { fill(results, h('p', { class: 'notice is-error', text: error.message })); }
      run.disabled = false;
    } });
    add(solveBox,
      h('p', { class: 'pane-note', text: 'Searches keys for the current source and ranks the readable results. vex only searches data you supply; it never targets a protection.' }),
      h('div', { class: 'toolbar decode-solve-bar' }, h('label', { class: 'field decode-param' }, h('span', { text: 'Solver' }), select), run),
      results);
  }

  function updateSize() {
    const n = decodeInputSize(D.source);
    sizeReadout.textContent = `${n} ${n === 1 ? 'byte' : 'bytes'} in`;
  }

  function renderSource() {
    fill(segGroup, ...DECODE_SOURCE_KINDS.map((k) => h('button', {
      type: 'button', class: 'seg-btn', 'aria-pressed': D.source.kind === k.id ? 'true' : 'false',
      onclick: () => { if (D.source.kind === k.id) return; D.source.kind = k.id; renderSource(); runDecode(); },
    }, k.label)));
    const def = DECODE_SOURCE_KINDS.find((k) => k.id === D.source.kind) || DECODE_SOURCE_KINDS[0];
    sourceHint.textContent = def.hint;
    fill(sourceFields);
    if (D.source.kind === 'file') {
      const offset = h('input', { type: 'text', class: 'mono-input', value: hex(Number(D.source.offset) || 0),
        oninput: (e) => { D.source.offset = decodeParseOffset(e.target.value); updateSize(); schedule(); } });
      const length = h('input', { type: 'number', min: 0, value: Number(D.source.length) || 0,
        oninput: (e) => { D.source.length = Math.max(0, Number(e.target.value) || 0); updateSize(); schedule(); } });
      add(sourceFields, h('div', { class: 'form-grid' },
        h('label', { class: 'field decode-param' }, h('span', { text: 'File' }), h('input', { type: 'text', class: 'mono-input', value: (state.info && state.info.name) || state.path || '', disabled: true })),
        h('label', { class: 'field decode-param' }, h('span', { text: 'Offset' }), offset),
        h('label', { class: 'field decode-param' }, h('span', { text: 'Length (bytes)' }), length)));
    } else {
      add(sourceFields, h('textarea', {
        class: 'decode-input' + (D.source.kind === 'text' ? '' : ' mono-input'), rows: 5, spellcheck: false,
        placeholder: def.hint, value: D.source.value || '',
        oninput: (e) => { D.source.value = e.target.value; updateSize(); schedule(); },
      }));
    }
    updateSize();
  }

  add(box,
    h('div', { class: 'view-head' },
      h('h2', { text: 'Decode' }),
      h('p', { text: 'A workbench for turning data you already have into something readable — decode and decompress it, or decrypt it with a key you supply, one step at a time. The program is never changed and nothing is run.' })),
    h('section', { class: 'card decode-input-card' },
      h('div', { class: 'decode-card-head' }, h('h3', { text: 'Input' }), sizeReadout),
      h('div', { class: 'seg' }, segGroup),
      sourceHint,
      sourceFields),
    h('div', { class: 'decode-grid' },
      h('div', { class: 'stack' },
        h('section', { class: 'card decode-ops-card' },
          h('div', { class: 'decode-card-head' }, h('h3', { text: 'Operations' })),
          paletteBox),
        h('section', { class: 'card decode-recipe-card' },
          h('div', { class: 'decode-card-head' }, h('h3', { text: 'Recipe' }), recipeClear),
          recipeList)),
      h('div', { class: 'stack' },
        h('section', { class: 'card decode-output-card' },
          h('div', { class: 'decode-card-head' }, h('h3', { text: 'Output' }), outMeta),
          outError, outBody, outSteps),
        h('section', { class: 'card decode-solve-card' },
          h('div', { class: 'decode-card-head' }, h('h3', { text: 'Auto-solve' })),
          solveBox))));

  renderSource();
  renderRecipe();
  showResult();

  // Build the palette and solvers from the catalogue — never from a hard-coded
  // list — so the C edition's catalogue (with available:false on what it lacks)
  // renders and greys out correctly here.
  api('decode/ops', {}).then((cat) => {
    catalogue = cat || { groups: [], solvers: [] };
    for (const group of catalogue.groups || []) for (const op of group.ops || []) opIndex[op.name] = op;
    renderPalette();
    renderSolve();
    renderRecipe();
    runDecode();
  }).catch((error) => {
    fill(paletteBox, h('p', { class: 'notice is-error', text: error.message }));
    fill(solveBox, h('p', { class: 'pane-note', text: 'Auto-solvers are unavailable.' }));
    runDecode();
  });
}

// --- start ------------------------------------------------------------------

// Settings are remembered per browser; storage can be missing or refuse
// (private windows, blocked site data), and the page works the same without it.
function remember(key, value) {
  try { localStorage.setItem(key, value); } catch (e) { /* private mode */ }
}
function recall(key) {
  try { return localStorage.getItem(key); } catch (e) { return null; }
}

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  $('theme-dark').setAttribute('aria-pressed', String(theme === 'dark'));
  $('theme-light').setAttribute('aria-pressed', String(theme === 'light'));
  remember('vex-theme', theme);
}

const reducedMotion = window.matchMedia ? matchMedia('(prefers-reduced-motion: reduce)') : null;

function applyMotion(on) {
  document.documentElement.dataset.motion = on ? 'on' : 'off';
  const toggle = $('motion-toggle');
  const reduced = Boolean(reducedMotion && reducedMotion.matches);
  toggle.checked = on && !reduced;
  toggle.disabled = reduced;
  $('motion-note').hidden = !reduced;
}

function closeSidebar() {
  const sidebar = document.querySelector('.sidebar');
  if (!sidebar.classList.contains('is-open')) return;
  sidebar.classList.remove('is-open');
  $('sidebar-toggle').setAttribute('aria-expanded', 'false');
}

function start() {
  const params = new URLSearchParams(location.hash.slice(1));
  let stored = null;
  try { stored = sessionStorage.getItem('vex-token'); } catch (e) { /* ignore */ }
  state.token = params.get('token') || stored || '';
  try { sessionStorage.setItem('vex-token', state.token); } catch (e) { /* ignore */ }
  if (location.hash) history.replaceState(null, '', location.pathname);

  applyTheme(recall('vex-theme') === 'light' ? 'light' : 'dark');
  applyMotion(recall('vex-motion') !== 'off');
  if (reducedMotion && reducedMotion.addEventListener) {
    reducedMotion.addEventListener('change', () => applyMotion(recall('vex-motion') !== 'off'));
  }
  $('theme-dark').addEventListener('click', () => applyTheme('dark'));
  $('theme-light').addEventListener('click', () => applyTheme('light'));
  $('motion-toggle').addEventListener('change', (e) => {
    remember('vex-motion', e.target.checked ? 'on' : 'off');
    applyMotion(e.target.checked);
  });
  $('settings-button').addEventListener('click', () => toggleMenu($('settings-button'), $('settings-menu')));

  $('about-version').textContent = `Version ${VEX_VERSION}`;
  $('help-button').addEventListener('click', () => { closeMenu(); $('about-dialog').showModal(); });
  $('about-dialog').querySelector('button').addEventListener('click', (e) => { e.preventDefault(); $('about-dialog').close(); });

  $('sidebar-toggle').addEventListener('click', () => {
    const sidebar = document.querySelector('.sidebar');
    const open = !sidebar.classList.contains('is-open');
    sidebar.classList.toggle('is-open', open);
    $('sidebar-toggle').setAttribute('aria-expanded', String(open));
  });

  $('tab-add').addEventListener('click', openDialog);
  $('open-dialog').querySelector('.dialog-head button').addEventListener('click', (e) => { e.preventDefault(); $('open-dialog').close(); });
  $('path-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const path = $('path-input').value.trim();
    if (!path) return;
    $('open-dialog').close();
    openPath(path);
  });
  $('goto').addEventListener('submit', (e) => {
    e.preventDefault();
    const text = $('goto-input').value.trim();
    if (text) goTo(text);
  });
  window.addEventListener('dragover', (e) => { e.preventDefault(); const d = document.querySelector('.drop'); if (d) d.classList.add('is-over'); });
  window.addEventListener('dragleave', () => { const d = document.querySelector('.drop'); if (d) d.classList.remove('is-over'); });
  window.addEventListener('drop', (e) => {
    e.preventDefault();
    const d = document.querySelector('.drop');
    if (d) d.classList.remove('is-over');
    const file = e.dataTransfer && e.dataTransfer.files[0];
    if (file) uploadFile(file);
  });

  renderChrome();
  if (!state.token) {
    fill($('main'), welcomeCard('This page needs its session link',
      'Start vex from a terminal with “vex gui” and open the link it prints. The link carries a one-time key so that no other web page can use this tool.'));
    $('tab-add').disabled = true;
    for (const b of $('nav').querySelectorAll('button')) b.disabled = true;
    return;
  }
  renderWelcome();
  const open = params.get('open');
  if (open) openPath(open);
}

start();
