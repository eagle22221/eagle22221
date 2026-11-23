'use strict';
/* binspect web interface. Everything shown comes from untrusted files, so
   text is only ever inserted with textContent, never as HTML. */

const $ = (id) => document.getElementById(id);

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

// append()/replaceChildren() would print a literal "null" for skipped children
const present = (children) => children.flat().filter((c) => c !== null && c !== undefined && c !== false);
function add(parent, ...children) { parent.append(...present(children)); }
function fill(parent, ...children) { parent.replaceChildren(...present(children)); }

const state = {
  token: '', path: null, kind: null, info: null, view: 'overview',
  code: { at: null, history: [], filter: '' },
  bytes: { offset: 0 },
  archivePath: null,
  modify: {},
};

// --- server calls -----------------------------------------------------------

async function api(name, params, options) {
  const opts = options || {};
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params || {})) {
    if (v !== undefined && v !== null && v !== '') qs.set(k, v);
  }
  const res = await fetch(`/api/${name}?${qs}`, {
    method: opts.method || 'GET',
    headers: { 'X-Binspect-Token': state.token },
    body: opts.body,
  });
  if (!res.ok) {
    let message = res.statusText;
    try { message = (await res.json()).error || message; } catch (e) { /* not JSON */ }
    throw new Error(message);
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

// --- views registry ---------------------------------------------------------

const VIEWS = {
  overview: { label: 'Overview', render: renderOverview, kinds: ['binary'] },
  code: { label: 'Code', render: renderCode, kinds: ['binary'] },
  strings: { label: 'Strings', render: renderStrings, kinds: ['binary'] },
  imports: { label: 'Imports', render: renderImports, kinds: ['binary'] },
  sections: { label: 'Sections', render: renderSections, kinds: ['binary'] },
  bytes: { label: 'Bytes', render: renderBytes, kinds: ['binary'] },
  assets: { label: 'Assets', render: renderAssets, kinds: ['binary', 'archive', 'folder'] },
  modify: { label: 'Modify', render: renderModify, kinds: ['binary'] },
};

function renderNav() {
  const nav = $('nav');
  fill(nav);
  for (const [id, view] of Object.entries(VIEWS)) {
    if (!view.kinds.includes(state.kind)) continue;
    add(nav, h('button', {
      type: 'button', text: view.label,
      'aria-current': state.view === id ? 'page' : null,
      onclick: () => show(id),
    }));
  }
  nav.hidden = !state.path;
}

let renderSerial = 0;
async function show(view) {
  state.view = view;
  renderNav();
  const main = $('main');
  const serial = ++renderSerial;
  fill(main, busy('Loading…'));
  const box = h('div');
  try {
    await VIEWS[view].render(box);
  } catch (error) {
    fill(box, h('p', { class: 'notice is-error', text: error.message }));
  }
  if (serial === renderSerial) fill(main, box);
}

// --- opening things ---------------------------------------------------------

async function openPath(path) {
  let opened;
  try {
    opened = await api('open', { path });
  } catch (error) { fail(error); return; }
  if (opened.kind === 'unknown') {
    try {
      await api('archive/list', { path: opened.path, limit: 1 });
      opened.kind = 'archive';
    } catch (error) {
      toast(`${opened.name} is not a Linux/Windows program or an asset pack binspect can read.`, true);
      return;
    }
  }
  state.path = opened.path;
  state.kind = opened.kind;
  state.info = null;
  state.code = { at: null, history: [], filter: '' };
  state.bytes = { offset: 0 };
  state.archivePath = opened.kind === 'archive' ? opened.path : null;
  state.modify = {};
  const name = opened.path.split(/[\\/]/).filter(Boolean).pop() || opened.path;
  $('file-name').textContent = name;
  $('file-path').textContent = opened.path;
  $('bar-file').hidden = false;
  document.title = `${name} · binspect`;
  $('goto').hidden = opened.kind !== 'binary';
  $('map').hidden = true;
  if (opened.kind === 'binary') {
    try {
      state.info = await api('info', { path: state.path });
      renderMap(await api('layout', { path: state.path }));
    } catch (error) { fail(error); return; }
    show('overview');
  } else {
    show('assets');
  }
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

function renderWelcome() {
  const drop = h('div', { class: 'drop' },
    h('strong', { text: 'Drop a program, game file or asset pack here' }),
    h('span', { class: 'muted', text: 'Linux (ELF) and Windows (EXE, DLL) programs; ZIP, PAK, WAD, PCK, ASAR and RPA packs.' }),
    h('button', { type: 'button', class: 'btn btn-primary', text: 'Open file or folder', onclick: openDialog }));
  fill($('main'), h('div', { class: 'welcome' },
    h('h1', { text: 'Take a program apart and see how it works' }),
    h('p', { text: 'binspect reads a compiled program without running it and shows what is inside: its layout, the code, the text it contains and the functions it borrows from the system. It can also open game asset packs and save modified copies.' }),
    drop,
    h('ol', { class: 'steps' },
      h('li', {}, h('span', {}, h('b', { text: 'Open something. ' }), 'Pick a program, or a game folder to find its engine and asset packs.')),
      h('li', {}, h('span', {}, h('b', { text: 'Read the overview. ' }), 'What kind of file it is, how it is protected and which libraries it needs.')),
      h('li', {}, h('span', {}, h('b', { text: 'Follow a thread. ' }), 'Find an interesting string, see which code uses it, then read that function.')))));
}

function openDialog() {
  const dialog = $('open-dialog');
  if (!dialog.open) dialog.showModal();
  const start = state.path ? state.path.replace(/[\\/][^\\/]*$/, '') : '';
  browse(state.kind === 'folder' ? state.path : start);
}

// --- file map ---------------------------------------------------------------

const KIND_NAMES = {
  headers: 'Headers', code: 'Code', data: 'Data', meta: 'Tables and debug info',
  overlay: 'Appended data', padding: 'Padding',
};

function renderMap(layout) {
  const strip = $('map-strip');
  const readout = h('span', { class: 'map-readout' });
  fill(strip);
  const kinds = new Set();
  for (const region of layout.regions) {
    kinds.add(region.kind);
    const describe = `${region.name}: offset ${hex(region.offset)}, ${bytesText(region.size)}`;
    const button = h('button', {
      type: 'button', class: `region kind-${region.kind}`, title: describe,
      'aria-label': describe, style: { flexGrow: String(Math.max(region.size, 1)), flexBasis: '0' },
      onmouseenter: () => { readout.textContent = describe; },
      onfocus: () => { readout.textContent = describe; },
      onclick: () => { state.bytes.offset = region.offset; show('bytes'); },
    });
    if (region.kind !== 'padding' && region.size / layout.size > 0.06) add(button, h('span', { class: 'region-label', text: region.name }));
    add(strip, button);
  }
  const scale = $('map-scale');
  fill(scale);
  for (const fraction of [0, 0.25, 0.5, 0.75, 1]) {
    add(scale, h('span', {
      class: 'tick' + (fraction === 1 ? ' tick-end' : ''),
      text: hex(Math.round(layout.size * fraction)),
      style: { left: `${fraction * 100}%` },
    }));
  }
  const legend = $('map-legend');
  fill(legend);
  for (const kind of Object.keys(KIND_NAMES)) {
    if (!kinds.has(kind)) continue;
    add(legend, h('span', { class: 'legend-item' },
      h('span', { class: `swatch kind-${kind}` }), KIND_NAMES[kind]));
  }
  add(legend, readout);
  $('map').hidden = false;
}

// --- overview ---------------------------------------------------------------

function cell(label, value, extraClass) {
  return h('div', { class: 'cell ' + (extraClass || '') },
    h('div', { class: 'cell-label', text: label }),
    h('div', { class: 'cell-value' + ((extraClass || '').includes('is-mono') ? ' mono' : ''), text: value }));
}

async function renderOverview(box) {
  const info = state.info;
  const md = info.metadata;
  const block = h('div', { class: 'titleblock' },
    cell('File', info.name, 'w3 cell-name'),
    cell('Type', `${info.format === 'ELF' ? 'Linux' : 'Windows'} ${info.kind}, ${info.bits}-bit ${info.arch}`, 'w3'),
    cell('Entry point', info.entry || 'none', 'is-mono'),
    cell('Image base', info.image_base, 'is-mono'),
    cell('Size', bytesText(info.size)),
    cell('Entropy', `${info.entropy.toFixed(2)} of 8` + (info.entropy > 7.2 ? ' (packed?)' : '')),
    cell(md.timestamp ? 'Built' : 'Build ID', md.timestamp || md.build_id || 'not recorded', 'w2 is-mono'),
    cell('SHA-256', info.hashes.sha256, 'w6 is-mono'),
    cell('MD5', info.hashes.md5, 'w3 is-mono'),
    cell('SHA-1', info.hashes.sha1, 'w3 is-mono'));

  const checks = h('ul', { class: 'checks' }, info.security_details.map((row) =>
    h('li', {}, h('span', { text: row.label }),
      h('span', { class: `state state-${row.state}`, text: row.value }))));

  const libs = info.libraries.length
    ? h('ul', { class: 'plain-list' }, info.libraries.map((lib) => h('li', { class: 'mono', text: lib })))
    : h('p', { class: 'muted', text: 'None. This program is self-contained.' });

  const details = [];
  const names = {
    interpreter: 'Loader', compiler: 'Compiler', source_files: 'Source files', soname: 'Library name',
    subsystem: 'Subsystem', linker_version: 'Linker version', dll_name: 'Internal name',
    pdb_path: 'Debug file path', imphash: 'Import hash', rpath: 'RPATH', runpath: 'RUNPATH',
  };
  for (const [key, label] of Object.entries(names)) {
    if (md[key] === undefined) continue;
    const value = Array.isArray(md[key]) ? md[key].join(', ') : String(md[key]);
    details.push(h('li', {}, h('span', { class: 'muted', text: label + ': ' }), h('span', { class: 'mono', text: value })));
  }
  if (md.overlay) {
    details.push(h('li', {}, h('span', { class: 'muted', text: 'Appended data: ' }),
      `${bytesText(md.overlay.size)} after the program, at offset ${hex(md.overlay.offset)}`));
  }

  const notable = h('div', {}, busy('Looking for links, addresses and paths…'));
  api('strings', { path: state.path, tagged: 1, limit: 12 }).then((found) => {
    if (!found.items.length) {
      fill(notable, h('p', { class: 'muted', text: 'No links, network addresses or file paths found.' }));
      return;
    }
    fill(notable, h('ul', { class: 'plain-list' }, found.items.map((s) =>
      h('li', {}, s.tags.map((t) => h('span', { class: `tag tag-${t}`, text: t })), h('span', { class: 'mono', text: s.text })))),
    found.total > found.items.length
      ? h('p', {}, h('button', { class: 'link', type: 'button', text: `All ${found.total} notable strings`, onclick: () => show('strings') }))
      : null);
  }).catch(() => fill(notable));

  const engineNote = h('div');
  api('engine', { path: state.path }).then((result) => {
    if (!result.matches.length) return;
    const best = result.matches[0];
    fill(engineNote, h('p', { class: 'notice is-ok' },
      `This looks like a ${best.engine} game (${best.confidence} confidence). `,
      h('button', { class: 'link', type: 'button', text: 'See its assets', onclick: () => show('assets') })));
  }).catch(() => {});

  add(box, 
    engineNote,
    info.warnings.length ? h('div', { class: 'notice' }, h('strong', { text: 'This file is damaged or unusual. ' }), info.warnings.join(' · ')) : null,
    block,
    h('div', { class: 'columns' },
      h('section', { class: 'panel' }, h('h3', { text: 'Protections' }), checks),
      h('section', { class: 'panel' }, h('h3', { text: `Libraries it needs (${info.libraries.length})` }), libs),
      h('section', { class: 'panel' }, h('h3', { text: 'Notable strings' }), notable),
      details.length ? h('section', { class: 'panel' }, h('h3', { text: 'Build details' }), h('ul', { class: 'plain-list' }, details)) : null));
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
  const options = { q: '', tagged: false, encoding: 'all', min: 4, shown: 300 };
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
          h('td', { class: 'mono wrap' }, s.text, s.encoding === 'utf16' ? h('span', { class: 'muted', text: '  (wide)' }) : null),
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
      h('label', { class: 'check' }, h('input', { type: 'checkbox', onchange: (e) => { options.tagged = e.target.checked; reload(); } }), 'Only links, addresses and paths'),
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

async function renderImports(box) {
  const [imports, exports_] = await Promise.all([
    api('imports', { path: state.path }), api('exports', { path: state.path })]);
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
      h('tbody', {}, rows))) : h('p', { class: 'muted', text: 'This file imports nothing.' }));
  if (exports_.length) {
    add(box, 
      h('div', { class: 'view-head', style: { marginTop: '26px' } }, h('h2', { text: `Exports (${exports_.length})` }),
        h('p', { text: 'Functions this file offers to other programs.' })),
      h('div', { class: 'table-wrap' }, h('table', {},
        h('thead', {}, h('tr', {}, ['Number', 'Address', 'Name', 'Passed on to'].map((t) => h('th', { scope: 'col', text: t })))),
        h('tbody', {}, exports_.map((e) => h('tr', {},
          h('td', { class: 'num mono', text: e.ordinal === null ? '' : String(e.ordinal) }),
          h('td', { class: 'mono' }, e.address ? h('button', { class: 'link', type: 'button', text: e.address, onclick: () => goTo(e.address) }) : ''),
          h('td', { class: 'mono wrap', text: e.name }),
          h('td', { class: 'mono', text: e.forwarder || '' })))))));
  }
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
        h('td', { text: perms(s.perms) }),
        h('td', {}, h('div', { class: 'bar-cell' },
          h('span', { class: 'meter' + (s.entropy > 7.2 ? ' is-high' : '') }, h('i', { style: { width: `${(s.entropy / 8) * 100}%` } })),
          h('span', { class: 'mono', text: s.entropy.toFixed(2) })))))))) :
      h('p', { class: 'notice', text: 'This file has no section table (it was removed). The segments below still describe what gets loaded.' }));
  if (segments.length) {
    add(box, 
      h('div', { class: 'view-head', style: { marginTop: '26px' } }, h('h2', { text: `Segments (${segments.length})` }),
        h('p', { text: 'How Linux maps the file into memory when it starts.' })),
      h('div', { class: 'table-wrap' }, h('table', {},
        h('thead', {}, h('tr', {}, ['Type', 'Address', 'Size in file', 'Size in memory', 'File offset', 'Access'].map((t, i) =>
          h('th', { scope: 'col', text: t, class: i >= 2 && i <= 4 ? 'num' : '' })))),
        h('tbody', {}, segments.map((s) => h('tr', {},
          h('td', { class: 'mono', text: s.type }), h('td', { class: 'mono', text: s.address }),
          h('td', { class: 'num mono', text: bytesText(s.size) }), h('td', { class: 'num mono', text: bytesText(s.vsize) }),
          h('td', { class: 'num mono', text: hex(s.offset) }), h('td', { text: perms(s.perms) })))))));
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
      h('button', { type: 'button', class: 'btn', text: 'Next page', onclick: () => step(PAGE) })),
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
      fill(preview, h('p', { class: 'notice', text: 'This file is encrypted. binspect does not decrypt protected content.' }));
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
      const out = window.prompt(`Save the modified pack as (the original is not changed):`, suggestOutput(path, 'modded'));
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
      summary.textContent = `${found.format} pack, ${found.count} files` + (found.writable ? '' : ' (read-only: binspect cannot rebuild this kind)');
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
        const dest = window.prompt('Folder to extract into (created if missing):', path + '_extracted');
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
        const out = window.prompt('Save the modified program as (the original is not changed):', suggestOutput(state.path, 'modded'));
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
    version.length ? h('ul', { class: 'plain-list', style: { marginBottom: '14px', maxWidth: '70ch' } }, version.map(([k, v]) =>
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
        h('p', { text: 'Packs binspect can open. Choose one to browse, extract or replace its files.' })),
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

// --- start ------------------------------------------------------------------

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  const button = $('theme-toggle');
  button.textContent = theme === 'dark' ? 'Light' : 'Dark';
  button.setAttribute('aria-pressed', String(theme === 'dark'));
  try { localStorage.setItem('binspect-theme', theme); } catch (e) { /* private mode */ }
}

function start() {
  const params = new URLSearchParams(location.hash.slice(1));
  let stored = null;
  try { stored = sessionStorage.getItem('binspect-token'); } catch (e) { /* ignore */ }
  state.token = params.get('token') || stored || '';
  try { sessionStorage.setItem('binspect-token', state.token); } catch (e) { /* ignore */ }
  if (location.hash) history.replaceState(null, '', location.pathname);

  let theme = null;
  try { theme = localStorage.getItem('binspect-theme'); } catch (e) { /* ignore */ }
  applyTheme(theme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));
  $('theme-toggle').addEventListener('click', () =>
    applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'));

  $('open-button').addEventListener('click', openDialog);
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
    const file = e.dataTransfer && e.dataTransfer.files[0];
    if (file) uploadFile(file);
  });

  if (!state.token) {
    fill($('main'), h('div', { class: 'welcome' },
      h('h1', { text: 'This page needs its session link' }),
      h('p', { text: 'Start binspect from a terminal with “binspect gui” and open the link it prints. The link carries a one-time key so that no other web page can use this tool.' })));
    $('open-button').disabled = true;
    return;
  }
  renderWelcome();
  const open = params.get('open');
  if (open) openPath(open);
}

start();
