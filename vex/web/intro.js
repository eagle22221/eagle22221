/* vex — opening animation.
 *
 * Load from <head> as a plain (not deferred) script, after intro.css. It
 * plays once per browser session: the three blades sweep in and lock, their
 * cyan edges draw on, the red eye ignites, a light sweep crosses the emblem
 * and the wordmark rises; then the emblem glides onto the sidebar logo and the
 * overlay fades away. intro.css holds all of the look and timing.
 *
 * - Skip: a click, Escape, Enter or Space ends it at once.
 * - Once per session: sessionStorage "vex-intro-played". "intro=1" in the
 *   query or hash forces it to play, "intro=0" turns it off. Browser
 *   automation (navigator.webdriver) does not get it unless forced.
 * - prefers-reduced-motion: the finished emblem, held still, then faded.
 * - The overlay is aria-hidden, holds nothing focusable, and the app loads
 *   underneath while it plays. Any error removes it.
 * - Landing spot: the first visible [data-intro-target] element, else an
 *   <img> of logo.svg. It must show logo.svg (viewBox 0 0 256 256).
 * - While it plays <html> has the class "vxi-active"; when it is gone,
 *   "vex:intro-done" is dispatched on document.
 * - Theme: it plays on the app's own sky, so it reads the theme the way
 *   app.js will (it runs first): localStorage "vex-theme", no key prefix.
 *   "light" gets the blue sky (.vxi.is-light, and "vxi-light" on <html> until
 *   it is gone); "dark" or nothing stored, the indigo field. With nothing
 *   stored, or storage unavailable, a data-theme="light" already on <html>
 *   counts too; otherwise it is dark.
 */
(function () {
  'use strict';

  var KEY = 'vex-intro-played';
  var THEME_KEY = 'vex-theme';     // app.js: remember('vex-theme', …) / recall(…)
  var NS = 'http://www.w3.org/2000/svg';
  // The timeline lives in intro.css; these only back it up. The overlay
  // leaves when its clock animation ends, the sidebar logo reappears when the
  // landing clock ends, and the overlay is removed once the emblem has settled
  // on it (or, with nothing to land on, once the field has faded out).
  var EXIT_MS = 1300;       // longest the exit may take before removal anyway
  var STILL_MS = 650;       // reduced motion: how long the still emblem shows
  var FAILSAFE_MS = 8000;   // whatever happens, the overlay is gone by then

  var doc = document;
  var html = doc.documentElement;
  var state = 'idle';       // idle → playing → leaving / skipping → done
  var light = false;        // the app's theme is light: play on the blue sky
  var overlay = null;
  var clock = null;
  var target = null;
  var observer = null;
  var timers = [];

  // logo.svg, part by part. Blades are tip, side, inner corner, other side.
  var BLADES = [
    [[128, 14], [163, 92], [128, 108], [93, 92]],
    [[230.2, 191], [145.1, 182.3], [148.8, 144], [180.1, 121.7]],
    [[25.8, 191], [75.9, 121.7], [107.2, 144], [110.9, 182.3]]
  ];
  var SHARDS = [
    '128,196 150,176 128,168 106,176',
    '72.6,100 78.9,129.1 96.8,114 100.9,90.9',
    '183.4,100 155.1,90.9 159.2,114 177.1,129.1'
  ];
  // The triangle and the eye's socket ring are drawn as two halves that start
  // together at the top and meet at the bottom.
  var TRIANGLE = ['M128 56L194 170L128 170', 'M128 56L62 170L128 170'];
  var RING = ['M128 105A27 27 0 0 1 128 159', 'M128 105A27 27 0 0 0 128 159'];
  var CYAN = '#3FE0E6';
  var SPARKS = 18;          // points of light on the field (placed by intro.css)

  function guard(fn) {
    return function () {
      try { return fn.apply(this, arguments); } catch (e) { teardown(); }
    };
  }

  function later(fn, ms) { timers.push(setTimeout(guard(fn), ms)); }

  function choice() {
    var m = /[?#&]intro=([01])(?![\w-])/.exec(location.search + location.hash);
    return m ? m[1] : '';
  }

  function shouldPlay() {
    var forced = choice();
    if (forced) return forced === '1';
    if (navigator.webdriver) return false;
    if (doc.visibilityState === 'hidden') return false;
    try { if (window.sessionStorage.getItem(KEY)) return false; } catch (e) { /* play */ }
    return true;
  }

  // Read like app.js's recall(): storage can be missing or refuse.
  function storedTheme() {
    var value = null;
    try { value = window.localStorage.getItem(THEME_KEY); } catch (e) { /* unavailable */ }
    if (value === 'light' || value === 'dark') return value;
    return html.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
  }

  function reducedMotion() {
    try { return window.matchMedia('(prefers-reduced-motion: reduce)').matches; } catch (e) { return false; }
  }

  // --- building the overlay ------------------------------------------------

  function el(tag, cls, parent, text) {
    var node = doc.createElement(tag);
    if (cls) node.className = cls;
    if (text) node.textContent = text;
    if (parent) parent.appendChild(node);
    return node;
  }

  function svg(tag, attrs, parent) {
    var node = doc.createElementNS(NS, tag);
    for (var name in attrs) {
      if (Object.prototype.hasOwnProperty.call(attrs, name)) node.setAttribute(name, attrs[name]);
    }
    if (parent) parent.appendChild(node);
    return node;
  }

  function points(list) {
    return list.map(function (p) { return p[0] + ',' + p[1]; }).join(' ');
  }

  function path(p) {
    return 'M' + p.map(function (q) { return q[0] + ' ' + q[1]; }).join('L');
  }

  function gradient(defs, kind, id, attrs, stops) {
    attrs.id = id;
    var g = svg(kind, attrs, defs);
    stops.forEach(function (s) {
      var stop = { offset: s[0], 'stop-color': s[1] };
      if (s.length > 2) stop['stop-opacity'] = s[2];
      svg('stop', stop, g);
    });
  }

  function drawn(d, parent, attrs) {
    var a = { d: d, pathLength: '1', 'class': 'vxi-draw' };
    for (var k in attrs) {
      if (Object.prototype.hasOwnProperty.call(attrs, k)) a[k] = attrs[k];
    }
    return svg('path', a, parent);
  }

  function emblem(parent) {
    var root = svg('svg', {
      'class': 'vxi-svg', viewBox: '0 0 256 256', 'aria-hidden': 'true', focusable: 'false'
    }, parent);
    var defs = svg('defs', {}, root);
    gradient(defs, 'linearGradient', 'vxi-steel', { x1: 0, y1: 0, x2: 1, y2: 1 },
      [[0, '#16324A'], [1, '#081320']]);
    gradient(defs, 'linearGradient', 'vxi-lit', { x1: 0, y1: 0, x2: 1, y2: 0 },
      [[0, '#2FD6E0', 0], [1, '#2FD6E0', 0.55]]);
    gradient(defs, 'radialGradient', 'vxi-eye', { cx: 0.5, cy: 0.5, r: 0.5 },
      [[0, '#FFD9D2'], [0.28, '#FF4A3D'], [1, '#8E0F14']]);
    gradient(defs, 'radialGradient', 'vxi-glow', { cx: 0.5, cy: 0.5, r: 0.5 },
      [[0, '#FF3B30', 0.55], [1, '#FF3B30', 0]]);
    gradient(defs, 'linearGradient', 'vxi-sheen', { x1: 0, y1: 0, x2: 1, y2: 0 },
      [[0, '#FFFFFF', 0], [0.5, '#E9FCFF', 0.6], [1, '#FFFFFF', 0]]);
    var blur = svg('filter', { id: 'vxi-blur', x: '-20%', y: '-20%', width: '140%', height: '140%' }, defs);
    svg('feGaussianBlur', { stdDeviation: '3.4' }, blur);
    var clip = svg('clipPath', { id: 'vxi-clip' }, defs);
    BLADES.forEach(function (b) { svg('polygon', { points: points(b) }, clip); });
    SHARDS.forEach(function (s) { svg('polygon', { points: s }, clip); });
    svg('circle', { cx: 128, cy: 132, r: 27 }, clip);

    // A soft cyan halo behind the edges, which flares as the blades lock.
    var halo = svg('g', {
      'class': 'vxi-halo', filter: 'url(#vxi-blur)', fill: 'none', stroke: CYAN,
      'stroke-width': '3.2', 'stroke-linejoin': 'round'
    }, root);
    BLADES.forEach(function (b) { svg('polygon', { points: points(b) }, halo); });
    svg('polygon', { points: '128,56 194,170 62,170' }, halo);

    var blades = svg('g', { 'class': 'vxi-blades' }, root);
    BLADES.forEach(function (b, i) {
      var g = svg('g', { 'class': 'vxi-blade vxi-b' + (i + 1) }, blades);
      svg('polygon', { 'class': 'vxi-fill', points: points(b), fill: 'url(#vxi-steel)' }, g);
      var lit = svg('g', { opacity: '.55' }, g);
      svg('polygon', { 'class': 'vxi-fill', points: points(b.slice(0, 3)), fill: 'url(#vxi-lit)' }, lit);
      var edge = { stroke: CYAN, 'stroke-width': '2.2' };
      drawn(path([b[0], b[1], b[2]]), g, edge);
      drawn(path([b[0], b[3], b[2]]), g, edge);
    });

    var shards = svg('g', {
      'class': 'vxi-shards', fill: '#0C1A2B', stroke: '#22B8C4', 'stroke-width': '1.6',
      'stroke-linejoin': 'round'
    }, root);
    SHARDS.forEach(function (s) { svg('polygon', { points: s }, shards); });

    var tri = svg('g', { 'class': 'vxi-tri', opacity: '.9' }, root);
    TRIANGLE.forEach(function (d) { drawn(d, tri, { stroke: CYAN, 'stroke-width': '3' }); });

    svg('circle', { 'class': 'vxi-glow', cx: 128, cy: 132, r: 46, fill: 'url(#vxi-glow)' }, root);
    svg('circle', {
      'class': 'vxi-shock', cx: 128, cy: 132, r: 21, fill: 'none', stroke: '#FF7B6E', 'stroke-width': '1.3'
    }, root);
    svg('circle', { 'class': 'vxi-socket', cx: 128, cy: 132, r: 27, fill: '#07101B' }, root);
    var ring = svg('g', { 'class': 'vxi-ring' }, root);
    RING.forEach(function (d) { drawn(d, ring, { stroke: CYAN, 'stroke-width': '2.4' }); });
    var iris = svg('g', { 'class': 'vxi-iris' }, root);
    svg('circle', { cx: 128, cy: 132, r: 17, fill: 'url(#vxi-eye)' }, iris);
    svg('circle', {
      cx: 128, cy: 132, r: 17, fill: 'none', stroke: '#FF8A7E', 'stroke-width': '1.2', opacity: '.8'
    }, iris);
    svg('circle', { 'class': 'vxi-pupil', cx: 128, cy: 132, r: 5, fill: '#FFF2EE' }, root);

    // The light sweep: a soft band crossing the emblem's faces on a diagonal.
    var lens = svg('g', { 'clip-path': 'url(#vxi-clip)' }, root);
    var tilt = svg('g', { 'class': 'vxi-tilt', transform: 'rotate(22 128 132)' }, lens);
    svg('rect', {
      'class': 'vxi-shine', x: -10, y: -60, width: 72, height: 380, fill: 'url(#vxi-sheen)'
    }, tilt);
    return root;
  }

  function build(still) {
    var root = el('div', 'vxi' + (light ? ' is-light' : '') + (still ? ' is-still' : ''));
    root.setAttribute('aria-hidden', 'true');
    // The field, with its sparkles in it, so they leave together.
    var sparks = el('div', 'vxi-sparks', el('div', 'vxi-bg', root));
    for (var i = 0; i < SPARKS; i++) el('i', 'vxi-spark', sparks);
    var center = el('div', 'vxi-center', root);
    var mark = el('div', 'vxi-mark', center);
    el('div', 'vxi-aura', mark);
    el('div', 'vxi-ember', mark);
    emblem(el('div', 'vxi-core', mark));

    var word = el('div', 'vxi-word', center);
    var name = el('span', 'vxi-line vxi-name', word);
    el('span', 'vxi-rise vxi-vex', name, 'vex');
    name.appendChild(doc.createTextNode(' '));
    el('span', 'vxi-rise vxi-pro', name, 'Pro');
    el('span', 'vxi-rise vxi-tag', el('span', 'vxi-line', word), 'Binary Analysis Suite');

    var credit = el('span', '', el('div', 'vxi-credit', root), 'Developed by ');
    el('b', '', credit, 'SS');

    clock = el('div', 'vxi-clock', root);
    return root;
  }

  // --- landing on the sidebar logo -----------------------------------------

  function findTarget() {
    var found = doc.querySelectorAll('[data-intro-target], img[src$="logo.svg"]');
    var w = window.innerWidth;
    var h = window.innerHeight;
    for (var i = 0; i < found.length; i++) {
      var node = found[i];
      if (overlay.contains(node)) continue;
      var r = node.getBoundingClientRect();
      if (r.width >= 12 && r.height >= 12 && r.right > 0 && r.bottom > 0 && r.left < w && r.top < h) {
        return { node: node, rect: r };
      }
    }
    return null;
  }

  function aim(hit) {
    var from = overlay.querySelector('.vxi-mark').getBoundingClientRect();
    if (!from.width) return false;
    // In the overlay, 1 logo unit = from.width / 216 px and the eye is at
    // (50%, 63.265%) of the mark; in the target, logo.svg is fitted to its box.
    var r = hit.rect;
    var side = Math.min(r.width, r.height);
    var unit = side / 256;
    var tx = r.left + (r.width - side) / 2 + 128 * unit;
    var ty = r.top + (r.height - side) / 2 + 132 * unit;
    var ex = from.left + from.width * 0.5;
    var ey = from.top + from.height * (124 / 196);
    overlay.style.setProperty('--vxi-dx', (tx - ex).toFixed(2) + 'px');
    overlay.style.setProperty('--vxi-dy', (ty - ey).toFixed(2) + 'px');
    overlay.style.setProperty('--vxi-s', (unit / (from.width / 216)).toFixed(4));
    target = hit.node;
    target.classList.add('vxi-target');
    html.classList.add('vxi-landing');
    return true;
  }

  // --- playing -------------------------------------------------------------

  function leave(gentle) {
    if (state !== 'playing') return;
    state = 'leaving';
    window.removeEventListener('keydown', onKey, true);
    if (gentle) {
      overlay.classList.add('is-fading');
      later(teardown, 400);
      return;
    }
    var hit = findTarget();
    if (hit && aim(hit)) overlay.classList.add('has-target');
    overlay.classList.add('is-leaving');
    later(teardown, EXIT_MS);
  }

  function skip() {
    if (state !== 'playing') return;
    state = 'skipping';
    window.removeEventListener('keydown', onKey, true);
    overlay.classList.add('is-skipping');
    later(teardown, 200);
  }

  // Skip keys are kept from the app (Enter must not also press a button);
  // every other key goes through untouched.
  function onKey(e) {
    try {
      var k = e.key;
      if (k === 'Escape' || k === 'Esc' || k === 'Enter' || k === ' ' || k === 'Spacebar') {
        e.preventDefault();
        e.stopImmediatePropagation();
        skip();
      }
    } catch (x) {
      teardown();
    }
  }

  function onAnimationEnd(e) {
    var name = e.animationName;
    if (name === 'vxi-clock') leave(false);
    if (state !== 'leaving') return;
    if (name === 'vxi-land') html.classList.remove('vxi-landing');
    // Gone once the emblem has settled on the sidebar logo, or else once the
    // field has faded out.
    if (name === (target ? 'vxi-settle' : 'vxi-field-out')) teardown();
  }

  function onVisibility() {
    if (doc.visibilityState === 'hidden') teardown();
  }

  function teardown() {
    if (state === 'done') return;
    state = 'done';
    timers.forEach(clearTimeout);
    timers = [];
    try { if (observer) observer.disconnect(); } catch (e) { /* ignore */ }
    window.removeEventListener('keydown', onKey, true);
    doc.removeEventListener('visibilitychange', onVisibility);
    try { if (overlay && overlay.parentNode) overlay.parentNode.removeChild(overlay); } catch (e) { /* ignore */ }
    html.classList.remove('vxi-boot');
    html.classList.remove('vxi-light');
    html.classList.remove('vxi-active');
    html.classList.remove('vxi-landing');
    try { if (target) target.classList.remove('vxi-target'); } catch (e) { /* ignore */ }
    overlay = target = clock = null;
    try { doc.dispatchEvent(new CustomEvent('vex:intro-done')); } catch (e) { /* ignore */ }
  }

  function mount() {
    if (state !== 'idle') return;
    var still = reducedMotion();
    overlay = build(still);
    doc.body.insertBefore(overlay, doc.body.firstChild);
    // Without intro.css the overlay would be an unstyled mess: leave at once.
    if (window.getComputedStyle(overlay).position !== 'fixed') {
      teardown();
      return;
    }
    state = 'playing';
    html.classList.add('vxi-active');
    html.classList.remove('vxi-boot');
    overlay.addEventListener('click', guard(skip));
    overlay.addEventListener('animationend', guard(onAnimationEnd));
    window.addEventListener('keydown', onKey, true);
    doc.addEventListener('visibilitychange', onVisibility);
    if (still) later(function () { leave(true); }, STILL_MS);
  }

  // The overlay goes in as soon as <body> exists: before the app's own
  // scripts run, and before anything of the app is painted.
  function whenBody(fn) {
    if (doc.body) {
      fn();
      return;
    }
    var go = guard(function () {
      if (!doc.body || state !== 'idle') return;
      if (observer) observer.disconnect();
      doc.removeEventListener('DOMContentLoaded', go);
      fn();
    });
    if (window.MutationObserver) {
      observer = new MutationObserver(go);
      observer.observe(html, { childList: true });
    }
    doc.addEventListener('DOMContentLoaded', go);
  }

  try {
    if (!shouldPlay()) return;
    try { window.sessionStorage.setItem(KEY, '1'); } catch (e) { /* storage unavailable */ }
    light = storedTheme() === 'light';
    html.classList.add('vxi-boot');
    if (light) html.classList.add('vxi-light');
    later(teardown, FAILSAFE_MS);
    whenBody(guard(mount));
  } catch (e) {
    teardown();
  }
})();
