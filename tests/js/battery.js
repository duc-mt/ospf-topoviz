// Drives the explorer page in jsdom and prints one JSON object of observations.
// Usage: node battery.js plain.html [findings.html]
const { JSDOM, VirtualConsole } = require('jsdom');
const fs = require('fs');
const [plainFile, richFile] = process.argv.slice(2);
const errors = [];
const wait = ms => new Promise(r => setTimeout(r, ms));

function open(file, storage, media) {
  const vc = new VirtualConsole();
  const listeners = [];
  const mq = { matches: media === 'light' };
  vc.on('jsdomError', e => errors.push(String(e.stack || e)));
  const downloads = [];
  const dom = new JSDOM(fs.readFileSync(file, 'utf8'), {
    runScripts: 'dangerously', pretendToBeVisual: true, url: 'http://localhost/explorer.html', virtualConsole: vc,
    beforeParse(w) {
      for (const k of Object.keys(storage || {})) w.localStorage.setItem(k, storage[k]);
      if (media) w.matchMedia = () => Object.assign(mq, { addEventListener: (t, fn) => listeners.push(fn), removeEventListener() {} });
      w.URL.createObjectURL = blob => { downloads.push({ blob }); return 'blob:test'; };
      w.URL.revokeObjectURL = () => {};
      w.HTMLAnchorElement.prototype.click = function () { if (this.download) downloads[downloads.length - 1].name = this.download; };
    },
  });
  dom.downloads = downloads;
  dom.setSystemTheme = light => { mq.matches = light; listeners.forEach(fn => fn({ matches: light })); };
  return dom;
}
function ev(w, type, target, init) { target.dispatchEvent(new w.MouseEvent(type, Object.assign({ bubbles: true, cancelable: true, view: w }, init || {}))); }
function readBlob(w, blob) { return new Promise(res => { const r = new w.FileReader(); r.onload = () => res(r.result); r.readAsText(blob); }); }
const storageOf = w => { const s = {}; for (let i = 0; i < w.localStorage.length; i++) { const k = w.localStorage.key(i); s[k] = w.localStorage.getItem(k); } return s; };

(async () => {
  const out = {};
  // ============================================================ plain page
  let dom = open(plainFile), w = dom.window, d = w.document; await wait(150);
  const X = () => w.__explorer;
  out.nodes = d.querySelectorAll('g[data-node]').length;
  out.links = d.querySelectorAll('g[data-link]').length;
  out.areaBoxes = d.querySelectorAll('#areas g[data-area]').length;
  out.summary = d.getElementById('summary').textContent;
  out.cards = [...d.querySelectorAll('#diag .card')].map(c => c.textContent.trim());

  const hit = d.querySelector('g[data-link] .hit'), tip = d.getElementById('tip');
  ev(w, 'mouseover', hit, { clientX: 300, clientY: 300 });
  out.tipShown = tip.style.display === 'block'; out.tipText = tip.textContent;
  ev(w, 'mouseout', hit, { relatedTarget: d.getElementById('canvas') });
  out.tipHidden = tip.style.display === 'none';

  const n8 = d.querySelector('g[data-node="10.255.255.8"]');
  ev(w, 'mousedown', n8, { button: 0, clientX: 100, clientY: 100 }); ev(w, 'mouseup', n8, { button: 0, clientX: 100, clientY: 100 });
  const opacity = id => d.querySelector('g[data-node="' + id + '"]').getAttribute('opacity');
  out.selVisible = d.getElementById('sel').className !== 'hidden'; out.selText = d.getElementById('sel').textContent;
  out.farDimmed = opacity('10.255.255.15') === '0.15'; out.selfLit = opacity('10.255.255.8') === '1';
  d.getElementById('sel-clear').click();
  out.selectionCleared = d.getElementById('sel').className === 'hidden' && opacity('10.255.255.15') === '1';

  // link selection
  const hit2 = d.querySelector('g[data-link] .hit');
  ev(w, 'mousedown', hit2, { button: 0, clientX: 50, clientY: 50 }); ev(w, 'mouseup', hit2, { button: 0, clientX: 50, clientY: 50 });
  out.linkSelected = !!(X().state.sel && X().state.sel.type === 'link');
  d.getElementById('sel-clear').click();

  // drag, save, restore, reset
  const before = Object.assign({}, X().pos['10.255.255.20']), k = X().state.view.k;
  const n20 = d.querySelector('g[data-node="10.255.255.20"]');
  ev(w, 'mousedown', n20, { button: 0, clientX: 500, clientY: 500 });
  ev(w, 'mousemove', w, { clientX: 620, clientY: 560 }); ev(w, 'mouseup', w, { clientX: 620, clientY: 560 });
  const after = X().pos['10.255.255.20'];
  out.dragDx = Math.round((after.x - before.x) * k); out.dragDy = Math.round((after.y - before.y) * k);
  const saved = storageOf(w);
  out.savedKeys = Object.keys(saved);
  out.savedOnlyMovedNode = Object.values(saved).every(v => Object.keys(JSON.parse(v)).join() === '10.255.255.20');
  const dom2 = open(plainFile, saved); await wait(150);
  const p2 = dom2.window.__explorer.pos['10.255.255.20'];
  out.restoredAfterReload = Math.abs(p2.x - after.x) < 1.5 && Math.abs(p2.y - after.y) < 1.5;
  out.otherNodesUntouched = Math.abs(dom2.window.__explorer.pos['10.255.255.8'].x - X().pos['10.255.255.8'].x) < 1.5;
  dom2.window.close();
  // a click without movement must not count as a drag
  const keep = JSON.stringify(storageOf(w));
  ev(w, 'mousedown', n20, { button: 0, clientX: 10, clientY: 10 }); ev(w, 'mousemove', w, { clientX: 12, clientY: 11 }); ev(w, 'mouseup', w, { clientX: 12, clientY: 11 });
  out.wobbleSelects = !!(X().state.sel && X().state.sel.id === '10.255.255.20'); d.getElementById('sel-clear').click();
  out.clickIsNotADrag = JSON.stringify(storageOf(w)) === keep;
  d.getElementById('b-reset').click();
  const back = X().pos['10.255.255.20'];
  out.resetRestoresBase = Math.abs(back.x - before.x) < 1 && Math.abs(back.y - before.y) < 1 && w.localStorage.length === 0;

  // search
  const q = d.getElementById('q'); q.value = '10.255.255.19'; ev(w, 'input', q);
  out.searchHits = X().state.matches ? [...X().state.matches] : [];
  q.value = '10.136.4.0/28'; ev(w, 'input', q); out.searchByPrefix = X().state.matches ? [...X().state.matches] : [];
  q.value = '10.80.0.0/24'; ev(w, 'input', q); out.searchByRouterPrefix = X().state.matches ? [...X().state.matches] : [];
  q.value = 'zzzz'; ev(w, 'input', q); out.searchNoMatch = X().state.matches ? X().state.matches.size : -1;
  q.value = ''; ev(w, 'input', q); out.searchCleared = X().state.matches === null;

  // diagnostics -> focus
  [...d.querySelectorAll('#diag .card')][0].click();
  out.splitFocus = X().state.focus ? X().state.focus.nodes : null;
  out.rings = [...d.querySelectorAll('g[data-node] rect[stroke="#f43f5e"]')].filter(r => r.getAttribute('display') === 'inline').length;
  d.dispatchEvent(new w.KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
  out.escapeClears = X().state.focus === null;

  // filters
  const oneway = d.getElementById('f-oneway'); oneway.checked = false; ev(w, 'change', oneway);
  out.linksWithoutOneWay = d.querySelectorAll('g[data-link]').length; oneway.checked = true; ev(w, 'change', oneway);
  const area = d.querySelector('input[data-area="0.0.0.4"]'); area.checked = false; ev(w, 'change', area);
  out.nodesWithoutArea4 = d.querySelectorAll('g[data-node]').length; area.checked = true; ev(w, 'change', area);
  const af = d.getElementById('f-areas'); af.checked = false; ev(w, 'change', af);
  out.areaBoxesHidden = d.querySelectorAll('#areas g[data-area]').length; af.checked = true; ev(w, 'change', af);

  // bundles
  const b = d.getElementById('f-bundle'), bm = d.getElementById('f-bundlemin');
  bm.value = '5'; b.checked = true; ev(w, 'change', b); ev(w, 'change', bm);
  out.bundleNodes = d.querySelectorAll('g[data-node]').length; out.bundleLinks = d.querySelectorAll('g[data-link]').length;
  const bn = d.querySelector('g[data-node^="bundle:"]'); out.hasBundle = !!bn;
  if (bn) {
    out.bundleLabel = bn.textContent;
    q.value = '10.255.255.10'; ev(w, 'input', q); out.searchOpensBundle = d.querySelectorAll('g[data-node^="bundle:"]').length === 0;
    q.value = ''; ev(w, 'input', q);
    out.bundleBack = d.querySelectorAll('g[data-node^="bundle:"]').length === 1;
    ev(w, 'mousedown', d.querySelector('g[data-node^="bundle:"]'), { button: 0, clientX: 9, clientY: 9 }); ev(w, 'mouseup', w, { clientX: 9, clientY: 9 });
    out.afterExpand = d.querySelectorAll('g[data-node]').length;
  }
  b.checked = false; ev(w, 'change', b);

  // view
  const z0 = X().state.view.k; d.getElementById('b-zin').click(); out.zoomIn = X().state.view.k > z0;
  d.getElementById('b-zout').click(); d.getElementById('b-fit').click();
  out.fitK = X().state.view.k > 0;
  d.dispatchEvent(new w.KeyboardEvent('keydown', { key: '/', bubbles: true })); out.slashFocusesSearch = d.activeElement && d.activeElement.id === 'q';
  d.activeElement.blur();
  d.getElementById('b-side').click(); out.sidebarCollapsed = d.getElementById('side').className.indexOf('collapsed') >= 0;
  d.getElementById('b-side').click();
  d.getElementById('b-filter').click(); out.filterPanelOpen = !d.getElementById('p-filter').classList.contains('hidden');
  d.getElementById('b-more').click(); out.morePanelOpensFilterCloses = !d.getElementById('p-more').classList.contains('hidden') && d.getElementById('p-filter').classList.contains('hidden');

  // export / import layout, svg download
  d.getElementById('m-export').click();
  const exp = dom.downloads[dom.downloads.length - 1];
  out.exportName = exp.name; const exported = JSON.parse(await readBlob(w, exp.blob));
  out.exportCount = Object.keys(exported.positions).length; out.exportScope = exported.scope;
  const file = new w.File([JSON.stringify({ positions: { '10.255.255.20': [111, 222], 'nope': [1, 2] } })], 'l.json');
  const input = d.getElementById('m-file'); Object.defineProperty(input, 'files', { value: [file], configurable: true }); ev(w, 'change', input);
  await wait(60);
  out.importMoved = X().pos['10.255.255.20'].x === 111 && X().pos['10.255.255.20'].y === 222;
  d.getElementById('m-svg').click();
  const svgDl = dom.downloads[dom.downloads.length - 1]; out.svgName = svgDl.name;
  const svgText = await readBlob(w, svgDl.blob); out.svgOk = svgText.indexOf('<svg') > 0 && svgText.indexOf('viewBox') > 0 && svgText.indexOf('10.255.255.20') > 0;

  // ====================================================== page with findings and a trace
  if (richFile) {
    dom = open(richFile); w = dom.window; d = w.document; await wait(150);
    out.rich = {};
    const R = out.rich;
    R.groups = [...d.querySelectorAll('#findings details')].map(x => x.querySelector('summary').textContent.replace(/\s+/g, ' ').trim());
    R.chips = [...d.querySelectorAll('#sevchips .chip')].map(x => x.textContent.trim());
    R.suspectCard = [...d.querySelectorAll('#diag .card')].some(c => c.textContent.indexOf('Suspect run') >= 0);
    const row = d.querySelector('#findings details .row'); row.click();
    R.focusAfterRow = X().state.focus.nodes;
    d.dispatchEvent(new w.KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    R.groupsDefault = d.querySelectorAll('#findings details').length;       // information is hidden until asked for
    R.infoChipOff = d.querySelectorAll('#sevchips .chip')[2].classList.contains('off');
    d.querySelectorAll('#sevchips .chip')[2].click();
    R.groupsWithInfo = d.querySelectorAll('#findings details').length;
    d.querySelectorAll('#sevchips .chip')[2].click();
    d.querySelectorAll('#sevchips .chip')[0].click();   // hide the critical group
    R.groupsWithoutCritical = d.querySelectorAll('#findings details').length;
    d.querySelectorAll('#sevchips .chip')[0].click();
    R.flushCard = [...d.querySelectorAll('#diag .card')].filter(c => c.textContent.indexOf('about to age out') >= 0).map(c => c.textContent.trim());
    R.traceCard = d.getElementById('trace').textContent.trim();
    d.querySelector('#trace .card').click();
    R.traceFocusLinks = X().state.focus.links.length; R.traceFocusNodes = X().state.focus.nodes.length;
    R.traceLinksDrawn = [...d.querySelectorAll('g[data-link] line')].filter(l => l.getAttribute('stroke') === '#38bdf8' && l.getAttribute('display') === 'inline').length;
    R.errors = errors.length;
  }

  // ============================================================ theme switch
  out.theme = {};
  const T = out.theme;
  const snap = dm => {
    const win = dm.window, doc = win.document;
    return { attr: doc.documentElement.getAttribute('data-theme'), pref: win.__explorer.state.theme, icon: doc.getElementById('b-theme').textContent,
      title: doc.getElementById('b-theme').title, saved: win.localStorage.getItem('ospf-explorer:theme'),
      areaFill: doc.querySelector('#areas rect').getAttribute('fill'), areaLabel: doc.querySelector('#areas text').getAttribute('fill'),
      linkColor: doc.querySelector('g[data-link] line:nth-of-type(3)').getAttribute('stroke'), pill: (doc.querySelector('#labels rect') || { getAttribute: () => null }).getAttribute('fill') };
  };
  // no saved choice, no matchMedia: starts in "auto", which resolves to dark
  let t1 = open(plainFile); await wait(130);
  T.initial = snap(t1);
  // the button cycles auto -> light -> dark -> auto, saving each choice
  const btn = t1.window.document.getElementById('b-theme');
  T.cycle = [];
  for (let i = 0; i < 3; i++) { btn.click(); T.cycle.push(snap(t1)); }
  T.drawnWithoutError = t1.window.document.querySelectorAll('g[data-node]').length;
  // "auto" follows the operating system, live
  let t2 = open(plainFile, null, 'light'); await wait(130);
  T.autoWhenSystemIsLight = snap(t2);
  t2.setSystemTheme(false); T.afterSystemGoesDark = snap(t2);
  t2.setSystemTheme(true); T.afterSystemGoesLight = snap(t2);
  t2.window.document.getElementById('b-theme').click();           // -> light (explicit)
  t2.setSystemTheme(false); T.explicitIgnoresSystem = snap(t2);
  // a saved choice wins over the system and over the page default
  let t3 = open(plainFile, { 'ospf-explorer:theme': 'dark' }, 'light'); await wait(130);
  T.savedDark = snap(t3);
  let t4 = open(plainFile, { 'ospf-explorer:theme': 'light' }); await wait(130);
  T.savedLight = snap(t4);
  let t5 = open(plainFile, { 'ospf-explorer:theme': 'nonsense' }); await wait(130);
  T.junkIgnored = snap(t5);
  // selection and view survive a theme change
  t4.window.document.querySelector('g[data-node="10.255.255.8"]').dispatchEvent(new t4.window.MouseEvent('mousedown', { bubbles: true, button: 0, clientX: 5, clientY: 5 }));
  t4.window.dispatchEvent(new t4.window.MouseEvent('mouseup', { bubbles: true, button: 0, clientX: 5, clientY: 5 }));
  const kBefore = t4.window.__explorer.state.view.k;
  t4.window.document.getElementById('b-theme').click();
  T.selectionKept = !!t4.window.__explorer.state.sel && t4.window.__explorer.state.view.k === kBefore;
  // the SVG download takes the page's background
  t4.window.document.getElementById('b-theme').click(); t4.window.document.getElementById('b-theme').click();   // back to light
  t4.window.document.getElementById('m-svg').click();
  const dl = t4.downloads[t4.downloads.length - 1];
  T.exportBg = (await readBlob(t4.window, dl.blob)).match(/<rect[^>]*fill="(#[0-9a-f]{6})"/)[1];
  for (const x of [t1, t2, t3, t4, t5]) x.window.close();
  // the script in <head> alone (the page's own script removed): no flash of the wrong theme
  const headOnly = fs.readFileSync(plainFile, 'utf8').replace(/<script>\s*\(function \(\) \{\s*'use strict';[\s\S]*<\/script>/, '');
  const headTheme = (page, storage, media) => {
    const vc = new VirtualConsole(); vc.on('jsdomError', e => errors.push(String(e.stack || e)));
    const dm = new JSDOM(page, { runScripts: 'dangerously', url: 'http://localhost/h.html', virtualConsole: vc, beforeParse(w) {
      for (const k of Object.keys(storage || {})) w.localStorage.setItem(k, storage[k]);
      if (media) w.matchMedia = () => ({ matches: media === 'light' });
    } });
    return dm.window.document.documentElement.getAttribute('data-theme');
  };
  T.head = {
    nothing: headTheme(headOnly), autoLight: headTheme(headOnly, null, 'light'), savedLight: headTheme(headOnly, { 'ospf-explorer:theme': 'light' }),
    savedDarkBeatsSystem: headTheme(headOnly, { 'ospf-explorer:theme': 'dark' }, 'light'),
    pageDefaultLight: headTheme(headOnly.replace('data-theme-default="auto"', 'data-theme-default="light"')),
    pageDefaultDark: headTheme(headOnly.replace('data-theme-default="auto"', 'data-theme-default="dark"'), null, 'light'),
    scriptWasRemoved: headOnly.indexOf("'use strict'") < 0,
  };

  out.errors = errors.length; out.errorText = errors.slice(0, 2);
  console.log(JSON.stringify(out));
  process.exit(0);
})();
