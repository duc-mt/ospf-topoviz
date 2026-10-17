'use strict';
/*
 * What-if simulation tests for src/web/explorer.html.
 *
 *   node tests/js/test_simulation.js        (run from the project root)
 *
 * 1. The engine block of the page (between SIM-ENGINE:BEGIN and SIM-ENGINE:END) is cut out and run on its own,
 *    on a scene made by tests/js/make_scene.py, so it needs no browser and no npm packages.
 * 2. Its Dijkstra is held against the Python SPF (correlation.spf) on that same scene, from every router.
 * 3. If `jsdom` can be resolved (it is optional), the real page is loaded and driven: toolbar, overlay, popovers,
 *    reset and exit. Without it that part is reported as skipped.
 *
 * The network drawn by make_scene.py: R1 -> R4 costs 20 via R2 (the detour via R3 costs 40), R7 hangs off R4 only,
 * R1 -> R10 has two equal paths, R1 <-> R12 is asymmetric, R4/R5/R6 share a transit network, R6 -> R10 is one-way.
 */
const assert = require('assert');
const cp = require('child_process');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..', '..');
const page = fs.readFileSync(path.join(root, 'src', 'web', 'explorer.html'), 'utf8');

// ---------------------------------------------------------------- fixture (Python builds the scene)
const made = cp.spawnSync('python3', [path.join(__dirname, 'make_scene.py')], {
  cwd: root, env: Object.assign({}, process.env, { PYTHONPATH: root }), encoding: 'utf8', maxBuffer: 64 * 1024 * 1024
});
if (made.status !== 0) {
  console.error('Could not build the fixture with python3 tests/js/make_scene.py:\n' + (made.stderr || made.error));
  process.exit(2);
}
const fixture = JSON.parse(made.stdout);
const scene = fixture.scene;

// ---------------------------------------------------------------- the engine block, on its own
const body = page.split('SIM-ENGINE:BEGIN')[1].split('/* SIM-ENGINE:END')[0];
const E = new Function(body.slice(body.indexOf('\n')) + `
  return { SIM_MAX_METRIC, makeGraphModel, computeShortestPaths, dijkstra, simAnalyze, simDrainImpact, simSetModel, simCountPaths, simPaths };`)();

const R = (n) => '10.0.0.' + n;
const NET = 'net-192.168.1.1';
const short = (id) => (id === NET ? 'net' : id.replace('10.0.0.', 'R'));
const route = (p) => p.nodes.map(short).join('>');
function linkId(a, b) {
  const x = a === 'net' ? NET : R(a), y = b === 'net' ? NET : R(b);
  const l = scene.links.find((k) => (k.a === x && k.b === y) || (k.a === y && k.b === x));
  assert.ok(l, `no link ${a}-${b} in the scene`);
  return l.id;
}
function state(over) {
  return Object.assign({ disabledLinks: new Set(), disabledNodes: new Set(), costOverrides: new Map(), drainedNodes: new Set(), sourceNode: null, targetNode: null }, over || {});
}
const M = E.makeGraphModel(scene);
E.simSetModel(M);
const run = (src, dst, s) => { s = s || state(); return E.dijkstra(R(src), R(dst), s.disabledLinks, s.disabledNodes, s.costOverrides, M, s.drainedNodes); };

let passed = 0, failed = 0, skipped = 0;
function test(name, fn) {
  try { fn(); passed++; console.log('  ok    ' + name); } catch (e) { failed++; console.log('  FAIL  ' + name + '\n        ' + String(e && e.message).split('\n').join('\n        ')); }
}

console.log('engine (Dijkstra, ECMP, what-if state)');
test('baseline: R1 -> R4 costs 20 over R2, a single path', () => {
  const r = run(1, 4);
  assert.strictEqual(r.cost, 20); assert.strictEqual(r.ecmp, 1); assert.deepStrictEqual(r.paths.map(route), ['R1>R2>R4']);
});
test('1. shutting the primary link redirects the path over the secondary', () => {
  const s = state({ disabledLinks: new Set([linkId(2, 4)]) });
  const r = run(1, 4, s);
  assert.strictEqual(r.cost, 40); assert.deepStrictEqual(r.paths.map(route), ['R1>R3>R4']);
  const a = E.simAnalyze(M, Object.assign(s, { sourceNode: R(1), targetNode: R(4) }));
  assert.ok(a.pathChanged && a.lost.includes(linkId(2, 4)) && a.gained.includes(linkId(1, 3)));
});
test('2. a cost above the alternative swaps the route; an equal cost splits it (ECMP)', () => {
  const swap = state({ costOverrides: new Map([[linkId(1, 2), { forwardCost: 40 }]]) });   // R1 -> R2: 40 + 10 > 40
  assert.deepStrictEqual(run(1, 4, swap).paths.map(route), ['R1>R3>R4']); assert.strictEqual(run(1, 4, swap).cost, 40);
  const tie = state({ costOverrides: new Map([[linkId(1, 2), { forwardCost: 30 }]]) });   // 30 + 10 == 40
  const r = run(1, 4, tie);
  assert.strictEqual(r.cost, 40); assert.strictEqual(r.ecmp, 2); assert.deepStrictEqual(r.paths.map(route).sort(), ['R1>R2>R4', 'R1>R3>R4']);
});
test('2b. a cost changed in one direction only moves the traffic in that direction', () => {
  const s = state({ costOverrides: new Map([[linkId(1, 2), { reverseCost: 40 }]]) });    // R2 -> R1 only
  assert.deepStrictEqual(run(1, 4, s).paths.map(route), ['R1>R2>R4']);                   // R1 -> R4 untouched
  assert.deepStrictEqual(run(4, 1, s).paths.map(route), ['R4>R3>R1']);                   // R4 -> R1 leaves R2
  const a = E.simAnalyze(M, Object.assign(s, { sourceNode: R(1), targetNode: R(4) }));
  assert.ok(a.asymmetric, 'forward over R2, reverse over R3');
});
test('3. shutting every link to a stub router makes it UNREACHABLE', () => {
  const s = state({ disabledLinks: new Set([linkId(4, 7)]), sourceNode: R(1), targetNode: R(7) });
  const r = run(1, 7, s);
  assert.strictEqual(r.reachable, false); assert.strictEqual(r.cost, Infinity); assert.strictEqual(r.ecmp, 0); assert.deepStrictEqual(r.paths, []);
  const a = E.simAnalyze(M, s);
  assert.strictEqual(a.forward.after.reachable, false); assert.strictEqual(a.forward.before.reachable, true);
  assert.deepStrictEqual(a.isolated, [R(7)]);
});
test('4. resetting the changes restores the baseline paths and costs', () => {
  const s = state({ disabledLinks: new Set([linkId(2, 4)]), disabledNodes: new Set([R(3)]), drainedNodes: new Set([R(8)]), costOverrides: new Map([[linkId(1, 2), { forwardCost: 99 }]]) });
  assert.ok(run(1, 4, s).cost !== 20 || !run(1, 4, s).reachable);
  s.disabledLinks.clear(); s.disabledNodes.clear(); s.drainedNodes.clear(); s.costOverrides.clear();
  const r = run(1, 4, s);
  assert.strictEqual(r.cost, 20); assert.deepStrictEqual(r.paths.map(route), ['R1>R2>R4']);
  assert.strictEqual(E.simAnalyze(M, Object.assign(s, { sourceNode: R(1), targetNode: R(4) })).changes, 0);
});
test('max-metric drains a link but keeps the destination reachable when no other path exists', () => {
  const s = state({ costOverrides: new Map([[linkId(4, 7), { forwardCost: 65535, reverseCost: 65535 }]]) });
  const r = run(1, 7, s);
  assert.ok(r.reachable); assert.strictEqual(r.cost, 20 + 65535);
});
test('draining a router (max-metric LSA) moves transit away but keeps the router itself reachable', () => {
  const s = state({ drainedNodes: new Set([R(2)]) });
  assert.deepStrictEqual(run(1, 4, s).paths.map(route), ['R1>R3>R4']); assert.strictEqual(run(1, 4, s).cost, 40);
  assert.strictEqual(run(1, 2, s).cost, 10);        // R2's own address is still reached at its normal price
  assert.strictEqual(run(2, 1, s).cost, 65535);     // ... but R2 itself advertises 65535 on its links
});
test('ECMP: two equal paths, and what is left after shutting one', () => {
  const r = run(1, 10);
  assert.strictEqual(r.cost, 10); assert.strictEqual(r.ecmp, 2); assert.strictEqual(r.paths.length, 2);
  const one = run(1, 10, state({ disabledLinks: new Set([linkId(1, 8)]) }));
  assert.strictEqual(one.ecmp, 1); assert.deepStrictEqual(one.paths.map(route), ['R1>R9>R10']);
  assert.strictEqual(run(1, 10, state({ disabledLinks: new Set([linkId(1, 8), linkId(1, 9)]) })).reachable, false);
});
test('asymmetric routing: forward and reverse take different routes, and it goes away when the cause does', () => {
  const s = state({ sourceNode: R(1), targetNode: R(12) });
  const a = E.simAnalyze(M, s);
  assert.deepStrictEqual(a.forward.after.paths.map(route), ['R1>R11>R12']);
  assert.deepStrictEqual(a.reverse.after.paths.map(route), ['R12>R1']);
  assert.ok(a.asymmetric);
  s.disabledLinks.add(linkId(1, 11));
  assert.strictEqual(E.simAnalyze(M, s).asymmetric, false);
});
test('a router that is down cuts off whatever hangs only off it', () => {
  const s = state({ disabledNodes: new Set([R(4)]), sourceNode: R(1), targetNode: R(7) });
  const a = E.simAnalyze(M, s);
  assert.deepStrictEqual(a.down, [R(4)]);
  assert.deepStrictEqual(a.isolated.slice().sort(), [R(5), R(6), R(7), NET].sort());
  assert.strictEqual(a.forward.after.reachable, false);
});
test('a source that is down reaches nothing', () => {
  const a = E.simAnalyze(M, state({ disabledNodes: new Set([R(1)]), sourceNode: R(1), targetNode: R(4) }));
  assert.ok(a.sourceDown); assert.strictEqual(a.forward.after.reachable, false);
});
test('a transit network is a node: R5 -> R6 crosses it for the cost of R5\'s own interface', () => {
  const r = run(5, 6);
  assert.strictEqual(r.cost, 3); assert.deepStrictEqual(r.paths.map(route), ['R5>net>R6']);
  assert.strictEqual(run(6, 5).cost, 7);
});
test('the cost of the attachment (network -> router) cannot be tuned', () => {
  const s = state({ costOverrides: new Map([[linkId(5, 'net'), { reverseCost: 500 }]]) });   // net -> R5 is the attachment
  assert.strictEqual(run(4, 5, s).cost, run(4, 5).cost);
});
test('a one-way link is never used by the SPF', () => {
  assert.strictEqual(run(1, 10).cost, 10);
  assert.strictEqual(run(6, 10).cost, 37);          // R6 -> segment -> R4 -> R2 -> R1 -> R8 -> R10, not the one-way link
});
test('a scene without the exported `spf` costs gives the same distances (derived from the link ends)', () => {
  const bare = JSON.parse(JSON.stringify(scene)); bare.links.forEach((l) => delete l.spf);
  const B = E.makeGraphModel(bare);
  scene.nodes.filter((n) => n.kind === 'router').forEach((n) => {
    assert.deepStrictEqual(E.computeShortestPaths(n.id, B, null).dist, E.computeShortestPaths(n.id, M, null).dist, n.id);
  });
});
test('drain impact: what hangs only off the drained router, and what does not', () => {
  const four = E.simDrainImpact(M, R(4), R(1), state());
  assert.deepStrictEqual(four.stranded.slice().sort(), [R(5), R(6), R(7)].sort()); assert.strictEqual(four.strandedPrefixes, 2);
  const two = E.simDrainImpact(M, R(2), R(1), state());
  assert.deepStrictEqual(two.stranded, []); assert.deepStrictEqual(two.stillTransit, []);
});

console.log('parity with the Python SPF (correlation.spf) on the exported scene');
test('every router, every node: same distances', () => {
  const sources = Object.keys(fixture.expected);
  assert.ok(sources.length >= 12);
  sources.forEach((src) => {
    const js = E.computeShortestPaths(src, M, null).dist;
    Object.keys(M.nodes).forEach((id) => {
      const want = fixture.expected[src][id];
      assert.strictEqual(js[id], want === undefined ? Infinity : want, `${short(src)} -> ${short(id)}`);
    });
  });
});

console.log('performance');
test('a 200-router network: the full what-if analysis stays under 10 ms', () => {
  const nodes = [], links = [], N = 200;
  for (let i = 0; i < N; i++) nodes.push({ id: 'r' + i, kind: 'router', title: 'r' + i });
  const add = (a, b, m) => links.push({ id: a + '|' + b, a: a, b: b, kind: 'p2p', spf: { ab: m, ba: m } });
  for (let i = 0; i < N; i++) add('r' + i, 'r' + ((i + 1) % N), 1 + (i % 7));
  for (let i = 0; i < N; i += 3) add('r' + i, 'r' + ((i * 7 + 11) % N === i ? (i + 5) % N : (i * 7 + 11) % N), 4 + (i % 5));
  const big = E.makeGraphModel({ nodes: nodes, links: links });
  const s = state({ sourceNode: 'r0', targetNode: 'r100', disabledLinks: new Set(['r0|r1']), costOverrides: new Map([['r5|r6', { forwardCost: 500 }]]) });
  const timed = () => { const t = process.hrtime.bigint(); E.simAnalyze(big, s); return Number(process.hrtime.bigint() - t) / 1e6; };
  const cold = timed();                                          // first call: the JS engine is still compiling the code
  for (let i = 0; i < 5; i++) timed();
  const times = [];
  for (let i = 0; i < 50; i++) times.push(timed());
  times.sort((a, b) => a - b);
  const median = times[25], p95 = times[47];
  console.log(`        simAnalyze on ${N} routers (4 Dijkstra runs): cold first call ${cold.toFixed(2)} ms, then median ${median.toFixed(2)} ms, p95 ${p95.toFixed(2)} ms`);
  assert.ok(cold < 50, 'cold ' + cold + ' ms');
  assert.ok(median < 10 && p95 < 10, 'median ' + median + ' ms, p95 ' + p95 + ' ms');
});

// ---------------------------------------------------------------- the real page, if jsdom is around
console.log('page (jsdom)');
let JSDOM = null;
try { JSDOM = require('jsdom').JSDOM; } catch (e) { /* optional */ }
if (!JSDOM) {
  skipped++; console.log('  skip  jsdom is not installed (npm i jsdom in tests/js, or set NODE_PATH): the page itself was not exercised');
} else {
  const errors = [];
  const { VirtualConsole } = require('jsdom');
  const vc = new VirtualConsole(); vc.on('jsdomError', (e) => errors.push(String(e && e.stack || e)));
  const dom = new JSDOM(fixture.html, { runScripts: 'dangerously', pretendToBeVisual: true, url: 'http://localhost/', virtualConsole: vc });
  const w = dom.window, d = w.document, X = w.__explorer, api = X.simApi;
  const $ = (id) => d.getElementById(id);
  const count = (sel) => d.querySelectorAll(sel).length;
  const bar = () => $('sim-metrics').textContent + ' | ' + $('sim-diff').textContent;
  const fire = (el, type) => el.dispatchEvent(new w.MouseEvent(type, { bubbles: true, cancelable: true, button: 0, clientX: 300, clientY: 200 }));
  const click = (el) => { fire(el, 'mousedown'); fire(el, 'mouseup'); };
  const world = () => JSON.stringify([X.nodes, X.links].map((o) => Object.keys(o).map((k) => [k, o[k].x, o[k].y, o[k].spf, o[k].metric])));

  test('loads without script errors; simulation is off and draws nothing', () => {
    assert.deepStrictEqual(errors, []);
    assert.strictEqual(X.sim.active, false); assert.ok(!$('sim-bar').classList.contains('on'));
    assert.strictEqual(count('.sim-path-active, .sim-disabled, .sim-overridden'), 0);
  });
  const before = world();
  test('Simulate shows the banner; picking A and B draws the live path with the cost', () => {
    $('b-sim').click();
    assert.ok(X.sim.active && $('sim-bar').classList.contains('on') && $('b-sim').classList.contains('on'));
    assert.ok(d.querySelector('.sim-badge').textContent.includes('SIMULATION MODE ACTIVE'));
    $('sim-a').value = R(1); $('sim-a').dispatchEvent(new w.Event('change'));
    $('sim-b').value = R(4); $('sim-b').dispatchEvent(new w.Event('change'));
    assert.strictEqual(X.sim.sourceNode, R(1)); assert.strictEqual(X.sim.targetNode, R(4));
    assert.strictEqual(count('.sim-path-active'), 2);            // R1-R2, R2-R4
    assert.ok(bar().includes('Cost: 20 (unchanged)') && bar().includes('Path unchanged'), bar());
  });
  test('shutting the primary link: X on the link, old path faded, cost 20 -> 40', () => {
    api.toggleLink(linkId(2, 4));
    assert.ok(count('.sim-disabled') >= 1 && count('.sim-lost') >= 1);
    assert.strictEqual(count('.sim-path-active'), 2);            // now R1-R3, R3-R4
    assert.ok(bar().includes('Cost: 20 \u2192 40 (+20)') && bar().includes('Path changed'), bar());
    assert.ok($('sim-changes').textContent.includes('Link down'));
  });
  test('a cost change shows an old -> new pill on the link', () => {
    api.toggleLink(linkId(2, 4));                                 // back up
    assert.strictEqual(api.setCost(linkId(1, 2), 'ab', 40), true);
    assert.ok(count('.sim-overridden') === 1 && d.querySelector('.sim-overridden').textContent.includes('10\u219240'));
    assert.strictEqual(api.setCost(linkId(1, 2), 'ab', 0), false);              // rejected: 1..65535 only
    assert.strictEqual(api.setCost(linkId(1, 2), 'ab', 10), true);              // the real cost again = no change
    assert.strictEqual(count('.sim-overridden'), 0); assert.strictEqual(X.sim.costOverrides.size, 0);
  });
  test('cutting everything to a stub: UNREACHABLE banner, isolated node flagged', () => {
    api.setTarget(R(7)); api.toggleLink(linkId(4, 7));
    assert.ok(bar().includes('UNREACHABLE'), bar());
    assert.ok($('sim-metrics').textContent.includes('isolated'));
    assert.ok(d.querySelector('#simtop rect[stroke-dasharray]'), 'red ring around the isolated router');
    assert.ok($('simside').textContent.includes('Simulation active'));
  });
  test('asymmetric routing is flagged with forward (cyan) and reverse (magenta) paths', () => {
    api.reset(); api.setSource(R(1)); api.setTarget(R(12));
    assert.ok(bar().includes('Asymmetric Routing Detected'), bar());
    assert.ok(count('.sim-path-active') >= 1 && count('.sim-path-rev') >= 1);
    assert.strictEqual(d.querySelector('.sim-path-active').getAttribute('stroke'), X.palette().simPath);
    assert.strictEqual(d.querySelector('.sim-path-rev').getAttribute('stroke'), X.palette().simRev);
  });
  test('draw colours follow the theme (light palette after the theme button)', () => {
    $('b-theme').click();                                         // auto -> light
    assert.strictEqual(d.documentElement.getAttribute('data-theme'), 'light');
    assert.strictEqual(d.querySelector('.sim-path-active').getAttribute('stroke'), '#0284c7');
    $('b-theme').click(); $('b-theme').click();                  // light -> dark -> auto
  });
  test('clicking a router opens its popover: set A / set B / node down / drain', () => {
    api.reset(); api.setSource(null); api.setTarget(null);
    click(d.querySelector(`[data-node="${R(2)}"] rect`));
    const pop = $('sim-pop');
    assert.strictEqual(pop.style.display, 'block');
    const labels = [...pop.querySelectorAll('button')].map((b) => b.textContent);
    ['Set as Path Source (A)', 'Set as Path Target (B)', 'Toggle Node Down (reboot / outage)', 'Set Max-Metric Router LSA (Drain Router)'].forEach((t) => assert.ok(labels.includes(t), t + ' in ' + labels));
    [...pop.querySelectorAll('button')].find((b) => b.textContent === 'Set as Path Source (A)').click();
    assert.strictEqual(X.sim.sourceNode, R(2));
    [...pop.querySelectorAll('button')].find((b) => b.textContent.startsWith('Set Max-Metric Router LSA')).click();
    assert.ok(X.sim.drainedNodes.has(R(2)) && d.querySelector('#simtop').textContent.includes('DRAIN 65535'));
    assert.ok(pop.querySelector('.note'), 'drain impact is spelled out');
  });
  test('clicking a link opens its popover: toggle, set cost, max-metric', () => {
    api.reset();
    click(d.querySelector(`[data-link="${linkId(1, 3)}"] .hit`));
    const pop = $('sim-pop'), labels = [...pop.querySelectorAll('button')].map((b) => b.textContent);
    assert.strictEqual(pop.style.display, 'block');
    ['Toggle Link Down (shut)', 'Set', 'Set Max-Metric (65535)'].forEach((t) => assert.ok(labels.includes(t), t + ' in ' + labels));
    [...pop.querySelectorAll('button')].find((b) => b.textContent === 'Set Max-Metric (65535)').click();
    assert.strictEqual(JSON.stringify(X.sim.costOverrides.get(linkId(1, 3))), JSON.stringify({ forwardCost: 65535, reverseCost: 65535 }));
    assert.ok(d.querySelector('.sim-overridden').textContent.includes('65535'));
  });
  test('Reset Simulation brings back the real network; nothing of the scene was touched', () => {
    $('sim-reset').click();
    assert.strictEqual(simCount(), 0); assert.strictEqual(count('.sim-disabled, .sim-overridden, .sim-lost'), 0);
    assert.strictEqual($('sim-pop').style.display, 'none');
    assert.strictEqual(world(), before, 'positions, costs and spf of every node and link are unchanged');
  });
  test('Exit leaves simulation mode and clears everything', () => {
    api.setSource(R(1)); api.setTarget(R(4)); api.toggleLink(linkId(2, 4));
    $('sim-exit').click();
    assert.strictEqual(X.sim.active, false); assert.ok(!$('sim-bar').classList.contains('on'));
    assert.strictEqual(count('.sim-path-active, .sim-disabled, .sim-overridden, .sim-lost'), 0);
    assert.strictEqual(simCount(), 0); assert.strictEqual(X.sim.sourceNode, null);
  });
  test('outside simulation mode clicking a router opens no popover', () => {
    click(d.querySelector(`[data-node="${R(2)}"] rect`));
    assert.notStrictEqual($('sim-pop').style.display, 'block');
  });
  test('the sidebar shows the area coverage status (an area hides behind ABR R3)', () => {
    const cards = [...d.querySelectorAll('#diag .card.ac')].map((c) => c.textContent);
    assert.ok(cards.some((t) => t.includes('An area behind an ABR is not polled') && t.includes(R(3))), cards.join(' | '));
  });
  test('no script errors at any point', () => assert.deepStrictEqual(errors, []));
  function simCount() { const s = X.sim; return s.disabledLinks.size + s.disabledNodes.size + s.costOverrides.size + s.drainedNodes.size; }
}

console.log(`\n${passed} passed, ${failed} failed${skipped ? ', ' + skipped + ' skipped' : ''}`);
process.exit(failed ? 1 : 0);
