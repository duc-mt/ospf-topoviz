'use strict';
/*
 * CLI runbook and documentation spec of src/web/explorer.html.
 *
 *   node tests/js/test_explorer_docs.js        (run from the project root)
 *
 * The two pure blocks of the page (between RUNBOOK:BEGIN/END and SPEC:BEGIN/END) are cut out and run on their own,
 * on the scene made by tests/js/make_scene.py, so this needs no browser and no npm packages.
 */
const assert = require('assert');
const cp = require('child_process');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..', '..');
const page = fs.readFileSync(path.join(root, 'src', 'web', 'explorer.html'), 'utf8');
const made = cp.spawnSync('python3', [path.join(__dirname, 'make_scene.py')], {
  cwd: root, env: Object.assign({}, process.env, { PYTHONPATH: root }), encoding: 'utf8', maxBuffer: 64 * 1024 * 1024
});
if (made.status !== 0) { console.error('Could not build the fixture:\n' + (made.stderr || made.error)); process.exit(2); }
const scene = JSON.parse(made.stdout).scene;

const block = (name) => { const s = page.split(name + ':BEGIN')[1].split('/* ' + name + ':END')[0]; return s.slice(s.indexOf('\n')); };
const R = new Function(block('RUNBOOK') + '\nreturn { CLI_VENDORS, CLI_TABLE, cliGuess, cliRunbook };')();
const S = new Function(block('SPEC') + '\nreturn { buildSpec, specIsBridge, mdCell };')();

let passed = 0, failed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log('  ok    ' + name); } catch (e) { failed++; console.log('  FAIL  ' + name + '\n        ' + String(e && e.message).split('\n').join('\n        ')); }
}
const cmds = (blocks) => blocks.reduce((a, b) => a.concat(b.cmds), []);

console.log('CLI runbook');
test('every platform in the list has every command of the table', () => {
  assert.deepStrictEqual(R.CLI_VENDORS.map((v) => v[0]).sort(), Object.keys(R.CLI_TABLE).sort());
  Object.keys(R.CLI_TABLE).forEach((v) => assert.deepStrictEqual(Object.keys(R.CLI_TABLE[v]).sort(), ['ifOne', 'ifs', 'lsa', 'nbr', 'nbrIf', 'net', 'rib'], v));
});
test('the platform is guessed from the device type of the run', () => {
  const g = R.cliGuess;
  assert.strictEqual(g('cisco_ios'), 'cisco_ios'); assert.strictEqual(g('cisco_nxos'), 'cisco_nxos'); assert.strictEqual(g('arista_eos'), 'arista_eos');
  assert.strictEqual(g('juniper_junos'), 'juniper_junos'); assert.strictEqual(g('vyos'), 'vyos'); assert.strictEqual(g('huawei'), 'huawei');
  assert.strictEqual(g(''), null); assert.strictEqual(g('aruba_aoscx'), null);
});
test('OSPF link: Cisco shows the neighbour of that interface, Junos the extensive form', () => {
  const ctx = { kind: 'link', ends: [{ device: 'R1', rid: '10.0.0.1', iface: 'Gi0/0/1' }, { device: 'R2', rid: '10.0.0.2', iface: 'ge-0/0/1' }] };
  const cisco = cmds(R.cliRunbook('cisco_ios', ctx));
  assert.ok(cisco.includes('show ip ospf neighbor Gi0/0/1 detail') && cisco.includes('show ip ospf interface Gi0/0/1'), cisco.join(' | '));
  const junos = cmds(R.cliRunbook('juniper_junos', ctx));
  assert.ok(junos.includes('show ospf neighbor interface ge-0/0/1 extensive'), junos.join(' | '));
  assert.strictEqual(R.cliRunbook('cisco_ios', ctx).length, 2, 'one block per router end');
});
test('a router: neighbours, its own router LSA by router ID, and the OSPF routes, on all six platforms', () => {
  const want = { cisco_ios: 'show ip ospf database router adv-router 10.0.0.1', cisco_nxos: 'show ip ospf database router adv-router 10.0.0.1', arista_eos: 'show ip ospf database router adv-router 10.0.0.1',
    juniper_junos: 'show ospf database router advertising-router 10.0.0.1 extensive', vyos: 'show ip ospf database router adv-router 10.0.0.1', huawei: 'display ospf lsdb router 10.0.0.1' };
  Object.keys(want).forEach((v) => {
    const c = cmds(R.cliRunbook(v, { kind: 'node', rid: '10.0.0.1', name: 'R1' }));
    assert.ok(c.includes(want[v]), v + ': ' + c.join(' | ')); assert.strictEqual(c.length, 4, v);
    assert.ok(c.every((x) => !/[{}]/.test(x)), 'no placeholder left over: ' + c.join(' | '));
  });
});
test('an unknown interface keeps a visible placeholder instead of an empty argument', () => {
  const c = cmds(R.cliRunbook('cisco_ios', { kind: 'link', ends: [{ device: 'R1', rid: '10.0.0.1', iface: null }] }));
  assert.ok(c.includes('show ip ospf neighbor <intf> detail'), c.join(' | '));
});
test('a transit network gets the network LSA command', () => {
  assert.deepStrictEqual(cmds(R.cliRunbook('huawei', { kind: 'network', name: 'net 192.168.1.0/24' })), ['display ospf lsdb network']);
});

console.log('documentation spec (TOPOLOGY_SPEC.md)');
const md = S.buildSpec(scene, { vendor: 'Cisco IOS' });
const rowsOf = (title) => { const part = md.split('## ' + title)[1].split('\n## ')[0]; return part.split('\n').filter((l) => l.startsWith('|')).slice(2); };
test('the device table has the five columns asked for and one row per node', () => {
  assert.ok(md.includes('| Hostname | IP / Router ID | Role / Tier | Vendor | Software version |'));
  assert.strictEqual(rowsOf('Devices').length, scene.nodes.length);
  assert.ok(rowsOf('Devices').some((r) => r.includes('10.0.0.3') && r.includes('ABR') && r.includes('Cisco IOS')));
});
test('the link matrix lists each router end with its interface, remote device, cost and redundancy', () => {
  assert.ok(md.includes('| Local device | Local interface | Remote device | Remote interface | Cost (local \u2192 remote) | Adjacency | Redundancy |'));
  const rows = rowsOf('Link interconnect matrix');
  assert.ok(rows.length >= scene.links.length, rows.length + ' rows for ' + scene.links.length + ' links');
  assert.ok(rows.some((r) => r.includes('Single path (SPOF)')) && rows.some((r) => r.includes('Redundant (alternate path exists)')) && rows.some((r) => r.includes('One-way')));
});
test('a bridge is a single path; a cycle is redundant; parallel links are never a bridge', () => {
  const link = (a, b) => scene.links.find((l) => (l.a === '10.0.0.' + a && l.b === '10.0.0.' + b) || (l.a === '10.0.0.' + b && l.b === '10.0.0.' + a));
  assert.strictEqual(S.specIsBridge(scene, link(4, 7)), true);       // R7 hangs off R4 only
  assert.strictEqual(S.specIsBridge(scene, link(1, 2)), false);      // R1-R2-R4-R3 is a ring
  assert.strictEqual(S.specIsBridge(scene, Object.assign({}, link(4, 7), { parallel: 2 })), false);
});
test('parallel links are listed with the cost and address of each', () => {
  const s = JSON.parse(JSON.stringify(scene)), l = s.links.find((x) => x.a === '10.0.0.1' && x.b === '10.0.0.2');
  l.parallel = 2; l.members = [{ metric: 10, ip: '10.1.1.1' }, { metric: 30, ip: '10.1.2.1' }];
  const text = S.buildSpec(s, {});
  assert.ok(text.includes('### Parallel links') && text.includes('cost 10 (10.1.1.1), cost 30 (10.1.2.1)'), text.slice(text.indexOf('### Parallel')));
  assert.ok(text.includes('Bundle \u00d72'));
});
test('the snapshot decides what is listed: removed items leave the current spec, added ones the previous spec', () => {
  const s = JSON.parse(JSON.stringify(scene));
  s.nodes.find((n) => n.id === '10.0.0.7').status = 'removed'; s.nodes.find((n) => n.id === '10.0.0.8').status = 'added';
  s.diagnostics.changes = { baseline: true, addedNodes: ['10.0.0.8'], removedNodes: ['10.0.0.7'], addedLinks: 0, removedLinks: 0, metricChanges: 0 };
  const cur = S.buildSpec(s, { time: 'current' }), prev = S.buildSpec(s, { time: 'previous' });
  assert.ok(!cur.includes('| 10.0.0.7 |') && cur.includes('| 10.0.0.8 |'));
  assert.ok(prev.includes('| 10.0.0.7 |') && !prev.includes('| 10.0.0.8 |'));
  assert.ok(cur.includes('## Changes since the previous snapshot') && cur.includes('Added devices: 10.0.0.8') && cur.includes('Removed devices: 10.0.0.7'));
});
test('a changed cost shows the old one, and pipes or line breaks in names cannot break a table', () => {
  const s = JSON.parse(JSON.stringify(scene)), l = s.links.find((x) => x.a === '10.0.0.1' && x.b === '10.0.0.2');
  l.ends[0].old = 10; l.ends[0].new = 40; s.nodes.find((n) => n.id === '10.0.0.2').title = 'edge|2\nname';
  const text = S.buildSpec(s, {});
  assert.ok(text.includes('40 (was 10)'), 'cost'); assert.ok(text.includes('edge\\|2 name'), 'name');
  assert.strictEqual(S.mdCell(''), '\u2014'); assert.strictEqual(S.mdCell(null), '\u2014');
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
