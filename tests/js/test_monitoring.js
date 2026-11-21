'use strict';
const assert = require('assert');
const fs = require('fs');

const pagePath = process.argv[2];
const html = fs.readFileSync(pagePath, 'utf8');

// 1. Structural markup checks
for (const id of ['btn-events', 'mon-drawer', 'mon-histogram', 'mon-type', 'mon-status', 'mon-search', 'mon-tbody']) {
  assert.ok(html.includes('id="' + id + '"'), 'Missing DOM id #' + id + ' in explorer.html');
}

// 2. Pure Monitoring helper checks extracted between MON-ENGINE markers
assert.ok(html.includes('MON-ENGINE:BEGIN') && html.includes('MON-ENGINE:END'), 'Missing MON-ENGINE markers');
const body = html.split('MON-ENGINE:BEGIN')[1].split('/* MON-ENGINE:END')[0];
const M = new Function(body.slice(body.indexOf('\n')) + '\nreturn { monBuildHistogramBars, monFilterEvents, monFindRunIndex };')();

const series = [
  { ts: '2026-11-21T10:00:00+00:00', total: 4, up: 1, down: 2, changed: 1, critical: 1 },
  { ts: '2026-11-21T11:00:00+00:00', total: 2, up: 2, down: 0, changed: 0, critical: 0 },
];
const bars = M.monBuildHistogramBars(series, 200, 56);
assert.strictEqual(bars.length, 2);
assert.ok(bars[0].downH > bars[0].upH, 'First bar down segment exceeds up segment');

const filtered = M.monFilterEvents([
  { event_type: 'link_down', object_status: 'down', summary: 'Link down R1->R2', detected_by: '10.0.0.1', object_id: '10.0.0.2' },
  { event_type: 'link_up', object_status: 'up', summary: 'Link up R1->R3', detected_by: '10.0.0.1', object_id: '10.0.0.3' },
], 'link_down', '', 'R2');
assert.strictEqual(filtered.length, 1);
assert.strictEqual(filtered[0].object_id, '10.0.0.2');

const idx = M.monFindRunIndex([{ run_id: 'r1' }, { run_id: 'r2' }, { run_id: 'r3' }], 'r2');
assert.strictEqual(idx, 1);

console.log('MONITORING_OK');
