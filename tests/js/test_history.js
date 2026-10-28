// Drives the explorer page's history bar (time travel) in jsdom with a mocked web server and prints JSON.
// Usage: node test_history.js page.html fixture.json
//   fixture.json: { runs: [...newest first, as /api/history returns them], scenes: { run_id: scene } }
const { JSDOM, VirtualConsole } = require('jsdom');
const fs = require('fs');
const [pageFile, fixtureFile] = process.argv.slice(2);
const html = fs.readFileSync(pageFile, 'utf8');
const fixture = JSON.parse(fs.readFileSync(fixtureFile, 'utf8'));
const wait = ms => new Promise(r => setTimeout(r, ms));
const errors = [];

function reply(status, body, delay) {
  return new Promise(res => setTimeout(() => res({ ok: status < 400, status, json: () => Promise.resolve(body) }), delay || 0));
}

function open(url, server) {
  const calls = [];
  const vc = new VirtualConsole();
  vc.on('jsdomError', e => errors.push(String(e.stack || e)));
  const dom = new JSDOM(html, {
    runScripts: 'dangerously', pretendToBeVisual: true, url, virtualConsole: vc,
    beforeParse(w) {
      w.fetch = target => { calls.push(String(target)); return server(String(target)); };
    },
  });
  dom.calls = calls;
  return dom;
}

const healthy = (opts = {}) => target => {
  if (target.startsWith('api/history?')) return reply(200, { status: 'ok', data: { runs: fixture.runs, total: fixture.runs.length } });
  const m = target.match(/^api\/history\/([^/]+)\/scene$/);
  if (m && fixture.scenes[m[1]]) return reply(200, { status: 'ok', data: fixture.scenes[m[1]] }, (opts.delay || {})[m[1]] || 0);
  return reply(404, { status: 'error', error: 'no such run' });
};

const count = w => ({
  svgNodes: w.document.querySelectorAll('g[data-node]').length,
  exported: Object.keys(w.__explorer.nodes).length,
  routers: w.document.getElementById('sim-a').options.length - 1,
  label: w.document.getElementById('h-label').textContent,
  barHidden: w.document.getElementById('hist-bar').classList.contains('hidden'),
});
const sceneRequests = dom => dom.calls.filter(c => c.endsWith('/scene'));
const input = (w, el, value) => { el.value = String(value); el.dispatchEvent(new w.Event('input', { bubbles: true })); };

(async () => {
  const out = {};
  const [oldest, middle] = [fixture.runs[2].run_id, fixture.runs[1].run_id];

  // 1. opened from disk: no request at all, no bar
  let dom = open('file:///tmp/topology.html', healthy()); await wait(100);
  out.file = { calls: dom.calls.length, ...count(dom.window) };

  // 2. over http but nothing behind the page (a plain file server): the bar stays away
  dom = open('http://localhost/topology.html', () => reply(404, { status: 'error', error: 'nope' })); await wait(100);
  out.noApi = { calls: dom.calls.slice(), ...count(dom.window) };

  // 3. served by --serve
  dom = open('http://localhost:8080/', healthy()); let w = dom.window; await wait(100);
  const d = w.document, slider = d.getElementById('h-slider');
  out.live = { calls: dom.calls.slice(), max: slider.max, value: slider.value, disabled: slider.disabled,
    prev: d.getElementById('h-prev').disabled, next: d.getElementById('h-next').disabled, latest: d.getElementById('h-live').disabled, ...count(w) };
  out.liveNodes = out.live.svgNodes;

  // 4. scrub to the oldest run
  input(w, slider, 0); out.immediateLabel = d.getElementById('h-label').textContent;
  await wait(350);
  out.past = { requests: sceneRequests(dom), ...count(w), pastClass: d.getElementById('h-label').className, next: d.getElementById('h-next').disabled };
  const idBefore = w.__explorer.nodes;

  // 5. step forward one run
  d.getElementById('h-next').click(); await wait(350);
  out.stepped = { requests: sceneRequests(dom).slice(-1), ...count(w), sameObject: w.__explorer.nodes === idBefore };

  // 6. back to the latest: the page's own scene, no request
  const before = sceneRequests(dom).length;
  d.getElementById('h-live').click(); await wait(350);
  out.latest = { newRequests: sceneRequests(dom).length - before, ...count(w), pastClass: d.getElementById('h-label').className };

  // 7. a scrub that passes over several runs loads only the one it stops on
  const before7 = sceneRequests(dom).length;
  input(w, slider, 0); input(w, slider, 1); input(w, slider, 0); await wait(350);
  out.debounce = { requests: sceneRequests(dom).slice(before7) };

  // 8. the simulation and selection do not survive the swap
  w.__explorer.simApi.setActive(true);
  input(w, slider, 1); await wait(350);
  out.simAfterSwap = { active: w.__explorer.sim.active, selection: w.__explorer.state.sel };

  // 9. a slow answer for a run the user has already left is ignored
  dom = open('http://localhost:8080/', healthy({ delay: { [oldest]: 400 } })); w = dom.window; await wait(100);
  input(w, w.document.getElementById('h-slider'), 0); await wait(250);      // asks for the oldest (slow)
  input(w, w.document.getElementById('h-slider'), 1); await wait(250);      // moves on to the middle one (fast)
  const middleNodes = count(w).svgNodes;
  await wait(400);                                                          // the slow answer arrives now
  out.stale = { middleNodes, afterNodes: count(w).svgNodes, label: count(w).label };

  // 10. the server fails on a scene: the user is told, the page keeps what it showed
  dom = open('http://localhost:8080/', target => target.endsWith('/scene') ? reply(500, { status: 'error', error: 'boom' }) : healthy()(target));
  w = dom.window; await wait(100);
  input(w, w.document.getElementById('h-slider'), 0); await wait(350);
  out.failure = { toast: w.document.getElementById('toast').textContent, ...count(w) };

  // 11. a single recorded run: the slider is there but cannot move
  dom = open('http://localhost:8080/', target => target.startsWith('api/history?')
    ? reply(200, { status: 'ok', data: { runs: fixture.runs.slice(0, 1), total: 1 } }) : reply(404, {})); w = dom.window; await wait(100);
  out.single = { disabled: w.document.getElementById('h-slider').disabled, ...count(w) };

  out.errors = errors;
  console.log(JSON.stringify(out));
})();
