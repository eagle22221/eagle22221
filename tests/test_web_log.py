"""The page's notes of requests that never got an answer ("Failed to fetch"):
app.js keeps a short note of each and sends them to POST /api/log once the
server answers again, so that the C edition's vex-log.txt shows both sides.

The code is taken from app.js and run in node with a stand-in fetch() that
can be switched between "the server is gone" and "the server answers".
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

APP_JS = Path(__file__).resolve().parent.parent / "vex" / "web" / "app.js"

HARNESS = r"""
const fs = require('fs');
const src = fs.readFileSync(process.argv[1], 'utf8');
const start = src.indexOf('// A request that fails before any answer arrives');
const end = src.indexOf('function toast(');
if (start < 0 || end < start) throw new Error('the page-log code was not found in app.js');
const timers = [];
const posted = [];
const urls = [];
let mode = 'down';
const state = { token: 'SESSION-TOKEN' };
const fakeFetch = async (url, opts) => {
  urls.push(url);
  if (mode === 'down') throw new TypeError('Failed to fetch');
  if (url === '/api/log') {
    if (opts.headers['X-Vex-Token'] !== state.token) throw new Error('no token');
    posted.push(opts.body);
    return { ok: true, status: 204 };
  }
  if (mode === 'cut') return { ok: true, json: async () => { throw new TypeError('network error'); } };
  return { ok: true, json: async () => ({ fine: true }) };
};
const make = new Function('state', 'fetch', 'setTimeout', 'clearTimeout', 'performance',
  src.slice(start, end) + '\nreturn { api, PAGE_LOG };');
const page = make(state, fakeFetch, (fn) => { timers.push(fn); return timers.length; }, () => {},
  { now: () => 0 });
const settle = () => new Promise((resolve) => setImmediate(resolve));
const report = {};
(async () => {
  for (let i = 0; i < 3; i++) {
    await page.api('info', { path: '/home/someone/secret.exe' }).catch(() => {});
  }
  await page.api('upload', { name: 'x.bin' }, { method: 'POST', body: 'file contents' }).catch(() => {});
  report.notes = JSON.parse(JSON.stringify(page.PAGE_LOG.notes));
  report.timers = timers.length;
  timers.shift()();                       // the retry, while the server is still gone
  await settle(); await settle();
  report.afterRetry = { notes: page.PAGE_LOG.notes.length, tries: page.PAGE_LOG.tries,
    timers: timers.length, posted: posted.length };
  mode = 'up';
  report.answer = await page.api('sections', { path: '/home/someone/secret.exe' });
  await settle(); await settle();
  report.posted = posted.slice();
  report.left = page.PAGE_LOG.notes.length;
  mode = 'cut';
  await page.api('strings', { path: '/x' }).catch(() => {});
  report.cut = JSON.parse(JSON.stringify(page.PAGE_LOG.notes));
  mode = 'down';
  for (let i = 0; i < 30; i++) await page.api(`view${i}`, {}).catch(() => {});
  report.capped = page.PAGE_LOG.notes.length;
  report.urls = urls;
  console.log(JSON.stringify(report));
})().catch((e) => { console.error(e); process.exit(1); });
"""


@pytest.fixture(scope="module")
def report():
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    proc = subprocess.run([node, "-e", HARNESS, str(APP_JS)], capture_output=True, text=True,
                          timeout=60)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def test_a_failed_request_is_noted_once_and_counted(report):
    notes = report["notes"]
    assert [(n["kind"], n["method"], n["api"], n["error"], n["count"]) for n in notes] == [
        ("network", "GET", "info", "TypeError: Failed to fetch", 3),
        ("network", "POST", "upload", "TypeError: Failed to fetch", 1)]
    assert all(isinstance(n["ms"], int) and n["time"].endswith("Z") for n in notes)
    assert report["timers"] == 1                    # one retry is waiting


def test_notes_are_kept_while_the_server_is_still_gone(report):
    assert report["afterRetry"] == {"notes": 2, "tries": 1, "timers": 1, "posted": 0}  # a new retry waits


def test_notes_are_sent_once_the_server_answers_again(report):
    assert report["answer"] == {"fine": True}
    assert len(report["posted"]) == 1 and report["left"] == 0
    sent = json.loads(report["posted"][0])
    assert [e["api"] for e in sent["events"]] == ["info", "upload"]
    assert set(sent["events"][0]) == {"kind", "method", "api", "error", "ms", "count", "time"}
    # never a file path, a request body or the session token
    text = report["posted"][0]
    assert "secret.exe" not in text and "file contents" not in text and "SESSION-TOKEN" not in text
    assert "x.bin" not in text
    assert all(len(json.dumps(v)) <= 202 for e in sent["events"] for v in e.values())


def test_an_answer_cut_short_is_noted_too(report):
    assert [(n["kind"], n["api"], n["error"]) for n in report["cut"]] == [
        ("answer", "strings", "TypeError: network error")]


def test_notes_are_bounded(report):
    assert report["capped"] == 20                   # what POST /api/log takes at most
    assert "/api/log" in report["urls"]
