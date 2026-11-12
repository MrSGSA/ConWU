// Exercise production rendering with independently changing network log sources.
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const { chromium } = require(process.env.CONWU_BROWSER_TOOLS || path.resolve(root, '../StreamLink/out/browser-tools/node_modules/playwright'));
const assets = path.join(root, 'src/StreamLink.Web/wwwroot');
const settings = { service: '', pathSelection: 'faketcp-only', connectionSource: 'existing', directMode: true, listenPort: 44680, sourcePort: 44691, existingEntries: [], tcpStun: [], udpStun: [], coordinator: { enabled: false } };
const status = { version: 'test', deviceName: 'Log fixture', state: '就绪', serviceReady: true, networkEnabled: false, directPeers: 0, totalPeers: 0, peers: [], logLevel: 'info', settings, settingsRevision: '1', logs: [], logEntries: [] };
const baseTime = Date.parse('2026-11-10T15:59:59Z');
const event = (id, text, offset = 0) => ({ id, timestamp: baseTime + offset, text });
const model = { ...status, workspaceVersion: 2, selectedNetworkId: '', networks: [], configurations: [], deviceSettings: settings, networkDefaults: settings, deviceSettingsRevision: '1', desktop: { autoStart: false, serviceRegistered: true }, aggregate: { sentBytes: 0, receivedBytes: 0 } };
model.logEntries = [event('device:1', '23:59:59 [INFO] 控制服务启动')];
model.networks = [
  { id: 'alpha', name: '主机 A', status: { ...status, networkId: 'a', logEntries: [event('alpha:1', '23:59:59 [WARN] 对端暂不可用')] } },
  { id: 'beta', name: '主机 B', status: { ...status, networkId: 'b', logEntries: [event('beta:1', '00:00:00 [INFO] 双向连接已恢复', 1000)] } }
];
const checks = [], errors = [];
function check(value, message) {
  if (!value) throw Error(message);
  checks.push(message);
  console.log('PASS ' + message);
}

(async () => {
  const browser = await chromium.launch({ executablePath: 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', headless: true });
  const page = await browser.newPage();
  page.on('pageerror', error => errors.push(error.message));
  await page.route('https://conwu.test/**', async route => {
    const url = new URL(route.request().url());
    if (url.pathname === '/api/session') return route.fulfill({ json: { csrf: 'fixture' } });
    if (url.pathname === '/api/status') return route.fulfill({ json: { ok: true, status: model } });
    return route.fulfill({ path: path.join(assets, url.pathname === '/' ? 'index.html' : url.pathname), contentType: url.pathname.endsWith('.js') ? 'application/javascript' : url.pathname.endsWith('.css') ? 'text/css' : url.pathname.endsWith('.svg') ? 'image/svg+xml' : 'text/html' });
  });
  async function show() {
    await page.evaluate(snapshot => render(snapshot), model);
  }
  async function count() {
    return page.locator('#terminal-lines .log-entry').count();
  }
  try {
    await page.goto('https://conwu.test/#' + 'A'.repeat(64));
    await page.waitForFunction(() => online);
    await page.locator('.nav[data-page="logs"]').click();
    check(await count() === 3, 'the normal log page combines device and both network sources');
    check((await page.locator('#terminal-lines').innerText()).includes('[主机 A] 对端暂不可用'), 'network names accompany their log messages');
    check((await page.locator('#terminal-lines .message').allTextContents()).at(-1).includes('双向连接已恢复'), 'absolute timestamps order messages across midnight');
    for (let i = 0; i < 5; i++) await show();
    check(await count() === 3, 'unchanged polling does not repeat existing entries');
    model.networks[0].status.logEntries.push(event('alpha:2', '00:00:01 [ERROR] 入口解析失败', 2000));
    await page.evaluate(() => refresh());
    await page.getByText('[主机 A] 入口解析失败', { exact: true }).waitFor();
    check(await count() === 4, 'a network-only log change reaches the page through normal status polling');
    const full = model.networks[0].status.logEntries;
    model.networks[0].status.logEntries = full.slice(-1);
    await show();
    model.networks[0].status.logEntries = full;
    model.selectedNetworkId = 'alpha';
    await show();
    check(await count() === 4, 'reduced replies and network selection do not replay history');
    model.networks[1].status.logEntries.push(event('beta:2', '00:00:01 [ERROR] 入口解析失败', 2000));
    await show();
    check(await count() === 5, 'identical text from different networks remains distinct');
    model.networks[0].status.logEntries = [event('restarted:1', '00:00:01 [ERROR] 入口解析失败', 2000)];
    await show();
    check(await count() === 6, 'a restarted worker can emit the same message with a new identity');
    await page.locator('#log-filter').selectOption('ERROR');
    check(await count() === 3, 'level filtering applies to the combined history');
    await page.locator('#log-search').fill('主机 B');
    check(await count() === 1, 'search can select a network source');
    await page.evaluate(() => {
      Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: async text => { window.copiedLogs = text; } } });
      const original = URL.createObjectURL;
      URL.createObjectURL = blob => { window.exportedLogs = blob; return original(blob); };
    });
    await page.locator('[data-action="copy-logs"]').click();
    check((await page.evaluate(() => window.copiedLogs)).includes('[主机 B] 入口解析失败'), 'copy uses the same filtered network records');
    const download = page.waitForEvent('download');
    await page.locator('[data-action="download-logs"]').click();
    await (await download).cancel();
    check((await page.evaluate(() => window.exportedLogs.text())).includes('[主机 B] 入口解析失败'), 'export includes the same source labels as the page');
    await page.locator('#log-filter').selectOption('ALL');
    await page.locator('#log-search').fill('');
    model.logEntries = Array.from({ length: 600 }, (_, index) => event('bulk:' + index, '00:01:00 [INFO] event ' + index, 61000 + index));
    model.networks = [];
    await show();
    check(await count() === 500, 'the combined panel history remains bounded at 500 records');
    await show();
    check(await count() === 500 && !(await page.locator('#terminal-lines').innerText()).includes('event 0\n'), 'repeated snapshots cannot bring discarded history back into the view');
    await page.evaluate(() => { logLines = []; logSnapshots.clear(); seenLogEntries.clear(); });
    delete model.logEntries;
    model.logs = ['01:00:00 [INFO] legacy one', '01:00:01 [INFO] legacy two', '01:00:02 [INFO] legacy three'];
    await show();
    model.logs = model.logs.slice(-1);
    await show();
    model.logs = ['01:00:00 [INFO] legacy one', '01:00:01 [INFO] legacy two', '01:00:02 [INFO] legacy three', '01:00:03 [INFO] legacy four'];
    await show();
    check(await count() === 4, 'older statuses without log identities survive shrinking and expanding windows');
    check(errors.length === 0, 'the browser reports no script errors');
    console.log('PASS ' + checks.length + ' workspace log checks');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
