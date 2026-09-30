// Browser <-> desktop E2EE chat. The desktop admin creates #general and posts a
// message before the browser joins (must be unreadable), then one after (must
// decrypt); the browser replies through the UI and the desktop reads it.
//   node tests/web/chat-e2e.mjs <invite-link> <desktop-binary> <admin LAIRA_HOME>
import puppeteer from 'puppeteer-core';
import { execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { writeFileSync, readFileSync, mkdtempSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const [link, desktop, adminHome] = process.argv.slice(2);
const cli = (...a) => execFileSync(desktop, ['chat', ...a], { env: { ...process.env, LAIRA_HOME: adminHome }, encoding: 'utf8' });
const until = async (page, fn, what, ms = 15000) => {
  try { await page.waitForFunction(fn, { timeout: ms, polling: 250 }); }
  catch (e) { console.log('--- timeout waiting for', what); console.log(await page.evaluate(() => `${document.getElementById('messages')?.innerText}\n${document.getElementById('log')?.textContent}`)); throw e; }
};

const browser = await puppeteer.launch({ executablePath: '/usr/bin/chromium', headless: true, args: ['--no-sandbox'] });
let ok = false;
try {
  const page = await browser.newPage();
  await page.goto(link);
  await until(page, () => document.querySelectorAll('#channel option').length > 0, 'channel list');
  console.log('browser sees channels:', await page.$$eval('#channel option', (o) => o.map((x) => x.textContent)));
  cli('send', 'general', 'hello browser');
  await until(page, () => document.getElementById('messages').innerText.includes('hello browser'), 'decrypted admin message');
  const text = await page.$eval('#messages', (e) => e.innerText);
  if (!text.includes('unreadable')) throw new Error('pre-join message should be unreadable in the browser');
  if (text.includes('before the browser')) throw new Error('pre-join plaintext leaked');
  await page.type('#chatinput', 'hello desktop <b>not html</b>');
  await page.keyboard.press('Enter');
  await until(page, () => document.getElementById('messages').innerText.includes('hello desktop'), 'own message echo');
  if (await page.$('#messages b')) throw new Error('message rendered as HTML');
  const read = cli('read', 'general');
  if (!read.includes('hello desktop <b>not html</b>')) throw new Error('desktop cannot read the browser message:\n' + read);
  // --- files, browser -> desktop ---
  const tmp = mkdtempSync(join(tmpdir(), 'laira-files-'));
  const out = join(tmp, 'out'); mkdirSync(out);
  const up = randomBytes(200_000);
  writeFileSync(join(tmp, 'from-browser.bin'), up);
  await (await page.$('#fileinput')).uploadFile(join(tmp, 'from-browser.bin'));
  await until(page, () => document.querySelector('#messages a.file')?.textContent.includes('from-browser.bin'), 'own attachment listed');
  const lines = cli('read', 'general').split('\n');
  const seq = lines.find((l) => l.includes('[file] from-browser.bin'))?.match(/^\[(\d+)\]/)?.[1];
  if (!seq) throw new Error('desktop does not list the browser attachment:\n' + lines.join('\n'));
  execFileSync(desktop, ['chat', 'save-file', 'general', seq, '--out-dir', out], { env: { ...process.env, LAIRA_HOME: adminHome } });
  if (!readFileSync(join(out, 'from-browser.bin')).equals(up)) throw new Error('desktop got different bytes than the browser uploaded');
  // --- files, desktop -> browser ---
  const down = randomBytes(150_000);
  writeFileSync(join(tmp, 'from-desktop.bin'), down);
  cli('send-file', 'general', join(tmp, 'from-desktop.bin'));
  await until(page, () => [...document.querySelectorAll('#messages a.file')].some((a) => a.textContent.includes('from-desktop.bin')), 'desktop attachment listed');
  await page.evaluate(() => [...document.querySelectorAll('#messages a.file')].find((a) => a.textContent.includes('from-desktop.bin')).click());
  await until(page, () => window.__lastDownload?.name === 'from-desktop.bin', 'download finished');
  const got = await page.evaluate(() => window.__lastDownload);
  if (got.sha256 !== createHash('sha256').update(down).digest('hex')) throw new Error('browser decrypted different bytes');
  ok = true;
} finally {
  await browser.close();
}
console.log(ok ? 'BROWSER CHAT + FILES E2EE OK' : 'FAILED');
process.exit(ok ? 0 : 2);
