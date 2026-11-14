import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const htmlPath = path.join(root, 'VaultPOS_POS.html');
const html = fs.readFileSync(htmlPath, 'utf8');
const blocks = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)].map((match) => match[1]);
const runtime = blocks.at(-1);
const ids = new Set([...html.matchAll(/\bid=["']([^"']+)["']/g)].map((match) => match[1]));
const actions = new Set([...html.matchAll(/data-action=["']([^"']+)["']/g)].map((match) => match[1]));
const handlers = new Set([...runtime.matchAll(/case\s+["']([^"']+)["']/g)].map((match) => match[1]));
const refs = new Set([...runtime.matchAll(/\$\(\s*["']([^"']+)["']/g)].map((match) => match[1]));
const declaredFunctions = [...runtime.matchAll(/\bfunction\s+([A-Za-z_$][\w$]*)\s*\(/g)].map((match) => match[1]);
const unreferencedFunctions = declaredFunctions.filter((name) => (runtime.match(new RegExp(`\\b${name}\\b`, 'g')) || []).length < 2);
const fileInputIds = [...html.matchAll(/<input\b[^>]*type=["']file["'][^>]*>/gi)].map(([tag]) => tag.match(/\bid=["']([^"']+)["']/i)?.[1] || '<missing-id>');
const changeBlock = runtime.match(/document\.addEventListener\(\s*['"]change['"][\s\S]*?\}\s*\)\s*;/)?.[0] || '';
const unwiredFileInputs = fileInputIds.filter((id) => id === '<missing-id>' || !changeBlock.includes(`'${id}'`) && !changeBlock.includes(`"${id}"`));
let trackedFiles = [];
try {
  trackedFiles = execFileSync('git', ['ls-files'], { cwd: root, encoding: 'utf8' }).split(/\r?\n/).filter(Boolean);
} catch {
  trackedFiles = fs.readdirSync(root);
}
const leakedExports = trackedFiles.filter((entry) => /(?:^|\/)VaultPOS_.*(?:Backup|Report|Export).*\.(?:json|csv|xls|html)$/i.test(entry) || /\.(?:db|sqlite|sqlite3|bak)$/i.test(entry) || /^\.opencode\//i.test(entry));
const contentScanTargets = trackedFiles.filter((entry) => /\.(?:json|csv|xls|html|txt)$/i.test(entry) && !['VaultPOS_POS.html', 'ALL_CODE_BUNDLE.txt', 'VERSION.txt', 'package.json', 'package-lock.json', 'tests/fixtures/qr-reference-matrices.json'].includes(entry));
const leakedContentFiles = contentScanTargets.filter((entry) => {
  try {
    const text = fs.readFileSync(path.join(root, entry), 'utf8');
    return /"schema"\s*:\s*"ENC_BACKUP_V2"|ENC_V1:[A-Za-z0-9+/=]{12,}:|OBF_V1:[A-Za-z0-9+/=]{12,}/i.test(text);
  } catch {
    return false;
  }
});
const versionTxt = fs.readFileSync(path.join(root, 'VERSION.txt'), 'utf8').trim();
const pkgVersion = `v${JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version}`;
const runtimeVersion = runtime.match(/const\s+APP_VERSION\s*=\s*['"]([^'"]+)['"]/)?.[1];

assert.ok(runtime, 'missing production runtime');
assert.equal(runtimeVersion, versionTxt, 'APP_VERSION must match VERSION.txt');
assert.equal(versionTxt, pkgVersion, 'VERSION.txt must match package.json version');
assert.deepEqual(leakedExports, [], `private backup/export files tracked in repository: ${leakedExports.join(', ')}`);
assert.deepEqual(leakedContentFiles, [], `encrypted backup or vault dumps tracked in repository: ${leakedContentFiles.join(', ')}`);
assert.doesNotThrow(() => new vm.Script(runtime, { filename: htmlPath }));
assert.doesNotMatch(html, /<(?:script|link)[^>]+(?:src|href)=["']https?:\/\//i);
assert.doesNotMatch(html, /\bonclick\s*=/i);
assert.deepEqual([...actions].filter((action) => !handlers.has(action)), [], 'unhandled data-action hook');
assert.deepEqual([...refs].filter((id) => !ids.has(id)), [], 'runtime DOM reference does not exist');
assert.deepEqual([...new Set([...html.matchAll(/data-target=["']([^"']+)["']/g)].map((match) => match[1]))].filter((id) => !ids.has(id)), [], 'data-target does not exist');
assert.deepEqual(unreferencedFunctions, [], `unreferenced function declarations: ${unreferencedFunctions.join(', ')}`);
assert.deepEqual(unwiredFileInputs, [], `file inputs missing change handler: ${unwiredFileInputs.join(', ')}`);
assert.match(html, /<\/html>\s*$/i);

console.log(`lint passed: ${ids.size} ids, ${actions.size} static data-actions, ${refs.size} literal DOM references, ${declaredFunctions.length} functions, ${fileInputIds.length} file inputs`);
