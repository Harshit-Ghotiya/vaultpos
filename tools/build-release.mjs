import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (name) => fs.readFileSync(path.join(root, name), 'utf8');
const sha256 = (content) => crypto.createHash('sha256').update(content, 'utf8').digest('hex');
const version = read('VERSION.txt').trim();
const pkg = JSON.parse(read('package.json'));
const html = read('VaultPOS_POS.html');
const bat = read('Start_VaultPOS_POS.bat').replace(/\r?\n/g, '\r\n');
fs.writeFileSync(path.join(root, 'Start_VaultPOS_POS.bat'), bat, 'utf8');

const htmlAppVersion = html.match(/const\s+APP_VERSION\s*=\s*['"]([^'"]+)['"]/)?.[1];
assert.equal(version, `v${pkg.version}`, `VERSION.txt (${version}) must match package.json (v${pkg.version})`);
assert.equal(htmlAppVersion, version, `VaultPOS_POS.html APP_VERSION (${htmlAppVersion}) must match VERSION.txt (${version})`);

const releaseManifest = JSON.stringify({
  name: pkg.name,
  version,
  schemaVersion: 2,
  supportedBrowser: 'Microsoft Edge / Chromium (Windows Kiosk & Desktop)',
  targetPrinter: 'TVS RP 3200 Lite (80mm Thermal Receipt Printer)',
  files: {
    'VaultPOS_POS.html': { sha256: sha256(html), bytes: Buffer.byteLength(html, 'utf8') },
    'Start_VaultPOS_POS.bat': { sha256: sha256(bat), bytes: Buffer.byteLength(bat, 'utf8') }
  }
}, null, 2) + '\n';

const optionalBundleFiles = [
  'CLAUDE.md',
  'HANDOFF.md',
  'ROADMAP.md',
  'VERSION.txt',
  'README.md',
  'package.json',
  'package-lock.json',
  '.gitignore',
  '.editorconfig',
  '.gitattributes',
  'tests/pos-static.test.mjs',
  'tools/lint.mjs',
  'tools/serve.mjs',
  'tools/build-release.mjs',
  '.github/workflows/ci.yml'
];
const bundleSections = [
  ['Start_VaultPOS_POS.bat', bat],
  ['VaultPOS_POS.html', html],
  ['RELEASE_MANIFEST.json', releaseManifest],
  ...optionalBundleFiles.filter((name) => fs.existsSync(path.join(root, name))).map((name) => [name, read(name)])
];
const divider = '================================================================================';
let bundle = `${divider}\nVAULTPOS — COMPLETE CODEBASE BUNDLE\nRelease: ${version}\nTarget Hardware: TVS RP 3200 Lite (80mm Thermal Receipt Printer)\n${divider}\n\n`;
for (const [name, content] of bundleSections) bundle += `FILE: ${name}\n${'-'.repeat(80)}\n${content.trimEnd()}\n\n`;
fs.writeFileSync(path.join(root, 'ALL_CODE_BUNDLE.txt'), bundle);

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function u16(value) { const buffer = Buffer.alloc(2); buffer.writeUInt16LE(value); return buffer; }
function u32(value) { const buffer = Buffer.alloc(4); buffer.writeUInt32LE(value >>> 0); return buffer; }

function createZip(entries) {
  const localParts = []; const centralParts = []; let offset = 0;
  for (const [name, content] of entries) {
    const nameBuffer = Buffer.from(name, 'utf8'); const source = Buffer.from(content, 'utf8'); const compressed = zlib.deflateRawSync(source, { level: 9 }); const crc = crc32(source);
    const local = Buffer.concat([Buffer.from('PK\x03\x04', 'binary'), u16(20), u16(0), u16(8), u16(0), u16(0), u32(crc), u32(compressed.length), u32(source.length), u16(nameBuffer.length), u16(0), nameBuffer, compressed]);
    localParts.push(local);
    centralParts.push(Buffer.concat([Buffer.from('PK\x01\x02', 'binary'), u16(20), u16(20), u16(0), u16(8), u16(0), u16(0), u32(crc), u32(compressed.length), u32(source.length), u16(nameBuffer.length), u16(0), u16(0), u16(0), u16(0), u32(0), u32(offset), nameBuffer]));
    offset += local.length;
  }
  const central = Buffer.concat(centralParts); const local = Buffer.concat(localParts);
  const end = Buffer.concat([Buffer.from('PK\x05\x06', 'binary'), u16(0), u16(0), u16(entries.length), u16(entries.length), u32(central.length), u32(local.length), u16(0)]);
  return Buffer.concat([local, central, end]);
}

const archive = createZip([
  ['VaultPOS_POS.html', html],
  ['Start_VaultPOS_POS.bat', bat],
  ['RELEASE_MANIFEST.json', releaseManifest]
]);
fs.writeFileSync(path.join(root, 'VaultPOS_POS_Offline_Release.zip'), archive);
console.log(`release artifacts built for ${version}: ALL_CODE_BUNDLE.txt, VaultPOS_POS_Offline_Release.zip`);
