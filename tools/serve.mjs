import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const portIndex = process.argv.indexOf('--port');
const port = Number(portIndex >= 0 ? process.argv[portIndex + 1] : 4173) || 4173;
const mime = {
  '.bat': 'application/octet-stream', '.css': 'text/css; charset=utf-8', '.csv': 'text/csv; charset=utf-8',
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.md': 'text/markdown; charset=utf-8', '.txt': 'text/plain; charset=utf-8', '.zip': 'application/zip'
};

const FORBIDDEN_PATTERNS = [
  /\0|%00/i,
  /(?:^|\/|\\)\.\.(?:\/|\\|$)|%2e%2e|%2f|%5c/i,
  /(?:^|\/)\.[^/]+/, // dotfiles and dot-directories (.git, .opencode, .env, .DS_Store)
  /\.(?:db|sqlite|sqlite3|bak)$/i,
  /(?:^|\/)(?:backups|exports|tools|tests|node_modules)(?:\/|$)/i,
  /VaultPOS_.*(?:Backup|Report|Export)/i
];

export function isForbiddenRelativePath(relative) {
  const normalized = String(relative || '').replace(/\\/g, '/');
  return FORBIDDEN_PATTERNS.some((pattern) => pattern.test(normalized));
}

const server = http.createServer((request, response) => {
  try {
    const rawPath = (request.url || '/').split('?')[0];
    if (isForbiddenRelativePath(rawPath)) {
      response.writeHead(403); response.end('Forbidden'); return;
    }
    let requestPath = '/';
    try {
      requestPath = decodeURIComponent(rawPath);
    } catch (e) {
      response.writeHead(400); response.end('Bad request'); return;
    }
    const relative = requestPath === '/' ? '/VaultPOS_POS.html' : requestPath;
    const filePath = path.resolve(root, `.${relative}`);
    if ((!filePath.startsWith(`${root}${path.sep}`) && filePath !== root) || isForbiddenRelativePath(relative)) {
      response.writeHead(403); response.end('Forbidden'); return;
    }
    const stats = fs.statSync(filePath);
    if (!stats.isFile()) {
      response.writeHead(403); response.end('Forbidden'); return;
    }
    response.writeHead(200, { 'Content-Type': mime[path.extname(filePath).toLowerCase()] || 'application/octet-stream', 'Cache-Control': 'no-store' });
    fs.createReadStream(filePath).pipe(response);
  } catch (error) {
    response.writeHead(error.code === 'ENOENT' ? 404 : 500); response.end(error.code === 'ENOENT' ? 'Not found' : 'Server error');
  }
});

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  server.listen(port, '127.0.0.1', () => console.log(`VaultPOS development server: http://127.0.0.1:${port}/VaultPOS_POS.html`));
}
