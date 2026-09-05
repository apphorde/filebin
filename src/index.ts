import type { IncomingMessage } from 'node:http';
import { createServer } from 'node:http';
import { createHmac, randomBytes, randomUUID, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { createReadStream, createWriteStream, existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { writeFile, readFile, mkdir, readdir, stat, rm, rename, unlink } from 'node:fs/promises';
import router from 'micro-router';
import * as yazl from 'yazl';
import * as yauzl from 'yauzl';
import { load } from 'js-yaml';
import { promisify } from 'node:util';

const rootDir = process.env.ROOT_DIR;
const jsonHeaders = { 'content-type': 'application/json' };
const lockFileName = '.bin.meta';
const sessionSecret = randomBytes(32);
const scrypt = promisify(scryptCallback);

export type Options = { port?: number };

async function onFileExists(_req, res, args) {
  const { binId = '', fileId = '' } = args;
  const filePath = join(rootDir, binId, fileId);

  if (!(binId && fileId && existsSync(filePath))) {
    return notFound(res);
  }

  res.end();
}

async function onReadFile(_req, res, args) {
  const { binId = '', fileId = '' } = args;
  const filePath = join(rootDir, binId, fileId);
  const metaPath = filePath + '.meta';

  if (!(binId && fileId && existsSync(filePath))) {
    return notFound(res);
  }

  tryCatch(res, async () => {
    const meta = await readMetaFile(metaPath);
    const stats = await stat(filePath);

    Object.entries(meta).forEach(([key, value]) => res.setHeader(key == 'type' ? 'content-type' : key, String(value)));

    res.setHeader('content-length', stats.size);
    res.setHeader('last-modified', new Date(stats.mtime).toString());

    createReadStream(filePath).pipe(res);
  });
}

async function readMetadata(binId: string, fileId: string, baseUrl: string | URL) {
  const filePath = join(...[rootDir, binId, fileId].filter(Boolean));

  if (!(binId && existsSync(filePath))) {
    return null;
  }

  try {
    const metaPath = filePath + '.meta';
    const meta = await readMetaFile(metaPath);
    const stats = await stat(filePath);

    return {
      ...meta,
      id: fileId || undefined,
      bin: binId,
      size: stats.size,
      name: meta.name || fileId,
      lastModified: new Date(stats.mtime).toISOString(),
      url: String(new URL('/' + ['f', binId, fileId].filter(Boolean).join('/'), baseUrl)),
    };
  } catch {
    return null;
  }
}

async function onReadMetadata(req, res, args) {
  const { binId = '', fileId = '' } = args;
  const baseUrl = getProxyHost(req);
  const metadata = await readMetadata(binId, fileId, baseUrl);

  if (!metadata) {
    return notFound(res);
  }

  res.writeHead(200, jsonHeaders);
  res.end(JSON.stringify(metadata));
}

async function onWriteMetadata(req, res, args) {
  const { binId = '', fileId = '' } = args;
  const filePath = join(...[rootDir, binId, fileId].filter(Boolean));
  const metaPath = filePath + '.meta';

  if (!(binId && existsSync(filePath))) {
    return notFound(res);
  }

  tryCatch(res, async () => {
    const payload = await readStream(req);
    const meta = payload.toString('utf-8').trim();

    if (meta) {
      await writeFile(metaPath, JSON.stringify(JSON.parse(meta)));
      const url = String(new URL('/' + ['f', binId, fileId].filter(Boolean).join('/'), getProxyHost(req)));
      res.writeHead(202).end(JSON.stringify({ url }));
      return;
    }

    badRequest(res);
  });
}

async function onCreateFile(req, res, args) {
  const { binId = '' } = args;
  const binPath = join(rootDir, binId);

  if (!(binId && existsSync(binPath))) {
    return notFound(res);
  }

  tryCatch(res, async () => {
    const payload = await readStream(req);
    const fileId = randomUUID();
    const meta = payload.toString('utf-8');

    if (meta) {
      await writeFile(join(binPath, fileId + '.meta'), JSON.stringify(JSON.parse(meta)));
    }

    await writeFile(join(binPath, fileId), '');

    res.setHeader('location', String(new URL(`/f/${binId}/${fileId}`, getProxyHost(req))));
    res.writeHead(201).end(`{"fileId": "${fileId}"}`);
  });
}

function onWriteFile(req, res, args) {
  const { binId = '', fileId = '' } = args;
  const filePath = join(rootDir, binId, fileId);

  if (!(binId && fileId && existsSync(filePath))) {
    return notFound(res);
  }

  const writer = createWriteStream(filePath);

  writer.on('close', () => {
    res.writeHead(202);
    res.end(
      JSON.stringify({
        id: fileId,
        bin: binId,
        url: String(new URL(`/f/${binId}/${fileId}`, getProxyHost(req))),
      }),
    );
  });

  req.pipe(writer);
}

async function readBin(binId: string) {
  const binPath = join(rootDir, binId);

  if (!(binId && existsSync(binPath))) {
    return null;
  }

  const allFiles = await readdir(binPath);
  return allFiles.filter((f) => !f.endsWith('.meta'));
}

async function onReadBin(_req, res, args) {
  const { binId = '' } = args;

  tryCatch(res, async () => {
    const files = await readBin(binId);

    if (files === null) {
      return notFound(res);
    }

    res.writeHead(200, jsonHeaders).end(JSON.stringify(files));
  });
}

function onCreateBin(req, res) {
  tryCatch(res, async () => {
    const binId = randomUUID();
    await ensureDir(join(rootDir, binId));
    res.setHeader('location', String(new URL('/bin/' + binId, getProxyHost(req))));
    res.writeHead(201).end(JSON.stringify({ binId }));
  });
}

function onRenameBin(req, res, args) {
  tryCatch(res, async () => {
    let { binId, newId } = args;
    const matcher = /^[a-z0-9-]+$/i;
    if (!binId || !newId || !matcher.test(newId)) {
      badRequest(res);
      return;
    }

    const oldPath = join(rootDir, binId);
    const newPath = join(rootDir, newId);
    const oldMetaPath = oldPath + '.meta';

    if (!existsSync(oldPath) || existsSync(newPath)) {
      badRequest(res);
      return;
    }

    await rename(oldPath, newPath);

    if (existsSync(oldMetaPath)) {
      await rename(oldMetaPath, newPath + '.meta');
    }

    if (await isBinLocked(newId)) {
      setUnlockCookie(req, res, newId);
    }
    res.setHeader('location', String(new URL('/bin/' + newId, getProxyHost(req))));
    res.writeHead(202).end(JSON.stringify({ binId: newId }));
  });
}

async function onRenameBinPatch(req, res, args) {
  const { newId = '' } = await readJson(req);
  return onRenameBin(req, res, { ...args, newId });
}

async function onDeleteFile(_req, res, args) {
  const { binId = '', fileId = '' } = args;
  const filePath = join(rootDir, binId, fileId);
  const metaPath = join(rootDir, binId, fileId + '.meta');

  if (!(binId && fileId && existsSync(filePath))) {
    return notFound(res);
  }

  tryCatch(res, async () => {
    await unlink(filePath);

    if (existsSync(metaPath)) {
      await unlink(metaPath);
    }

    res.end('OK');
  });
}

async function onDeleteBin(_req, res, args) {
  const { binId = '' } = args;
  const binPath = join(rootDir, binId);

  if (!(binId && existsSync(binPath))) {
    return notFound(res);
  }

  tryCatch(res, async () => {
    await rm(binPath, { recursive: true });
    res.end('OK');
  });
}

async function onApiSpec(req, res) {
  const isJson = req.url.endsWith('.json');
  const host = getProxyHost(req);
  let spec = (await readFile('./api.yaml', 'utf-8')).replace('__API_HOST__', host);

  if (isJson) {
    res.setHeader('content-type', 'application/json');
    spec = JSON.stringify(load(spec));
  } else {
    res.setHeader('content-type', 'application/yaml');
  }

  res.end(spec);
}

async function onEsModule(req, res) {
  const host = getProxyHost(req);
  const file = await readFile('./filebin.mjs', 'utf-8');
  res.setHeader('content-type', 'text/javascript');
  res.end(file.replace('__API_HOST__', host));
}

const indexFile = readFileSync('./index.html', 'utf-8');

function onGetUI(req, res, args) {
  tryCatch(res, async () => {
    const { binId } = args;
    let state: any;

    if (binId) {
      const baseUrl = getProxyHost(req);
      const fileIds = await readBin(binId);

      if (fileIds === null) {
        return notFound(res);
      }

      const locked = await isBinLocked(binId);
      const unlocked = !locked || (await isBinAuthorized(req, binId));
      const files = unlocked ? await Promise.all(fileIds.map((x) => readMetadata(binId, x, baseUrl))) : [];

      state = {
        files,
        locked,
        unlocked,
      };
    }

    res
      .writeHead(200, { 'content-type': 'text/html' })
      .end(indexFile.replace('<!-- %state% -->', JSON.stringify(state || {})));
  });
}

function onGetManifest(_req, res) {
  res.setHeader('content-type', 'application/manifest+json');
  createReadStream('./manifest.webmanifest').pipe(res);
}

function onGetIcon(_req, res) {
  res.setHeader('content-type', 'image/svg+xml');
  createReadStream('./icon.svg').pipe(res);
}

async function onUploadZip(req, res, args) {
  let { binId = '' } = args;
  binId = binId.replace(/\.zip$/, '');
  const binPath = join(rootDir, binId);

  if (!(binId && existsSync(binPath))) {
    return notFound(res);
  }

  const uid = randomUUID();
  const tmpFile = join(binPath, uid);

  try {
    await new Promise((resolve, reject) => {
      req.on('end', () => {
        const zipOptions = {
          strictFileNames: true,
          lazyEntries: true,
          decodeStrings: true,
        };

        yauzl.open(tmpFile, zipOptions, (err, zip) => {
          if (err) {
            return reject(err);
          }

          zip.on('error', (err) => reject(err));

          const writes = [];

          zip.once('end', async () => {
            await Promise.all(writes);
            zip.close();
            resolve(true);
          });

          zip.on('entry', (entry) => {
            if (entry.fileName.endsWith('/')) {
              zip.readEntry();
              return;
            }

            zip.openReadStream(entry, async (err, readStream) => {
              if (err) {
                return reject(err);
              }

              const fileId = randomUUID();
              const meta = { name: entry.fileName };
              const stream = createWriteStream(join(binPath, fileId));

              await writeFile(join(binPath, fileId + '.meta'), JSON.stringify(meta));
              writes.push(
                new Promise((resolve, reject) => {
                  stream.on('finish', () => resolve(null));
                  stream.on('error', reject);
                }),
              );
              readStream.on('end', () => zip.readEntry());
              readStream.pipe(stream);
            });
          });

          zip.readEntry();
        });
      });

      req.pipe(createWriteStream(tmpFile));
    });

    res.writeHead(202).end(`{"binId": "${binId}"}`);
  } catch (error) {
    console.log(error);
    res.writeHead(500).end();
  } finally {
    await unlink(tmpFile).catch(() => {});
  }
}

async function onLockStatus(req, res, args) {
  const { binId = '' } = args;

  if (!(binId && existsSync(join(rootDir, binId)))) {
    return notFound(res);
  }

  const locked = await isBinLocked(binId);
  const unlocked = !locked || (await isBinAuthorized(req, binId));
  res.writeHead(200, jsonHeaders).end(JSON.stringify({ locked, unlocked }));
}

async function onUnlockBin(req, res, args) {
  const { binId = '' } = args;

  if (!(binId && existsSync(join(rootDir, binId)))) {
    return notFound(res);
  }

  const { password = '' } = await readJson(req);

  if (!(await verifyBinPassword(binId, password))) {
    return unauthorized(res);
  }

  setUnlockCookie(req, res, binId);
  res.writeHead(204).end();
}

async function onSetBinPassword(req, res, args) {
  const { binId = '' } = args;

  if (!(binId && existsSync(join(rootDir, binId)))) {
    return notFound(res);
  }

  const { password = '' } = await readJson(req);

  if (typeof password !== 'string' || password.length < 8) {
    return badRequest(res, 'Password must contain at least 8 characters');
  }

  const salt = randomBytes(16).toString('base64url');
  const hash = Buffer.from((await scrypt(password, salt, 32)) as Buffer).toString('base64url');
  await writeFile(getLockPath(binId), JSON.stringify({ lock: { salt, hash } }));
  setUnlockCookie(req, res, binId);
  res.writeHead(204).end();
}

async function onRemoveBinPassword(req, res, args) {
  const { binId = '' } = args;
  await unlink(getLockPath(binId)).catch((error) => {
    if (error.code !== 'ENOENT') throw error;
  });
  clearUnlockCookie(req, res, binId);
  res.writeHead(204).end();
}

async function onDownloadZip(_req, res, args) {
  let { binId = '' } = args;
  binId = binId.replace('.zip', '');
  const binPath = join(rootDir, binId);

  if (!(binId && existsSync(binPath))) {
    return notFound(res);
  }

  tryCatch(res, async () => {
    const zip = new yazl.ZipFile();
    const allFiles = await readdir(binPath);
    const files = allFiles.filter((f) => !f.endsWith('.meta'));

    res.setHeader('content-type', 'application/x-zip');
    res.setHeader('Content-Disposition', `attachment; filename="archive-${binId.slice(0, 8)}.zip"`);
    zip.outputStream.pipe(res);

    for (const fileId of files) {
      const filePath = join(rootDir, binId, fileId);
      const metaPath = filePath + '.meta';
      const meta = await readMetaFile(metaPath);
      const buffer = await readFile(filePath);
      const fileName = meta.name || fileId;
      zip.addBuffer(buffer, fileName);
    }

    zip.end();
  });
}

function notFound(res) {
  res.writeHead(404).end('Not found');
}

function badRequest(res, message = 'Bad request') {
  res.writeHead(400).end(message);
}

function unauthorized(res) {
  res.writeHead(401, { ...jsonHeaders, 'www-authenticate': 'Basic realm="FileBin"' }).end(
    JSON.stringify({ error: 'This bin is locked' }),
  );
}

async function tryCatch(res, fn) {
  try {
    await fn();
  } catch (error) {
    console.log(error);
    res.writeHead(500).end();
  }
}

function getProxyHost(req: IncomingMessage): string {
  return new URL(
    `${req.headers['x-forwarded-proto'] || 'http'}://${req.headers['x-forwarded-host'] || req.headers.host}`,
  ).toString();
}

function readStream(stream): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const parts = [];
    stream.on('data', (c) => parts.push(c));
    stream.on('end', () => resolve(Buffer.concat(parts) as Buffer));
    stream.on('error', reject);
  });
}

async function readJson(req) {
  const payload = (await readStream(req)).toString('utf8').trim();
  return payload ? JSON.parse(payload) : {};
}

function getLockPath(binId: string) {
  return join(rootDir, binId, lockFileName);
}

async function readBinLock(binId: string) {
  const metadata = await readMetaFile(getLockPath(binId));
  return metadata.lock || null;
}

async function isBinLocked(binId: string) {
  return Boolean((await readBinLock(binId))?.hash);
}

async function verifyBinPassword(binId: string, password: string) {
  const lock = await readBinLock(binId);

  if (!lock?.salt || !lock?.hash || typeof password !== 'string') {
    return false;
  }

  const actual = Buffer.from((await scrypt(password, lock.salt, 32)) as Buffer);
  const expected = Buffer.from(lock.hash, 'base64url');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

function getCookieName(binId: string) {
  return `filebin_unlock_${binId}`;
}

function createUnlockToken(binId: string) {
  const expires = Date.now() + 12 * 60 * 60 * 1000;
  const value = `${binId}.${expires}`;
  const signature = createHmac('sha256', sessionSecret).update(value).digest('base64url');
  return `${expires}.${signature}`;
}

function hasValidUnlockCookie(req, binId: string) {
  const cookies = Object.fromEntries(
    String(req.headers.cookie || '')
      .split(';')
      .map((part) => part.trim().split('='))
      .filter(([key, value]) => key && value),
  );
  const [expires, signature] = String(cookies[getCookieName(binId)] || '').split('.');

  if (!expires || !signature || Number(expires) < Date.now()) {
    return false;
  }

  const expected = createHmac('sha256', sessionSecret).update(`${binId}.${expires}`).digest();
  const actual = Buffer.from(signature, 'base64url');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

async function isBinAuthorized(req, binId: string) {
  if (!(await isBinLocked(binId)) || hasValidUnlockCookie(req, binId)) {
    return true;
  }

  const authorization = String(req.headers.authorization || '');

  if (authorization.startsWith('Basic ')) {
    const credentials = Buffer.from(authorization.slice(6), 'base64').toString('utf8');
    const password = credentials.slice(credentials.indexOf(':') + 1);
    return verifyBinPassword(binId, password);
  }

  return false;
}

function setUnlockCookie(req, res, binId: string) {
  const secure = getProxyHost(req).startsWith('https:') ? '; Secure' : '';
  res.setHeader(
    'set-cookie',
    `${getCookieName(binId)}=${createUnlockToken(binId)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200${secure}`,
  );
}

function clearUnlockCookie(req, res, binId: string) {
  const secure = getProxyHost(req).startsWith('https:') ? '; Secure' : '';
  res.setHeader('set-cookie', `${getCookieName(binId)}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure}`);
}

function protectedBinId(req) {
  const url = new URL(req.url, 'http://localhost');
  const parts = url.pathname.split('/').filter(Boolean);
  const [resource, rawBinId] = parts;

  if (!['bin', 'f', 'meta', 'zip', 'lock'].includes(resource) || !rawBinId) {
    return null;
  }

  if (resource === 'bin' && req.method === 'POST') return null;
  if (resource === 'lock' && ['GET', 'POST'].includes(req.method)) return null;
  return resource === 'zip' ? rawBinId.replace(/\.zip$/, '') : rawBinId;
}

function ensureDir(path) {
  if (existsSync(path)) return;
  return mkdir(path, { recursive: true });
}

async function readMetaFile(metaPath: string) {
  try {
    if (existsSync(metaPath)) {
      return JSON.parse(await readFile(metaPath, 'utf8'));
    }
  } catch {}

  return {};
}

const match = router({
  'GET /': onGetUI,
  'GET /b/:binId': onGetUI,
  'GET /manifest.webmanifest': onGetManifest,
  'GET /icon.svg': onGetIcon,
  'GET /api': onApiSpec,
  'GET /api.yaml': onApiSpec,
  'GET /api.json': onApiSpec,
  'GET /index.mjs': onEsModule,
  'POST /bin': onCreateBin,
  'MOVE /bin/:binId/:newId': onRenameBin,
  'PATCH /bin/:binId': onRenameBinPatch,
  'GET /bin/:binId': onReadBin,
  'DELETE /bin/:binId': onDeleteBin,

  'POST /f/:binId': onCreateFile,
  'HEAD /f/:binId/:fileId': onFileExists,
  'GET /f/:binId/:fileId': onReadFile,
  'PUT /f/:binId/:fileId': onWriteFile,
  'DELETE /f/:binId/:fileId': onDeleteFile,

  'GET /meta/:binId/:fileId': onReadMetadata,
  'PUT /meta/:binId/:fileId': onWriteMetadata,
  'GET /meta/:binId': onReadMetadata,
  'PUT /meta/:binId': onWriteMetadata,
  'GET /zip/:binId': onDownloadZip,
  'POST /zip/:binId': onUploadZip,
  'GET /lock/:binId': onLockStatus,
  'POST /lock/:binId': onUnlockBin,
  'PUT /lock/:binId': onSetBinPassword,
  'DELETE /lock/:binId': onRemoveBinPassword,
});

export function start(options: Options = {}) {
  if (!rootDir) {
    throw new Error('Cannot start without ROOT_DIR in environment.');
  }

  return createServer((req, res) => {
    const _end = res.end;

    res.end = (...args) => {
      console.log('[%s] %d %s %s', new Date().toISOString(), res.statusCode, req.method, req.url);
      return _end.apply(res, args);
    };

    tryCatch(res, async () => {
      const binId = protectedBinId(req);

      if (binId && !(await isBinAuthorized(req, binId))) {
        return unauthorized(res);
      }

      match(req, res);
    });
  }).listen(Number(options.port ?? process.env.PORT));
}

export default start;
