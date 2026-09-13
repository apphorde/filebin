import type { IncomingMessage } from 'node:http';
import { createServer } from 'node:http';
import {
  createHash,
  createHmac,
  randomBytes,
  randomUUID,
  scrypt as scryptCallback,
  timingSafeEqual,
} from 'node:crypto';
import { createReadStream, createWriteStream, existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { writeFile, readFile, mkdir, readdir, stat, rm, rename, unlink } from 'node:fs/promises';
import router from 'micro-router';
import * as yazl from 'yazl';
import * as yauzl from 'yauzl';
import { load } from 'js-yaml';
import { promisify } from 'node:util';

const rootDir = process.env.ROOT_DIR;
const authIssuer = process.env.AUTH_PROVIDER?.replace(/\/+$/, '');
const oidcClientId = process.env.OIDC_CLIENT_ID;
const oidcClientSecret = process.env.OIDC_CLIENT_SECRET;
const databaseModuleUrl = process.env.DATABASE_URL;
const binAdjectives = [
  'Amber',
  'Bright',
  'Calm',
  'Cedar',
  'Coral',
  'Cosmic',
  'Dawn',
  'Dewy',
  'Golden',
  'Ivy',
  'Jolly',
  'Lucky',
  'Maple',
  'Misty',
  'Ocean',
  'Quiet',
  'River',
  'Silver',
  'Sunny',
  'Velvet',
];
const binNouns = [
  'Acorn',
  'Brook',
  'Comet',
  'Cove',
  'Fern',
  'Harbor',
  'Hearth',
  'Island',
  'Lagoon',
  'Meadow',
  'Moon',
  'Orchard',
  'Pebble',
  'Pine',
  'Sparrow',
  'Star',
  'Summit',
  'Willow',
  'Woodland',
  'Wren',
];

function generateBinName() {
  return `${binAdjectives[randomBytes(1)[0] % binAdjectives.length]} ${binNouns[randomBytes(1)[0] % binNouns.length]}`;
}

const publicBinRetentionMs = Number(process.env.PUBLIC_BIN_RETENTION_HOURS || 168) * 60 * 60 * 1000;
const publicBinCleanupToken = process.env.PUBLIC_BIN_CLEANUP_TOKEN;
const binDeletionGraceMs = Number(process.env.BIN_DELETION_GRACE_HOURS || 168) * 60 * 60 * 1000;
const sessionCookieMaxAge = 30 * 24 * 60 * 60;
const oidcMissingConfiguration = [
  !authIssuer && 'AUTH_PROVIDER',
  !oidcClientId && 'OIDC_CLIENT_ID',
  !oidcClientSecret && 'OIDC_CLIENT_SECRET',
].filter(Boolean);
let authClientPromise: Promise<any> | null = null;

function loadAuthClient() {
  if (!authIssuer || !oidcClientId) return Promise.resolve(null);
  return fetch(new URL('/node.mjs', authIssuer))
    .then((response) => {
      if (!response.ok) throw new Error(`OIDC provider module request failed: ${response.status}`);
      return response.text();
    })
    .then((source) => import(`data:text/javascript,${encodeURIComponent(source)}`))
    .then(({ createAuthClient }) => createAuthClient({ issuer: authIssuer, clientId: oidcClientId }))
    .catch((error) => {
      console.error('Unable to initialize OIDC provider client:', error);
      return null;
    });
}
const databasePromise = databaseModuleUrl
  ? fetch(databaseModuleUrl)
      .then((response) => response.text())
      .then((source) => import(`data:text/javascript,${encodeURIComponent(source)}`))
      .then(async (database) => {
        await database.exec(`
      CREATE TABLE IF NOT EXISTS oidc_sessions (
        id TEXT PRIMARY KEY,
        profile TEXT NOT NULL,
        access_token TEXT,
        refresh_token TEXT,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL
      );
       CREATE TABLE IF NOT EXISTS storage_bins (
         id TEXT PRIMARY KEY,
         name TEXT NOT NULL,
         visibility TEXT NOT NULL,
        owner_issuer TEXT,
        owner_subject TEXT,
        created_at INTEGER NOT NULL,
        last_completed_upload_at INTEGER,
        imported_at INTEGER
      );
      CREATE TABLE IF NOT EXISTS storage_files (
        bin_id TEXT NOT NULL,
        id TEXT NOT NULL,
        metadata TEXT NOT NULL,
        system_metadata TEXT NOT NULL,
        size INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (bin_id, id)
      );
      CREATE TABLE IF NOT EXISTS storage_uploads (
        bin_id TEXT NOT NULL,
        file_id TEXT NOT NULL,
        state TEXT NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (bin_id, file_id)
      );
      CREATE TABLE IF NOT EXISTS audit_events (
        id INTEGER PRIMARY KEY,
        actor_subject TEXT,
        action TEXT NOT NULL,
        target TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
    `);
        for (const column of ['name TEXT', 'deletion_requested_at INTEGER', 'deletion_expires_at INTEGER']) {
          await database.exec(`ALTER TABLE storage_bins ADD COLUMN ${column}`).catch(() => {});
        }
        const unnamedBins = await database.all(`SELECT id FROM storage_bins WHERE name IS NULL OR name = ''`);
        await Promise.all(
          unnamedBins.map((bin) =>
            database.run('UPDATE storage_bins SET name = ? WHERE id = ?', [generateBinName(), bin.id]),
          ),
        );
        for (const column of ['access_token', 'refresh_token']) {
          await database.exec(`ALTER TABLE oidc_sessions ADD COLUMN ${column} TEXT`).catch(() => {});
        }
        return database;
      })
      .catch(() => null)
  : Promise.resolve(null);
const jsonHeaders = { 'content-type': 'application/json' };
const lockFileName = '.bin.meta';
const sessionSecret = process.env.SESSION_SECRET || randomBytes(32);
const scrypt = promisify(scryptCallback);
const uploadLocks = new Map<string, Promise<void>>();
const uploadRetentionMs = Number(process.env.UPLOAD_RETENTION_HOURS || 72) * 60 * 60 * 1000;
const uploadCleanupIntervalMs = Number(process.env.UPLOAD_CLEANUP_INTERVAL_MINUTES || 60) * 60 * 1000;

type ByteRange = { start: number; end: number };
type UploadPart = ByteRange & { digest: string };
type UploadState = {
  total: number | null;
  ranges: ByteRange[];
  pending: ByteRange[];
  parts: UploadPart[];
  immutable?: boolean;
};
type SystemMetadata = { immutable?: boolean; committedAt?: string; sha256?: string };

function getUploadDataPath(binId: string, fileId: string) {
  return join(rootDir, binId, `.upload-${fileId}`);
}

function getUploadStatePath(binId: string, fileId: string) {
  return getUploadDataPath(binId, fileId) + '.json';
}

function getSystemMetadataPath(binId: string, fileId: string) {
  return join(rootDir, binId, `${fileId}.system`);
}

async function withUploadLock<T>(path: string, fn: () => Promise<T>) {
  const previous = uploadLocks.get(path) || Promise.resolve();
  let release: () => void;
  const current = new Promise<void>((resolve) => (release = resolve));
  const queued = previous.then(() => current);
  uploadLocks.set(path, queued);
  await previous;
  try {
    return await fn();
  } finally {
    release!();
    if (uploadLocks.get(path) === queued) uploadLocks.delete(path);
  }
}

function parseContentRange(value: string | undefined) {
  const match = /^bytes (\d+)-(\d+)\/(\d+)$/.exec(value || '');
  if (!match) return null;
  const [, start, end, total] = match;
  const range = { start: Number(start), end: Number(end), total: Number(total) };
  return Number.isSafeInteger(range.start) &&
    Number.isSafeInteger(range.end) &&
    Number.isSafeInteger(range.total) &&
    range.start <= range.end &&
    range.end < range.total
    ? range
    : null;
}

function mergeRanges(ranges: ByteRange[]) {
  return [...ranges]
    .sort((a, b) => a.start - b.start)
    .reduce<ByteRange[]>((merged, range) => {
      const last = merged.at(-1);
      if (last && range.start <= last.end + 1) last.end = Math.max(last.end, range.end);
      else merged.push({ ...range });
      return merged;
    }, []);
}

function rangesOverlap(ranges: ByteRange[], range: ByteRange) {
  return ranges.some((item) => item.start <= range.end && range.start <= item.end);
}

function isUploadComplete(state: UploadState) {
  return (
    state.total !== null &&
    state.ranges.length === 1 &&
    state.ranges[0].start === 0 &&
    state.ranges[0].end === state.total - 1
  );
}

async function readUploadState(binId: string, fileId: string): Promise<UploadState | null> {
  const path = getUploadStatePath(binId, fileId);
  return existsSync(path) ? JSON.parse(await readFile(path, 'utf8')) : null;
}

async function writeUploadState(binId: string, fileId: string, state: UploadState) {
  await writeFile(getUploadStatePath(binId, fileId), JSON.stringify(state));
}

async function readSystemMetadata(binId: string, fileId: string): Promise<SystemMetadata> {
  const path = getSystemMetadataPath(binId, fileId);
  try {
    return existsSync(path) ? JSON.parse(await readFile(path, 'utf8')) : {};
  } catch {
    return {};
  }
}

async function writeSystemMetadata(binId: string, fileId: string, metadata: SystemMetadata) {
  const path = getSystemMetadataPath(binId, fileId);
  const temporaryPath = `${path}.${randomUUID()}`;
  await writeFile(temporaryPath, JSON.stringify(metadata));
  await rename(temporaryPath, path);
}

async function sha256File(filePath: string) {
  const hash = createHash('sha256');
  await new Promise<void>((resolve, reject) => {
    const stream = createReadStream(filePath);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', resolve);
    stream.on('error', reject);
  });
  return hash.digest('hex');
}

function getEtag(sha256: string | undefined) {
  return sha256 ? `"${sha256}"` : undefined;
}

async function recoverCompletedUpload(binId: string, fileId: string) {
  const filePath = join(rootDir, binId, fileId);
  const uploadPath = getUploadDataPath(binId, fileId);
  const statePath = getUploadStatePath(binId, fileId);

  if (!existsSync(statePath)) return false;

  if (existsSync(filePath)) {
    const state = JSON.parse(await readFile(statePath, 'utf8')) as UploadState;
    if (!(await readSystemMetadata(binId, fileId)).sha256) {
      await writeSystemMetadata(binId, fileId, {
        sha256: await sha256File(filePath),
        committedAt: new Date().toISOString(),
        ...(state.immutable ? { immutable: true } : {}),
      });
    }
    await Promise.all([rm(uploadPath, { force: true }), rm(statePath, { force: true })]);
    return true;
  }

  const state = JSON.parse(await readFile(statePath, 'utf8')) as UploadState;
  if (!isUploadComplete(state) || !existsSync(uploadPath)) return false;

  const sha256 = await sha256File(uploadPath);
  await rename(uploadPath, filePath);
  await writeSystemMetadata(binId, fileId, {
    sha256,
    committedAt: new Date().toISOString(),
    ...(state.immutable ? { immutable: true } : {}),
  });
  await rm(statePath, { force: true });
  return true;
}

export type Options = { port?: number };

async function onFileExists(_req, res, args) {
  const { binId = '', fileId = '' } = args;
  const filePath = join(rootDir, binId, fileId);

  if (!(binId && fileId && existsSync(filePath))) {
    return notFound(res);
  }

  const metadata = await readSystemMetadata(binId, fileId);
  const stats = await stat(filePath);
  res.setHeader('accept-ranges', 'bytes');
  res.setHeader('content-length', stats.size);
  if (metadata.sha256) res.setHeader('etag', getEtag(metadata.sha256));
  res.end();
}

async function onReadFile(req, res, args) {
  const { binId = '', fileId = '' } = args;
  const filePath = join(rootDir, binId, fileId);
  const metaPath = filePath + '.meta';

  if (!(binId && fileId && existsSync(filePath))) {
    return notFound(res);
  }

  tryCatch(res, async () => {
    const meta = await readMetaFile(metaPath);
    const system = await readSystemMetadata(binId, fileId);
    const stats = await stat(filePath);

    Object.entries(meta).forEach(([key, value]) => res.setHeader(key == 'type' ? 'content-type' : key, String(value)));

    res.setHeader('content-length', stats.size);
    res.setHeader('last-modified', new Date(stats.mtime).toString());
    res.setHeader('accept-ranges', 'bytes');
    if (system.sha256) res.setHeader('etag', getEtag(system.sha256));

    const range = parseByteRange(req.headers.range, stats.size);
    const ifRange = req.headers['if-range'];
    const rangeAllowed = range && (!ifRange || ifRange === getEtag(system.sha256));
    if (req.headers.range && !range) {
      res.writeHead(416, { 'content-range': `bytes */${stats.size}` }).end();
      return;
    }
    if (rangeAllowed) {
      res.writeHead(206, {
        'content-length': range.end - range.start + 1,
        'content-range': `bytes ${range.start}-${range.end}/${stats.size}`,
      });
      createReadStream(filePath, { start: range.start, end: range.end }).pipe(res);
      return;
    }
    createReadStream(filePath).pipe(res);
  });
}

function parseByteRange(value: string | undefined, size: number): ByteRange | null {
  if (!value) return null;
  const match = /^bytes=(\d+)-(\d*)$/.exec(value);
  if (!match || size === 0) return null;
  const start = Number(match[1]);
  const requestedEnd = match[2] ? Number(match[2]) : size - 1;
  const end = Math.min(requestedEnd, size - 1);
  return Number.isSafeInteger(start) && Number.isSafeInteger(end) && start <= end && start < size
    ? { start, end }
    : null;
}

async function onReadUpload(_req, res, args) {
  const { binId = '', fileId = '' } = args;
  const statePath = getUploadStatePath(binId, fileId);
  const state = await withUploadLock(statePath, async () => {
    await recoverCompletedUpload(binId, fileId);
    return readUploadState(binId, fileId);
  });
  if (!state) return notFound(res);
  res.writeHead(200, jsonHeaders).end(JSON.stringify({ total: state.total, ranges: state.ranges, complete: false }));
}

async function readMetadata(binId: string, fileId: string, baseUrl: string | URL) {
  const filePath = join(...[rootDir, binId, fileId].filter(Boolean));

  if (!(binId && existsSync(filePath))) {
    return null;
  }

  try {
    const metaPath = filePath + '.meta';
    const meta = await readMetaFile(metaPath);
    const system = await readSystemMetadata(binId, fileId);
    const stats = await stat(filePath);

    return {
      ...meta,
      id: fileId || undefined,
      bin: binId,
      size: stats.size,
      name: meta.name || fileId,
      lastModified: new Date(stats.mtime).toISOString(),
      ...(system.sha256 ? { sha256: system.sha256, etag: getEtag(system.sha256) } : {}),
      ...(system.immutable ? { immutable: true } : {}),
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

async function getAuthClient() {
  authClientPromise ||= loadAuthClient();
  const auth = await authClientPromise;
  if (!auth) authClientPromise = null;
  return auth;
}

async function getOidcProfile(auth, tokens): Promise<any> {
  if (!tokens.id_token || !tokens.access_token) {
    throw new Error('OIDC provider did not return both ID and access tokens');
  }
  const claims: any = await auth.verifyToken(tokens.id_token);
  const profile = await getOidcUserInfo(tokens.access_token);
  return { ...profile, sub: profile.sub || claims.sub, iss: profile.iss || claims.iss };
}

async function getOidcUserInfo(accessToken: string): Promise<any> {
  const response = await fetch(new URL('/userinfo', authIssuer), {
    headers: {
      authorization: `Bearer ${accessToken}`,
      'x-auth-audience': oidcClientId,
    },
  });
  if (!response.ok) throw new Error(`Could not load profile: ${response.status}`);
  return response.json();
}

async function getDatabase() {
  return databasePromise;
}

function getCookie(req, name: string) {
  return String(req.headers.cookie || '')
    .split(';')
    .map((part) => part.trim().split('='))
    .find(([key]) => key === name)?.[1];
}

function sign(value: string) {
  return createHmac('sha256', sessionSecret).update(value).digest('base64url');
}

function setCookie(req, res, name: string, value: string, maxAge: number) {
  const secure = getProxyHost(req).startsWith('https:') ? '; Secure' : '';
  const cookie = `${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure}`;
  const existing = res.getHeader('set-cookie');
  res.setHeader('set-cookie', existing ? [...(Array.isArray(existing) ? existing : [existing]), cookie] : cookie);
}

async function refreshOidcSession(database, session) {
  if (!session.refresh_token || !oidcClientSecret || !oidcClientId) return null;
  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: session.refresh_token,
    client_id: oidcClientId,
    client_secret: oidcClientSecret,
  });
  const response = await fetch(new URL('/token', authIssuer), {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (!response.ok) return null;
  const tokens: any = await response.json();
  const profile = tokens.access_token ? await getOidcUserInfo(tokens.access_token) : JSON.parse(session.profile);
  const expiresAt = Date.now() + (Number(tokens.expires_in) || 300) * 1000;
  await database.run(
    'UPDATE oidc_sessions SET profile = ?, access_token = ?, refresh_token = ?, expires_at = ? WHERE id = ?',
    [
      JSON.stringify(profile),
      tokens.access_token,
      tokens.refresh_token || session.refresh_token,
      expiresAt,
      session.id,
    ],
  );
  return profile;
}

async function getSessionProfile(req) {
  const raw = getCookie(req, 'filebin_session');
  if (!raw) return null;
  const [id, signature] = raw.split('.');
  const expected = Buffer.from(sign(id || ''));
  const actual = Buffer.from(signature || '');
  if (!id || actual.length !== expected.length || !timingSafeEqual(actual, expected)) return null;
  const database = await getDatabase();
  const session = database && (await database.get('SELECT * FROM oidc_sessions WHERE id = ?', [id]));
  if (!session) return null;
  if (session.expires_at > Date.now()) return JSON.parse(session.profile);
  return refreshOidcSession(database, session).catch(() => null);
}

async function getPrincipal(req) {
  const profile = await getSessionProfile(req);
  return profile?.sub ? { issuer: profile.iss || authIssuer, subject: profile.sub, profile } : null;
}

async function listOwnedBins(database, principal) {
  const bins = await database.all(
    `SELECT b.id, b.name, b.visibility, COALESCE(SUM(f.size), 0) AS size
     FROM storage_bins b
     LEFT JOIN storage_files f ON f.bin_id = b.id
     WHERE rtrim(replace(b.owner_issuer, '"', ''), '/') = rtrim(?, '/')
       AND replace(b.owner_subject, '"', '') = ?
     GROUP BY b.id, b.visibility
     ORDER BY b.created_at DESC`,
    [principal.issuer, principal.subject],
  );
  return Promise.all(bins.map(async (bin) => ({ ...bin, protected: await isBinLocked(bin.id) })));
}

async function getStorageBin(binId: string) {
  const database = await getDatabase();
  return database && database.get('SELECT * FROM storage_bins WHERE id = ?', [binId]);
}

async function markBinForDeletion(req, binId: string) {
  const database = await getDatabase();
  if (!database) return false;
  const now = Date.now();
  const expiresAt = now + binDeletionGraceMs;
  await database.run('UPDATE storage_bins SET deletion_requested_at = ?, deletion_expires_at = ? WHERE id = ?', [
    now,
    expiresAt,
    binId,
  ]);
  await audit(req, 'bin.delete_requested', binId);
  return true;
}

async function permanentlyDeleteBin(binId: string) {
  const database = await getDatabase();
  await rm(join(rootDir, binId), { recursive: true, force: true });
  await rm(join(rootDir, `${binId}.meta`), { force: true });
  if (database) {
    await database.run('DELETE FROM storage_uploads WHERE bin_id = ?', [binId]);
    await database.run('DELETE FROM storage_files WHERE bin_id = ?', [binId]);
    await database.run('DELETE FROM storage_bins WHERE id = ?', [binId]);
  }
}

async function audit(req, action: string, target: string) {
  const principal = await getPrincipal(req);
  const database = await getDatabase();
  if (database)
    await database.run('INSERT INTO audit_events (actor_subject, action, target, created_at) VALUES (?, ?, ?, ?)', [
      principal?.subject || null,
      action,
      target || 'unknown',
      Date.now(),
    ]);
}

async function importDiskCatalog() {
  const database = await getDatabase();
  if (!database || !rootDir || !existsSync(rootDir)) return;
  const now = Date.now();
  const bins = await readdir(rootDir, { withFileTypes: true });
  for (const entry of bins.filter((entry) => entry.isDirectory())) {
    const binPath = join(rootDir, entry.name);
    const binStats = await stat(binPath);
    const files = await readdir(binPath);
    const completed = files.filter(
      (file) => !file.endsWith('.meta') && !file.endsWith('.system') && !file.startsWith('.upload-'),
    );
    const uploadTimes = await Promise.all(completed.map(async (file) => (await stat(join(binPath, file))).mtimeMs));
    const lastCompletedUploadAt = uploadTimes.length ? Math.max(...uploadTimes) : null;
    await database.run(
      'INSERT OR IGNORE INTO storage_bins (id, name, visibility, created_at, last_completed_upload_at, imported_at) VALUES (?, ?, ?, ?, ?, ?)',
      [entry.name, generateBinName(), 'public', binStats.birthtimeMs || binStats.mtimeMs, lastCompletedUploadAt, now],
    );
    for (const fileId of completed) {
      const filePath = join(binPath, fileId);
      const [metadata, systemMetadata, fileStats] = await Promise.all([
        readMetaFile(`${filePath}.meta`),
        readSystemMetadata(entry.name, fileId),
        stat(filePath),
      ]);
      await database.run(
        'INSERT OR REPLACE INTO storage_files (bin_id, id, metadata, system_metadata, size, updated_at) VALUES (?, ?, ?, ?, ?, ?)',
        [
          entry.name,
          fileId,
          JSON.stringify(metadata),
          JSON.stringify(systemMetadata),
          fileStats.size,
          fileStats.mtimeMs,
        ],
      );
    }
    for (const stateFile of files.filter((file) => file.startsWith('.upload-') && file.endsWith('.json'))) {
      const fileId = stateFile.slice('.upload-'.length, -'.json'.length);
      const statePath = join(binPath, stateFile);
      const [state, stateStats] = await Promise.all([readFile(statePath, 'utf8'), stat(statePath)]);
      await database.run(
        'INSERT OR REPLACE INTO storage_uploads (bin_id, file_id, state, updated_at) VALUES (?, ?, ?, ?)',
        [entry.name, fileId, state, stateStats.mtimeMs],
      );
    }
  }
}

async function recordCompletedFile(binId: string, fileId: string) {
  const database = await getDatabase();
  if (!database) return;
  const filePath = join(rootDir, binId, fileId);
  const [metadata, systemMetadata, fileStats] = await Promise.all([
    readMetaFile(`${filePath}.meta`),
    readSystemMetadata(binId, fileId),
    stat(filePath),
  ]);
  const now = Date.now();
  await database.run(
    'INSERT OR REPLACE INTO storage_files (bin_id, id, metadata, system_metadata, size, updated_at) VALUES (?, ?, ?, ?, ?, ?)',
    [binId, fileId, JSON.stringify(metadata), JSON.stringify(systemMetadata), fileStats.size, fileStats.mtimeMs],
  );
  await database.run('UPDATE storage_bins SET last_completed_upload_at = ? WHERE id = ?', [now, binId]);
  await database.run('DELETE FROM storage_uploads WHERE bin_id = ? AND file_id = ?', [binId, fileId]);
}

async function onAuthProfile(req, res) {
  const profile = await getSessionProfile(req);
  if (!profile) return unauthenticated(res);
  res.writeHead(200, jsonHeaders).end(JSON.stringify(profile));
}

async function onAuthBins(req, res) {
  const principal = await getPrincipal(req);
  const database = await getDatabase();
  if (!principal || !database) return unauthenticated(res);
  const summaries = await listOwnedBins(database, principal);
  res.writeHead(200, jsonHeaders).end(JSON.stringify(summaries));
}

async function readAuthState(req) {
  try {
    const profile = await getSessionProfile(req);
    if (!profile) return { profile: null, binList: [] };
    const database = await getDatabase();
    const bins = database
      ? await listOwnedBins(database, { issuer: profile.iss || authIssuer, subject: profile.sub })
      : [];
    return { profile, binList: bins };
  } catch {
    return { profile: null, binList: [] };
  }
}

async function onAuthLogin(req, res) {
  const auth = await getAuthClient();
  if (oidcMissingConfiguration.length) {
    return res.writeHead(503).end(`OIDC configuration missing: ${oidcMissingConfiguration.join(', ')}`);
  }
  if (!auth) return res.writeHead(503).end('OIDC provider client is unavailable');
  const forwardedProtocol = String(req.headers['x-forwarded-proto'] || 'https').split(',')[0];
  const forwardedHost = String(req.headers['x-forwarded-host'] || req.headers.host || 'localhost').split(',')[0];
  const origin = `${forwardedProtocol}://${forwardedHost}`;
  const requestedUrl = new URL(req.url, origin).searchParams.get('url') || `${origin}/app`;
  const url = new URL(requestedUrl, origin);
  if (url.origin !== origin) url.href = `${origin}/app`;
  const redirectUri = `${origin}/auth/callback`;
  const authorization = auth.createAuthorizationRequest({ redirectUri });
  const authorizationUrl = new URL(authorization.url);
  authorizationUrl.searchParams.set('scope', 'openid profile offline_access');
  const state = Buffer.from(
    JSON.stringify({ ...authorization, url: String(url), expires: Date.now() + 10 * 60 * 1000 }),
  ).toString('base64url');
  setCookie(req, res, 'filebin_oidc', `${state}.${sign(state)}`, 600);
  res.writeHead(302, { location: String(authorizationUrl) }).end();
}

async function onAuthCallback(req, res) {
  const auth = await getAuthClient();
  const cookie = getCookie(req, 'filebin_oidc');
  const [state, signature] = String(cookie || '').split('.');
  const expected = Buffer.from(sign(state || ''));
  const actual = Buffer.from(signature || '');
  if (!auth || !oidcClientSecret || !state || actual.length !== expected.length || !timingSafeEqual(actual, expected))
    return unauthenticated(res);
  const saved = JSON.parse(Buffer.from(state, 'base64url').toString('utf8'));
  const url = new URL(req.url, getProxyHost(req));
  if (saved.expires < Date.now() || url.searchParams.get('state') !== saved.state || !url.searchParams.get('code'))
    return unauthorized(res);
  const tokens = await auth.exchangeCode({
    code: url.searchParams.get('code'),
    codeVerifier: saved.codeVerifier,
    redirectUri: `${url.origin}/auth/callback`,
    clientSecret: oidcClientSecret,
  });
  const profile = await getOidcProfile(auth, tokens);
  const id = randomUUID();
  const database = await getDatabase();
  if (!database) return res.writeHead(503).end('Database unavailable');
  await database.run(
    'INSERT INTO oidc_sessions (id, profile, access_token, refresh_token, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)',
    [
      id,
      JSON.stringify(profile),
      tokens.access_token,
      tokens.refresh_token || null,
      Date.now() + (Number(tokens.expires_in) || 3600) * 1000,
      Date.now(),
    ],
  );
  setCookie(req, res, 'filebin_session', `${id}.${sign(id)}`, sessionCookieMaxAge);
  setCookie(req, res, 'filebin_oidc', '', 0);
  await audit(req, 'auth.login', profile.sub);
  res.writeHead(302, { location: saved.url }).end();
}

async function onAuthLogout(req, res) {
  const raw = getCookie(req, 'filebin_session');
  const id = raw?.split('.')[0];
  const database = await getDatabase();
  if (id && database) await database.run('DELETE FROM oidc_sessions WHERE id = ?', [id]);
  setCookie(req, res, 'filebin_session', '', 0);
  res.writeHead(204).end();
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
    const metadata = meta ? JSON.parse(meta) : {};
    const immutable = metadata?.immutable === true;

    if (meta) {
      const userMetadata = { ...metadata };
      delete userMetadata.immutable;
      await writeFile(join(binPath, fileId + '.meta'), JSON.stringify(userMetadata));
    }

    await writeFile(getUploadDataPath(binId, fileId), '');
    await writeUploadState(binId, fileId, { total: null, ranges: [], pending: [], parts: [], immutable });

    res.setHeader('location', String(new URL(`/f/${binId}/${fileId}`, getProxyHost(req))));
    res.writeHead(201).end(`{"fileId": "${fileId}"}`);
  });
}

async function onWriteFile(req, res, args) {
  const { binId = '', fileId = '' } = args;
  const filePath = join(rootDir, binId, fileId);
  const uploadPath = getUploadDataPath(binId, fileId);
  const statePath = getUploadStatePath(binId, fileId);
  const system = await readSystemMetadata(binId, fileId);

  if (!(binId && fileId && (existsSync(filePath) || existsSync(statePath)))) {
    return notFound(res);
  }
  if (system.immutable) return res.writeHead(409).end('File is immutable');

  const contentRange = parseContentRange(req.headers['content-range']);
  if (req.headers['content-range'] && !contentRange) return badRequest(res, 'Invalid Content-Range header');

  if (!contentRange) {
    const temporaryPath = `${uploadPath}.replace-${randomUUID()}`;
    const writer = createWriteStream(temporaryPath);
    req.pipe(writer);
    writer.on('error', () => {
      rm(temporaryPath, { force: true }).catch(() => {});
      if (!res.headersSent) res.writeHead(500).end('Failed to write file');
    });
    writer.on('close', async () => {
      try {
        const sha256 = await sha256File(temporaryPath);
        await rename(temporaryPath, filePath);
        await Promise.all([rm(uploadPath, { force: true }), rm(statePath, { force: true })]);
        await writeSystemMetadata(binId, fileId, { sha256, committedAt: new Date().toISOString() });
        await recordCompletedFile(binId, fileId);
        sendFileReference(req, res, binId, fileId);
      } catch {
        if (!res.headersSent) res.writeHead(500).end('Failed to write file');
      }
    });
    return;
  }

  const digest = String(req.headers.digest || '');
  if (!/^sha-256=[A-Za-z0-9+/]+={0,2}$/.test(digest)) return badRequest(res, 'A SHA-256 Digest header is required');
  const range: ByteRange = { start: contentRange.start, end: contentRange.end };
  let state: UploadState | null = null;
  let duplicate = false;
  await withUploadLock(statePath, async () => {
    await recoverCompletedUpload(binId, fileId);
    state = await readUploadState(binId, fileId);
    if (!state || (state.total !== null && state.total !== contentRange.total)) {
      state = null;
      return;
    }
    duplicate = state.parts.some(
      (part) => part.start === range.start && part.end === range.end && part.digest === digest,
    );
    if (rangesOverlap([...state.ranges, ...state.pending], range) && !duplicate) {
      state = null;
      return;
    }
    if (duplicate) return;
    state.total = contentRange.total;
    state.pending.push(range);
    await writeUploadState(binId, fileId, state);
  });
  if (!state) {
    if (existsSync(filePath)) {
      req.resume();
      req.on('end', () => sendFileReference(req, res, binId, fileId));
      return;
    }
    return res.writeHead(409).end('Conflicting upload range or total size');
  }
  if (duplicate) {
    req.resume();
    req.on('end', () => res.writeHead(202, jsonHeaders).end(JSON.stringify({ complete: false })));
    return;
  }

  const hash = createHash('sha256');
  let written = 0;
  const writer = createWriteStream(uploadPath, { flags: 'r+', start: range.start });
  req.on('data', (chunk) => {
    written += chunk.length;
    hash.update(chunk);
  });
  req.pipe(writer);

  const discardRange = async () =>
    withUploadLock(statePath, async () => {
      const current = await readUploadState(binId, fileId);
      if (!current) return;
      current.pending = current.pending.filter((item) => item.start !== range.start || item.end !== range.end);
      await writeUploadState(binId, fileId, current);
    });

  writer.on('error', async () => {
    await discardRange();
    if (!res.headersSent) res.writeHead(500).end('Failed to write upload part');
  });
  writer.on('close', async () => {
    if (written !== range.end - range.start + 1 || `sha-256=${hash.digest('base64')}` !== digest) {
      await discardRange();
      return badRequest(res, 'Upload part does not match its range or digest');
    }

    try {
      let complete = false;
      await withUploadLock(statePath, async () => {
        const current = await readUploadState(binId, fileId);
        if (!current) throw new Error('Upload session disappeared');
        current.pending = current.pending.filter((item) => item.start !== range.start || item.end !== range.end);
        current.ranges = mergeRanges([...current.ranges, range]);
        current.parts.push({ ...range, digest });
        complete = isUploadComplete(current);
        if (complete) {
          const sha256 = await sha256File(uploadPath);
          await writeUploadState(binId, fileId, current);
          await rename(uploadPath, filePath);
          await rm(statePath, { force: true });
          await writeSystemMetadata(binId, fileId, {
            sha256,
            committedAt: new Date().toISOString(),
            ...(current.immutable ? { immutable: true } : {}),
          });
        } else {
          await writeUploadState(binId, fileId, current);
        }
      });
      if (complete) {
        await recordCompletedFile(binId, fileId);
        sendFileReference(req, res, binId, fileId);
      } else res.writeHead(202, jsonHeaders).end(JSON.stringify({ complete: false }));
    } catch {
      if (!res.headersSent) res.writeHead(500).end('Failed to finalize upload');
    }
  });
}

function sendFileReference(req, res, binId: string, fileId: string) {
  res.writeHead(202, jsonHeaders).end(
    JSON.stringify({
      id: fileId,
      bin: binId,
      url: String(new URL(`/f/${binId}/${fileId}`, getProxyHost(req))),
    }),
  );
}

async function readBin(binId: string) {
  const binPath = join(rootDir, binId);

  if (!(binId && existsSync(binPath))) {
    return null;
  }

  const allFiles = await readdir(binPath);
  return allFiles.filter((f) => !f.endsWith('.meta') && !f.endsWith('.system') && !f.startsWith('.upload-'));
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

async function onCreateBin(req, res) {
  tryCatch(res, async () => {
    const binId = randomUUID();
    const name = generateBinName();
    await ensureDir(join(rootDir, binId));
    const principal = await getPrincipal(req);
    const database = await getDatabase();
    if (database) {
      const now = Date.now();
      await database.run(
        'INSERT INTO storage_bins (id, name, visibility, owner_issuer, owner_subject, created_at) VALUES (?, ?, ?, ?, ?, ?)',
        [binId, name, principal ? 'private' : 'public', principal?.issuer || null, principal?.subject || null, now],
      );
    }
    if (principal && database) {
      await audit(req, 'bin.create', binId);
    }
    res.setHeader('location', String(new URL('/bin/' + binId, getProxyHost(req))));
    res.writeHead(201).end(JSON.stringify({ binId, name }));
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
  const { newId = '', name, visibility } = await readJson(req);
  if (newId) return onRenameBin(req, res, { ...args, newId });
  if (typeof name === 'string') {
    const value = name.trim();
    if (!value || value.length > 80) return badRequest(res);
    const database = await getDatabase();
    if (!database || !(await getStorageBin(args.binId))) return res.writeHead(404).end('Not found');
    await database.run('UPDATE storage_bins SET name = ? WHERE id = ?', [value, args.binId]);
    await audit(req, 'bin.name.updated', args.binId);
    return res.writeHead(204).end();
  }
  if (!['public', 'private'].includes(visibility)) return badRequest(res);

  const bin = await getStorageBin(args.binId);
  const principal = await getPrincipal(req);
  if (!bin || !principal || bin.owner_issuer !== principal.issuer || bin.owner_subject !== principal.subject) {
    return unauthenticated(res);
  }

  const database = await getDatabase();
  if (!database) return res.writeHead(503).end('Database unavailable');
  await database.run('UPDATE storage_bins SET visibility = ? WHERE id = ?', [visibility, args.binId]);
  await audit(req, `bin.visibility.${visibility}`, args.binId);
  res.writeHead(204).end();
}

async function onDeleteFile(_req, res, args) {
  const { binId = '', fileId = '' } = args;
  const filePath = join(rootDir, binId, fileId);
  const metaPath = join(rootDir, binId, fileId + '.meta');

  const uploadPath = getUploadDataPath(binId, fileId);
  const uploadStatePath = getUploadStatePath(binId, fileId);
  const system = await readSystemMetadata(binId, fileId);
  if (!(binId && fileId && (existsSync(filePath) || existsSync(uploadStatePath)))) {
    return notFound(res);
  }
  if (system.immutable) return res.writeHead(409).end('File is immutable');

  tryCatch(res, async () => {
    await rm(filePath, { force: true });

    if (existsSync(metaPath)) {
      await unlink(metaPath);
    }
    await Promise.all([rm(uploadPath, { force: true }), rm(uploadStatePath, { force: true })]);
    await rm(getSystemMetadataPath(binId, fileId), { force: true });

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
    if (!(await getDatabase())) {
      await rm(binPath, { recursive: true });
      return res.end('OK');
    }
    await importDiskCatalog();
    if (!(await getStorageBin(binId))) return res.writeHead(404).end('Not found');
    if (!(await markBinForDeletion(_req, binId))) return res.writeHead(503).end('Database unavailable');
    res.writeHead(202, jsonHeaders).end(JSON.stringify({ binId, deletionGraceHours: binDeletionGraceMs / 3600000 }));
  });
}

async function onRestoreBin(req, res, args) {
  const { binId = '' } = args;
  const bin = await getStorageBin(binId);
  const principal = await getPrincipal(req);
  if (!bin || !principal || bin.owner_issuer !== principal.issuer || bin.owner_subject !== principal.subject) {
    return unauthenticated(res);
  }
  const database = await getDatabase();
  await database.run('UPDATE storage_bins SET deletion_requested_at = NULL, deletion_expires_at = NULL WHERE id = ?', [
    binId,
  ]);
  await audit(req, 'bin.restored', binId);
  res.writeHead(204).end();
}

async function onApiSpec(req, res) {
  const isJson = new URL(req.url, 'http://localhost').pathname.endsWith('.json');
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

function serializeState(state) {
  return JSON.stringify(state).replaceAll('<', '\\u003c').replaceAll('>', '\\u003e').replaceAll('&', '\\u0026');
}

function onGetUI(req, res, args) {
  tryCatch(res, async () => {
    const { binId } = args;
    const requestedBinId = binId || new URL(req.url, 'http://localhost').searchParams.get('bin');
    let state: any = await readAuthState(req);

    if (requestedBinId) {
      const baseUrl = getProxyHost(req);
      const fileIds = await readBin(requestedBinId);

      if (fileIds === null) {
        return notFound(res);
      }

      const locked = await isBinLocked(requestedBinId);
      const unlocked = !locked || (await isBinAuthorized(req, requestedBinId));
      const files = unlocked ? await Promise.all(fileIds.map((x) => readMetadata(requestedBinId, x, baseUrl))) : [];
      const bin = await getStorageBin(requestedBinId);

      state = {
        ...state,
        binName: bin?.name || '',
        files,
        filesLoaded: true,
        locked,
        unlocked,
      };
    }

    res
      .writeHead(200, { 'content-type': 'text/html', 'cache-control': 'private, no-store' })
      .end(indexFile.replace('<!-- %state% -->', serializeState(state || {})));
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
    const files = allFiles.filter((f) => !f.endsWith('.meta') && !f.endsWith('.system') && !f.startsWith('.upload-'));

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
  res
    .writeHead(401, { ...jsonHeaders, 'www-authenticate': 'Basic realm="FileBin"' })
    .end(JSON.stringify({ error: 'This bin is locked' }));
}

function unauthenticated(res) {
  res.writeHead(401, jsonHeaders).end(JSON.stringify({ error: 'Authentication required' }));
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

async function cleanupAbandonedUploads() {
  if (!Number.isFinite(uploadRetentionMs) || uploadRetentionMs <= 0) return;
  const cutoff = Date.now() - uploadRetentionMs;
  const bins = await readdir(rootDir, { withFileTypes: true });
  await Promise.all(
    bins
      .filter((entry) => entry.isDirectory())
      .map(async (entry) => {
        const binPath = join(rootDir, entry.name);
        const files = await readdir(binPath);
        await Promise.all(
          files
            .filter((file) => file.startsWith('.upload-') && file.endsWith('.json'))
            .map(async (file) => {
              const statePath = join(binPath, file);
              const stats = await stat(statePath).catch(() => null);
              if (!stats || stats.mtimeMs >= cutoff) return;
              const fileId = file.slice('.upload-'.length, -'.json'.length);
              await withUploadLock(statePath, async () => {
                const current = await stat(statePath).catch(() => null);
                if (!current || current.mtimeMs >= cutoff) return;
                await Promise.all([
                  rm(statePath, { force: true }),
                  rm(join(binPath, `.upload-${fileId}`), { force: true }),
                ]);
              });
            }),
        );
      }),
  );
}

async function cleanupExpiredPublicBins() {
  const database = await getDatabase();
  if (!database || !Number.isFinite(publicBinRetentionMs) || publicBinRetentionMs <= 0) return [];
  await importDiskCatalog();
  const now = Date.now();
  const cutoff = now - publicBinRetentionMs;
  const bins = await database.all(
    `SELECT id FROM storage_bins
     WHERE (visibility = 'public' AND owner_subject IS NULL AND last_completed_upload_at IS NOT NULL AND last_completed_upload_at < ?)
        OR (deletion_expires_at IS NOT NULL AND deletion_expires_at < ?)`,
    [cutoff, now],
  );
  for (const { id } of bins) {
    await permanentlyDeleteBin(id);
  }
  return bins.map((bin) => bin.id);
}

async function onPublicBinCleanup(req, res) {
  const token = String(req.headers.authorization || '').replace(/^Bearer /, '');
  if (!publicBinCleanupToken || token !== publicBinCleanupToken) return unauthenticated(res);
  const deleted = await cleanupExpiredPublicBins();
  res.writeHead(200, jsonHeaders).end(JSON.stringify({ deleted }));
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
  } catch {
    // Missing or malformed metadata is treated as empty metadata.
  }

  return {};
}

const match = router({
  'GET /': onGetUI,
  'GET /app': onGetUI,
  'GET /help': onGetUI,
  'GET /auth/profile': onAuthProfile,
  'GET /api/bins': onAuthBins,
  'GET /auth/login': onAuthLogin,
  'GET /auth/callback': onAuthCallback,
  'POST /auth/logout': onAuthLogout,
  'POST /admin/cleanup': onPublicBinCleanup,
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
  'POST /bin/:binId/restore': onRestoreBin,

  'POST /f/:binId': onCreateFile,
  'HEAD /f/:binId/:fileId': onFileExists,
  'GET /f/:binId/:fileId/upload': onReadUpload,
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

  cleanupAbandonedUploads().catch((error) => console.log(error));
  importDiskCatalog().catch((error) => console.log(error));
  const cleanupTimer = setInterval(
    () => cleanupAbandonedUploads().catch((error) => console.log(error)),
    uploadCleanupIntervalMs,
  );
  cleanupTimer.unref();

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
