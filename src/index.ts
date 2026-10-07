import type { IncomingMessage } from 'node:http';
import { createServer } from 'node:http';
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  randomUUID,
  scrypt as scryptCallback,
  timingSafeEqual,
} from 'node:crypto';
import { createReadStream, createWriteStream, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { readFile, unlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import router from 'micro-router';
import * as yazl from 'yazl';
import * as yauzl from 'yauzl';
import { load } from 'js-yaml';
import { promisify } from 'node:util';

const authIssuer = process.env.AUTH_PROVIDER?.replace(/\/+$/, '');
const oidcClientId = process.env.OIDC_CLIENT_ID;
const oidcClientSecret = process.env.OIDC_CLIENT_SECRET;
const databaseModuleUrl = process.env.DATABASE_URL;
const adminSubjects = new Set(
  String(process.env.ADMIN_SUBJECTS || '')
    .split(',')
    .map((subject) => subject.trim())
    .filter(Boolean),
);
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

const binCleanupToken = process.env.BIN_CLEANUP_TOKEN;
const binDeletionGraceMs = Number(process.env.BIN_DELETION_GRACE_HOURS || 168) * 60 * 60 * 1000;
const binStorageQuotaBytes = Math.max(0, Number(process.env.BIN_MAX_STORAGE_BYTES || 0));
const sessionCookieMaxAge = 30 * 24 * 60 * 60;
const s3Endpoint = process.env.S3_DEFAULT_ENDPOINT || 'https://s3.api.apphor.de';
const s3Region = process.env.S3_DEFAULT_REGION || 'local';
const s3CredentialEncryptionKey = process.env.S3_CREDENTIAL_ENCRYPTION_KEY;
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
CREATE TABLE IF NOT EXISTS user_s3_credentials (
          id TEXT PRIMARY KEY,
          user_issuer TEXT NOT NULL,
          user_subject TEXT NOT NULL,
          access_key TEXT NOT NULL,
          secret_key TEXT NOT NULL DEFAULT '',
          encrypted_secret TEXT,
          encryption_iv TEXT,
          encryption_tag TEXT,
          endpoint TEXT NOT NULL,
          region TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL,
          revoked_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_user_s3_credentials_user ON user_s3_credentials (user_issuer, user_subject);
        CREATE TABLE IF NOT EXISTS storage_bins (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          visibility TEXT NOT NULL DEFAULT 'private' CHECK (visibility = 'private'),
         owner_issuer TEXT,
         owner_subject TEXT,
         bucket_name TEXT,
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
       CREATE TABLE IF NOT EXISTS storage_bin_quota_overrides (
         bin_id TEXT PRIMARY KEY,
         extra_bytes INTEGER NOT NULL,
         updated_at INTEGER NOT NULL
       );
       CREATE TABLE IF NOT EXISTS audit_events (
        id INTEGER PRIMARY KEY,
        actor_subject TEXT,
        action TEXT NOT NULL,
        target TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
    `);
        for (const column of [
          'name TEXT',
          'deletion_requested_at INTEGER',
          'deletion_expires_at INTEGER',
          'bucket_name TEXT',
          'lock_salt TEXT',
          'lock_hash TEXT',
        ]) {
          await database.exec(`ALTER TABLE storage_bins ADD COLUMN ${column}`).catch(() => {});
        }
        for (const column of ['encrypted_secret TEXT', 'encryption_iv TEXT', 'encryption_tag TEXT', 'bucket_name TEXT']) {
          await database.exec(`ALTER TABLE user_s3_credentials ADD COLUMN ${column}`).catch(() => {});
        }
        const unnamedBins = await database.all(`SELECT id FROM storage_bins WHERE name IS NULL OR name = ''`);
        await Promise.all(
          unnamedBins.map((bin) =>
            database.run('UPDATE storage_bins SET name = ? WHERE id = ?', [generateBinName(), bin.id]),
          ),
        );
        await database.run("UPDATE storage_bins SET visibility = 'private' WHERE visibility <> 'private'");
        for (const column of ['access_token', 'refresh_token']) {
          await database.exec(`ALTER TABLE oidc_sessions ADD COLUMN ${column} TEXT`).catch(() => {});
        }
        return database;
      })
      .catch(() => null)
  : Promise.resolve(null);
const jsonHeaders = { 'content-type': 'application/json' };
const sessionSecret = process.env.SESSION_SECRET || randomBytes(32);
const scrypt = promisify(scryptCallback);
const uploadLocks = new Map<string, Promise<void>>();
const binStorageLocks = new Map<string, Promise<void>>();
const uploadRetentionMs = Number(process.env.UPLOAD_RETENTION_HOURS || 72) * 60 * 60 * 1000;
const uploadCleanupIntervalMs = Number(process.env.UPLOAD_CLEANUP_INTERVAL_MINUTES || 60) * 60 * 1000;

/* eslint-disable no-unused-vars */
interface StorageBackend {
  createBucket(_binId: string): Promise<void>;
  bucketExists(_binId: string): Promise<boolean>;
  writeObject(_binId: string, _fileId: string, _data: Uint8Array, _metadata?: Record<string, string>): Promise<{ sha256: string; size: number }>;
  readObject(_binId: string, _fileId: string, _range?: { start: number; end: number }): Promise<{ data: any; size: number; metadata: Record<string, string>; sha256?: string }>;
  deleteObject(_binId: string, _fileId: string): Promise<void>;
  listObjects(_binId: string): Promise<string[]>;
  getObjectMetadata(_binId: string, _fileId: string): Promise<{ size: number; metadata: Record<string, string>; sha256?: string; lastModified: number } | null>;
  createMultipartUpload(_binId: string, _fileId: string, _metadata?: Record<string, string>): Promise<string>;
  uploadPart(_binId: string, _fileId: string, _uploadId: string, _partNumber: number, _data: Uint8Array): Promise<{ etag: string }>;
  completeMultipartUpload(_binId: string, _fileId: string, _uploadId: string, _parts: Array<{ partNumber: number; etag: string }>): Promise<{ sha256: string; size: number }>;
  abortMultipartUpload(_binId: string, _fileId: string, _uploadId: string): Promise<void>;
  getBucketUsage(_binId: string): Promise<{ used: number; reserved: number }>;
  deleteBucket(_binId: string): Promise<void>;
}
/* eslint-enable no-unused-vars */

class S3StorageBackend implements StorageBackend {
  private principal: { issuer: string; subject: string };
  private s3Client: any;

  constructor(principal: { issuer: string; subject: string }) {
    this.principal = principal;
  }

  async init() {
    if (this.s3Client) return;
    const database = await getDatabase();
    if (!database) throw new Error('Database unavailable');

    const creds = await database.get(
      'SELECT * FROM user_s3_credentials WHERE user_issuer = ? AND user_subject = ? AND revoked_at IS NULL',
      [this.principal.issuer, this.principal.subject],
    );

    if (!creds) throw new Error('No S3 credentials found for user');

    const { S3Client } = await import('@aws-sdk/client-s3');
    this.s3Client = new S3Client({
      endpoint: creds.endpoint,
      region: creds.region,
      credentials: {
        accessKeyId: creds.access_key,
        secretAccessKey: await decryptS3Secret(creds),
      },
      forcePathStyle: true,
    });
  }

  async createBucket(binId: string): Promise<void> {
    await this.init();
    const { CreateBucketCommand, HeadBucketCommand } = await import('@aws-sdk/client-s3');
    try {
      await this.s3Client.send(new CreateBucketCommand({ Bucket: binId }));
    } catch (error) {
      const name = error?.name;
      if (name === 'BucketAlreadyOwnedByYou' || name === 'BucketAlreadyExists') {
        await this.s3Client.send(new HeadBucketCommand({ Bucket: binId }));
        return;
      }
      throw error;
    }
  }

  async bucketExists(binId: string): Promise<boolean> {
    await this.init();
    const { HeadBucketCommand } = await import('@aws-sdk/client-s3');
    try {
      await this.s3Client.send(new HeadBucketCommand({ Bucket: binId }));
      return true;
    } catch (error) {
      if (error?.$metadata?.httpStatusCode === 404 || error?.name === 'NotFound') return false;
      throw error;
    }
  }

  async getBucketName(binId: string): Promise<string> {
    const database = await getDatabase();
    if (!database) throw new Error('Database unavailable');
    const bin = await database.get('SELECT bucket_name FROM storage_bins WHERE id = ?', [binId]);
    if (!bin) {
      throw new Error(`No catalog record for bin ${binId}`);
    }
    return bin.bucket_name || binId;
  }

  async writeObject(_binId: string, _fileId: string, data: Uint8Array, metadata?: Record<string, string>): Promise<{ sha256: string; size: number }> {
    await this.init();
    const { PutObjectCommand } = await import('@aws-sdk/client-s3');
    const digest = createHash('sha256').update(data).digest();
    const sha256 = digest.toString('hex');
    
    const bucketName = await this.getBucketName(_binId);
    
    await this.s3Client.send(new PutObjectCommand({
      Bucket: bucketName,
      Key: `${_fileId}`,
      Body: data,
      Metadata: metadata,
      ChecksumSHA256: digest.toString('base64'),
    }));
    return { sha256, size: data.length };
  }

  async readObject(_binId: string, _fileId: string, range?: { start: number; end: number }): Promise<{ data: ReadableStream<Uint8Array>; size: number; metadata: Record<string, string>; sha256?: string }> {
    await this.init();
    const { GetObjectCommand } = await import('@aws-sdk/client-s3');
    const bucketName = await this.getBucketName(_binId);
    
    const command = new GetObjectCommand({
      Bucket: bucketName,
      Key: `${_fileId}`,
      Range: range ? `bytes=${range.start}-${range.end}` : undefined,
    });
    const response = await this.s3Client.send(command);
    return {
      data: response.Body as ReadableStream<Uint8Array>,
      size: response.ContentLength || 0,
      metadata: response.Metadata || {},
      sha256: response.Metadata?.sha256,
    };
  }

  async deleteObject(_binId: string, _fileId: string): Promise<void> {
    await this.init();
    const { DeleteObjectCommand } = await import('@aws-sdk/client-s3');
    const bucketName = await this.getBucketName(_binId);
    await this.s3Client.send(new DeleteObjectCommand({
      Bucket: bucketName,
      Key: `${_fileId}`,
    }));
  }

  async listObjects(_binId: string): Promise<string[]> {
    await this.init();
    const { ListObjectsV2Command } = await import('@aws-sdk/client-s3');
    const bucketName = await this.getBucketName(_binId);
    const keys: string[] = [];
    let continuationToken: string | undefined;
    do {
      const response = await this.s3Client.send(new ListObjectsV2Command({ Bucket: bucketName, ContinuationToken: continuationToken }));
      keys.push(...(response.Contents || []).map((obj: any) => obj.Key).filter(Boolean));
      continuationToken = response.NextContinuationToken;
    } while (continuationToken);
    return keys.filter((key) => !key.startsWith('.filebin/'));
  }

  async getObjectMetadata(_binId: string, _fileId: string): Promise<{ size: number; metadata: Record<string, string>; sha256?: string; lastModified: number } | null> {
    await this.init();
    const { HeadObjectCommand } = await import('@aws-sdk/client-s3');
    
    try {
      const bucketName = await this.getBucketName(_binId);
      const response = await this.s3Client.send(new HeadObjectCommand({
        Bucket: bucketName,
        Key: `${_fileId}`,
        ChecksumMode: 'ENABLED',
      }));
      
      return {
        size: response.ContentLength || 0,
        metadata: response.Metadata || {},
        sha256: response.Metadata?.sha256,
        lastModified: response.LastModified?.getTime() || Date.now(),
      };
    } catch (error) {
      if (error?.$metadata?.httpStatusCode === 404 || error?.name === 'NotFound' || error?.name === 'NoSuchKey') return null;
      throw error;
    }
  }

  async createMultipartUpload(_binId: string, _fileId: string, metadata?: Record<string, string>): Promise<string> {
    await this.init();
    const { CreateMultipartUploadCommand } = await import('@aws-sdk/client-s3');
    const bucketName = await this.getBucketName(_binId);
    
    const response = await this.s3Client.send(new CreateMultipartUploadCommand({
      Bucket: bucketName,
      Key: `${_fileId}`,
      Metadata: metadata,
    }));
    return response.UploadId!;
  }

  async uploadPart(_binId: string, _fileId: string, _uploadId: string, partNumber: number, data: Uint8Array): Promise<{ etag: string }> {
    await this.init();
    const { UploadPartCommand } = await import('@aws-sdk/client-s3');
    const checksum = createHash('sha256').update(data).digest('base64');
    const bucketName = await this.getBucketName(_binId);
    
    const response = await this.s3Client.send(new UploadPartCommand({
      Bucket: bucketName,
      Key: `${_fileId}`,
      UploadId: _uploadId,
      PartNumber: partNumber,
      Body: data,
      ChecksumSHA256: checksum,
    }));
    return { etag: response.ETag!.replace(/"/g, '') };
  }

  async completeMultipartUpload(_binId: string, _fileId: string, _uploadId: string, _parts: Array<{ partNumber: number; etag: string }>): Promise<{ sha256: string; size: number }> {
    await this.init();
    const { CompleteMultipartUploadCommand } = await import('@aws-sdk/client-s3');
    const bucketName = await this.getBucketName(_binId);
    
    await this.s3Client.send(new CompleteMultipartUploadCommand({
      Bucket: bucketName,
      Key: `${_fileId}`,
      UploadId: _uploadId,
      MultipartUpload: {
        Parts: _parts.map((part) => ({ PartNumber: part.partNumber, ETag: `"${part.etag}"` })),
      },
    }));
    const metadata = await this.getObjectMetadata(_binId, _fileId);
    if (!metadata) throw new Error('Completed S3 upload could not be verified');
    const { data } = await this.readObject(_binId, _fileId);
    const hash = createHash('sha256');
    for await (const chunk of data as AsyncIterable<Uint8Array>) hash.update(chunk);
    return { sha256: hash.digest('hex'), size: metadata.size };
  }

  async abortMultipartUpload(_binId: string, _fileId: string, _uploadId: string): Promise<void> {
    await this.init();
    const { AbortMultipartUploadCommand } = await import('@aws-sdk/client-s3');
    const bucketName = await this.getBucketName(_binId);
    await this.s3Client.send(new AbortMultipartUploadCommand({
      Bucket: bucketName,
      Key: `${_fileId}`,
      UploadId: _uploadId,
    }));
  }

  async getBucketUsage(_binId: string): Promise<{ used: number; reserved: number }> {
    await this.init();
    const { ListObjectsV2Command } = await import('@aws-sdk/client-s3');
    const bucketName = await this.getBucketName(_binId);
    let used = 0;
    let continuationToken: string | undefined;
    do {
      const response = await this.s3Client.send(new ListObjectsV2Command({
        Bucket: bucketName,
        ContinuationToken: continuationToken,
      }));
      for (const obj of response.Contents || []) {
        if (obj.Key && !obj.Key.startsWith('.filebin/')) used += obj.Size || 0;
      }
      continuationToken = response.NextContinuationToken;
    } while (continuationToken);
    return { used, reserved: 0 };
  }

  async deleteBucket(binId: string): Promise<void> {
    await this.init();
    const { DeleteBucketCommand, ListObjectsV2Command, DeleteObjectsCommand, ListObjectVersionsCommand, DeleteObjectCommand } = await import('@aws-sdk/client-s3');
    const bucketName = await this.getBucketName(binId);
    let continuationToken: string | undefined;

    do {
      const response = await this.s3Client.send(new ListObjectsV2Command({
        Bucket: bucketName,
        ContinuationToken: continuationToken,
      }));
      const objectsToDelete = (response.Contents || []).map((obj: any) => ({ Key: obj.Key })).filter((obj) => obj.Key);
      if (objectsToDelete.length) await this.s3Client.send(new DeleteObjectsCommand({ Bucket: bucketName, Delete: { Objects: objectsToDelete } }));
      continuationToken = response.NextContinuationToken;
    } while (continuationToken);

    let keyMarker: string | undefined;
    let versionIdMarker: string | undefined;
    do {
      const response = await this.s3Client.send(new ListObjectVersionsCommand({ Bucket: bucketName, KeyMarker: keyMarker, VersionIdMarker: versionIdMarker }));
      const versions = [
        ...(response.Versions || []).map((item: any) => ({ Key: item.Key, VersionId: item.VersionId })),
        ...(response.DeleteMarkers || []).map((item: any) => ({ Key: item.Key, VersionId: item.VersionId })),
      ].filter((item) => item.Key && item.VersionId);
      for (const item of versions) await this.s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, ...item }));
      keyMarker = response.NextKeyMarker;
      versionIdMarker = response.NextVersionIdMarker;
    } while (keyMarker);

    await this.s3Client.send(new DeleteBucketCommand({ Bucket: bucketName }));
  }
}

async function getStorageBackend(principal?: { issuer: string; subject: string } | null): Promise<StorageBackend> {
  if (!principal) throw new Error('Authentication required');
  const testAdapters = (globalThis as any).__FILEBIN_TEST_ADAPTERS__;
  if (process.env.NODE_ENV === 'test' && testAdapters?.storageFactory) return testAdapters.storageFactory(principal);
  return new S3StorageBackend(principal);
}

type ByteRange = { start: number; end: number };
type UploadPart = ByteRange & { digest: string; partNumber: number; etag?: string };
type UploadState = {
  total: number | null;
  ranges: ByteRange[];
  pending: ByteRange[];
  parts: UploadPart[];
  metadata: Record<string, string>;
  partSize: number;
  immutable?: boolean;
  uploadId?: string;
};
type SystemMetadata = { immutable?: boolean; committedAt?: string; sha256?: string };

function getUploadStatePath(binId: string, fileId: string) {
  return `${binId}:${fileId}`;
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

async function withBinStorageLock<T>(binId: string, fn: () => Promise<T>) {
  const previous = binStorageLocks.get(binId) || Promise.resolve();
  let release: () => void;
  const current = new Promise<void>((resolve) => (release = resolve));
  const queued = previous.then(() => current);
  binStorageLocks.set(binId, queued);
  await previous;
  try {
    return await fn();
  } finally {
    release!();
    if (binStorageLocks.get(binId) === queued) binStorageLocks.delete(binId);
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
  const database = await getDatabase();
  const row = database && (await database.get('SELECT state FROM storage_uploads WHERE bin_id = ? AND file_id = ?', [binId, fileId]));
  return row ? JSON.parse(row.state) : null;
}

async function getUploadState(binId: string, fileId: string): Promise<UploadState | null> {
  return readUploadState(binId, fileId);
}

async function writeUploadState(binId: string, fileId: string, state: UploadState) {
  const database = await getDatabase();
  if (!database) throw new Error('Database unavailable');
  await database.run(
    `INSERT INTO storage_uploads (bin_id, file_id, state, updated_at) VALUES (?, ?, ?, ?)
     ON CONFLICT(bin_id, file_id) DO UPDATE SET state = excluded.state, updated_at = excluded.updated_at`,
    [binId, fileId, JSON.stringify(state), Date.now()],
  );
}

async function deleteUploadState(binId: string, fileId: string) {
  const database = await getDatabase();
  if (database) await database.run('DELETE FROM storage_uploads WHERE bin_id = ? AND file_id = ?', [binId, fileId]);
}

function getEtag(sha256: string | undefined) {
  return sha256 ? `"${sha256}"` : undefined;
}

export type Options = { port?: number };

async function onFileExists(_req, res, args) {
  const { binId = '', fileId = '' } = args;

  const principal = await getPrincipal(_req);
  const storage = await getStorageBackend(principal);

  tryCatch(res, async () => {
    const metadata = await readMetadataRecord(binId, fileId, storage);
    if (!metadata) return notFound(res);

    res.setHeader('accept-ranges', 'bytes');
    res.setHeader('content-length', metadata.size);
    if (metadata.system.sha256) res.setHeader('etag', getEtag(metadata.system.sha256));
    res.end();
  });
}

async function onReadFile(req, res, args) {
  const { binId = '', fileId = '' } = args;

  const principal = await getPrincipal(req);
  const storage = await getStorageBackend(principal);

  tryCatch(res, async () => {
    const metadata = await readMetadataRecord(binId, fileId, storage);
    if (!metadata) return notFound(res);

    const meta = metadata.user;
    const systemSha256 = metadata.system.sha256;

    if (typeof meta.type === 'string') res.setHeader('content-type', meta.type);
    if (typeof meta.contentDisposition === 'string') res.setHeader('content-disposition', meta.contentDisposition);
    if (typeof meta.cacheControl === 'string') res.setHeader('cache-control', meta.cacheControl);

    res.setHeader('content-length', metadata.size);
    res.setHeader('last-modified', new Date(metadata.lastModified).toString());
    res.setHeader('accept-ranges', 'bytes');
    if (systemSha256) res.setHeader('etag', getEtag(systemSha256));

    const range = parseByteRange(req.headers.range, metadata.size);
    const ifRange = req.headers['if-range'];
    const rangeAllowed = range && (!ifRange || ifRange === getEtag(systemSha256));
    if (req.headers.range && !range) {
      res.writeHead(416, { 'content-range': `bytes */${metadata.size}` }).end();
      return;
    }
    if (rangeAllowed) {
      res.writeHead(206, {
        'content-length': range.end - range.start + 1,
        'content-range': `bytes ${range.start}-${range.end}/${metadata.size}`,
      });
      const { data } = await storage.readObject(binId, fileId, { start: range.start, end: range.end });
      if (data && typeof (data as any)[Symbol.asyncIterator] === 'function') {
        for await (const chunk of data as AsyncIterable<Uint8Array>) res.write(chunk);
        res.end();
      } else {
        (data as any).pipe(res);
      }
      return;
    }
    const { data } = await storage.readObject(binId, fileId);
    if (data && typeof (data as any)[Symbol.asyncIterator] === 'function') {
      for await (const chunk of data as AsyncIterable<Uint8Array>) res.write(chunk);
      res.end();
    } else {
      (data as any).pipe(res);
    }
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
    return readUploadState(binId, fileId);
  });
  if (!state) return notFound(res);
  res.writeHead(200, jsonHeaders).end(JSON.stringify({ total: state.total, ranges: state.ranges, complete: false }));
}

async function readMetadataRecord(binId: string, fileId: string, storage: StorageBackend) {
  const database = await getDatabase();
  if (!database) throw new Error('Database unavailable');
  const row = await database.get(
    'SELECT metadata, system_metadata, size, updated_at FROM storage_files WHERE bin_id = ? AND id = ?',
    [binId, fileId],
  );
  if (!row) return null;
  const object = await storage.getObjectMetadata(binId, fileId);
  if (!object) return null;
  if (Number(row.size) !== object.size) throw new Error('Stored object size does not match its catalog record');
  const system = JSON.parse(row.system_metadata || '{}') as SystemMetadata;
  if (object.sha256 && system.sha256 && object.sha256 !== system.sha256) {
    throw new Error('Stored object checksum does not match its catalog record');
  }
  return {
    user: JSON.parse(row.metadata || '{}'),
    system,
    size: object.size,
    lastModified: object.lastModified || Number(row.updated_at),
  };
}

async function readMetadata(binId: string, fileId: string, baseUrl: string | URL, principal?: { issuer: string; subject: string } | null) {
  const storage = await getStorageBackend(principal);
  const record = await readMetadataRecord(binId, fileId, storage);
  if (!record) return null;
  return {
    ...record.user,
    id: fileId || undefined,
    bin: binId,
    size: record.size,
    name: record.user.name || fileId,
    lastModified: new Date(record.lastModified).toISOString(),
    ...(record.system.sha256 ? { sha256: record.system.sha256, etag: getEtag(record.system.sha256) } : {}),
    ...(record.system.immutable ? { immutable: true } : {}),
    url: String(new URL('/' + ['f', binId, fileId].filter(Boolean).join('/'), baseUrl)),
  };
}

async function onReadMetadata(req, res, args) {
  const { binId = '', fileId = '' } = args;
  const baseUrl = getProxyHost(req);
  const principal = await getPrincipal(req);
  if (!fileId) {
    const database = await getDatabase();
    const bin = database && await database.get(
      `SELECT b.id, b.name, b.created_at, b.deletion_requested_at, b.deletion_expires_at,
              COALESCE(SUM(f.size), 0) AS size
       FROM storage_bins b LEFT JOIN storage_files f ON f.bin_id = b.id
       WHERE b.id = ? GROUP BY b.id`,
      [binId],
    );
    if (!bin) return notFound(res);
    res.writeHead(200, jsonHeaders).end(JSON.stringify({
      id: bin.id,
      name: bin.name,
      visibility: 'private',
      size: Number(bin.size || 0),
      protected: await isBinLocked(binId),
      deletionRequestedAt: bin.deletion_requested_at || null,
      deletionExpiresAt: bin.deletion_expires_at || null,
    }));
    return;
  }
  const metadata = await readMetadata(binId, fileId, baseUrl, principal);

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
  const testAdapters = (globalThis as any).__FILEBIN_TEST_ADAPTERS__;
  if (process.env.NODE_ENV === 'test' && testAdapters?.database) return testAdapters.database;
  return databasePromise;
}

function getCredentialEncryptionKey() {
  const configured = s3CredentialEncryptionKey || process.env.SESSION_SECRET;
  if (!configured) throw new Error('S3_CREDENTIAL_ENCRYPTION_KEY or SESSION_SECRET must be configured');
  if (/^[a-f0-9]{64}$/i.test(configured)) return Buffer.from(configured, 'hex');
  const key = Buffer.from(configured, 'base64url');
  return key.length === 32 ? key : createHash('sha256').update(configured).digest();
}

function encryptS3Secret(secret: string) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', getCredentialEncryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
  return {
    encrypted_secret: encrypted.toString('base64url'),
    encryption_iv: iv.toString('base64url'),
    encryption_tag: cipher.getAuthTag().toString('base64url'),
  };
}

async function decryptS3Secret(credentials) {
  if (credentials.encrypted_secret && credentials.encryption_iv && credentials.encryption_tag) {
    const decipher = createDecipheriv(
      'aes-256-gcm',
      getCredentialEncryptionKey(),
      Buffer.from(credentials.encryption_iv, 'base64url'),
    );
    decipher.setAuthTag(Buffer.from(credentials.encryption_tag, 'base64url'));
    return Buffer.concat([
      decipher.update(Buffer.from(credentials.encrypted_secret, 'base64url')),
      decipher.final(),
    ]).toString('utf8');
  }

  // Re-encrypt legacy plaintext records on first successful use.
  if (credentials.secret_key) {
    const encrypted = encryptS3Secret(credentials.secret_key);
    const database = await getDatabase();
    if (database) {
      await database.run(
        `UPDATE user_s3_credentials
         SET encrypted_secret = ?, encryption_iv = ?, encryption_tag = ?, secret_key = '', updated_at = ?
         WHERE id = ? AND secret_key IS NOT NULL`,
        [encrypted.encrypted_secret, encrypted.encryption_iv, encrypted.encryption_tag, Date.now(), credentials.id],
      );
    }
    return credentials.secret_key;
  }

  throw new Error('S3 account secret is unavailable or cannot be decrypted');
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
  const testAdapters = (globalThis as any).__FILEBIN_TEST_ADAPTERS__;
  const testSubject = process.env.NODE_ENV === 'test' && testAdapters ? req.headers['x-test-oidc-sub'] : null;
  if (testSubject) {
    return { sub: String(testSubject), iss: 'https://test-issuer.invalid', name: 'Test User' };
  }
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
  const testAdapters = (globalThis as any).__FILEBIN_TEST_ADAPTERS__;
  const testSubject = process.env.NODE_ENV === 'test' && testAdapters ? req.headers['x-test-oidc-sub'] : null;
  if (testSubject) {
    const profile = { sub: String(testSubject), iss: 'https://test-issuer.invalid', name: 'Test User' };
    return { issuer: profile.iss, subject: profile.sub, profile };
  }
  const profile = await getSessionProfile(req);
  return profile?.sub ? { issuer: profile.iss || authIssuer, subject: profile.sub, profile } : null;
}

function isAdminPrincipal(principal) {
  return Boolean(principal?.subject && adminSubjects.has(principal.subject));
}

async function getAdminContext(req, res) {
  const principal = await getPrincipal(req);
  if (!isAdminPrincipal(principal)) {
    forbidden(res);
    return null;
  }
  const database = await getDatabase();
  if (!database) {
    res.writeHead(503).end('Database unavailable');
    return null;
  }
  return { principal, database };
}

async function listOwnedBins(database, principal) {
  const bins = await database.all(
    `SELECT b.id, b.name, b.visibility, b.deletion_requested_at, b.deletion_expires_at,
            COALESCE(SUM(f.size), 0) AS size
     FROM storage_bins b
     LEFT JOIN storage_files f ON f.bin_id = b.id
     WHERE rtrim(replace(b.owner_issuer, '"', ''), '/') = rtrim(?, '/')
       AND replace(b.owner_subject, '"', '') = ?
      GROUP BY b.id, b.visibility, b.deletion_requested_at, b.deletion_expires_at
     ORDER BY b.created_at DESC`,
    [principal.issuer, principal.subject],
  );
  return Promise.all(
    bins.map(async (bin) => {
      const storageQuotaBytes = await getBinQuota(bin.id);
      return {
        ...bin,
        storageUsedBytes: Number(bin.size || 0),
        storageQuotaBytes: storageQuotaBytes || null,
        storageRemainingBytes: storageQuotaBytes ? Math.max(0, storageQuotaBytes - Number(bin.size || 0)) : null,
        deletionRequestedAt: bin.deletion_requested_at || null,
        deletionExpiresAt: bin.deletion_expires_at || null,
        protected: await isBinLocked(bin.id),
      };
    }),
  );
}

async function getStorageBin(binId: string) {
  const database = await getDatabase();
  return database && database.get('SELECT * FROM storage_bins WHERE id = ?', [binId]);
}

async function getBinQuota(binId: string) {
  const database = await getDatabase();
  if (!database) return binStorageQuotaBytes;
  const override = await database.get('SELECT extra_bytes FROM storage_bin_quota_overrides WHERE bin_id = ?', [binId]);
  return binStorageQuotaBytes + Math.max(0, Number(override?.extra_bytes || 0));
}

async function getBinStorage(binId: string, principal?: { issuer: string; subject: string } | null) {
  const storage = await getStorageBackend(principal);
  const usage = await storage.getBucketUsage(binId);
  return { used: usage.used, quota: await getBinQuota(binId) };
}

async function getBinStorageUsage(binId: string, _excludeFileId?: string, principal?: { issuer: string; subject: string } | null) {
  const storage = await getStorageBackend(principal);
  const usage = await storage.getBucketUsage(binId);
  let used = usage.used;
  if (_excludeFileId) {
    const existing = await storage.getObjectMetadata(binId, _excludeFileId);
    if (existing) used = Math.max(0, used - existing.size);
  }
  const database = await getDatabase();
  const uploadRows = database && (await database.all('SELECT state FROM storage_uploads WHERE bin_id = ?', [binId]));
  const reserved = (uploadRows || []).reduce((sum, row) => {
    const total = JSON.parse(row.state || '{}').total;
    return sum + (Number.isSafeInteger(total) ? total : 0);
  }, 0);
  return { used, reserved: Math.max(usage.reserved, reserved) };
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
  if (!database) throw new Error('Database unavailable');
  const bin = await database.get('SELECT owner_issuer, owner_subject FROM storage_bins WHERE id = ?', [binId]);
  if (!bin?.owner_issuer || !bin?.owner_subject) throw new Error(`Bin ${binId} has no owner; refusing destructive deletion`);
  const storage = await getStorageBackend({ issuer: bin.owner_issuer, subject: bin.owner_subject });
  await storage.deleteBucket(binId);
  await database.run('DELETE FROM storage_uploads WHERE bin_id = ?', [binId]);
  await database.run('DELETE FROM storage_files WHERE bin_id = ?', [binId]);
  await database.run('DELETE FROM storage_bin_quota_overrides WHERE bin_id = ?', [binId]);
  await database.run('DELETE FROM storage_bins WHERE id = ?', [binId]);
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

async function recordCompletedFile(binId: string, fileId: string, size: number, sha256: string, metadata: Record<string, string>, immutable = false) {
  const database = await getDatabase();
  if (!database) throw new Error('Database unavailable');
  const systemMetadata: SystemMetadata = { sha256, committedAt: new Date().toISOString(), ...(immutable ? { immutable: true } : {}) };
  const now = Date.now();
  await database.run(
    'INSERT OR REPLACE INTO storage_files (bin_id, id, metadata, system_metadata, size, updated_at) VALUES (?, ?, ?, ?, ?, ?)',
    [binId, fileId, JSON.stringify(metadata), JSON.stringify(systemMetadata), size, now],
  );
  await database.run('UPDATE storage_bins SET last_completed_upload_at = ? WHERE id = ?', [now, binId]);
  await deleteUploadState(binId, fileId);
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

async function onAuthS3Credentials(req, res) {
  const principal = await getPrincipal(req);
  const database = await getDatabase();
  if (!principal || !database) return unauthenticated(res);
  const credential = await database.get(
    'SELECT id, endpoint, region, created_at, updated_at FROM user_s3_credentials WHERE user_issuer = ? AND user_subject = ? AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1',
    [principal.issuer, principal.subject],
  );
  res.writeHead(200, jsonHeaders).end(JSON.stringify({ connected: Boolean(credential), ...credential }));
}

async function onAuthCreateS3Credential(req, res) {
  const principal = await getPrincipal(req);
  const database = await getDatabase();
  if (!principal || !database) return unauthenticated(res);

  const diagnosticId = randomUUID().slice(0, 8);
  const startedAt = Date.now();
  res.setHeader('x-diagnostic-id', diagnosticId);
  const logDiagnostic = (stage: string, details: Record<string, unknown> = {}) => {
    if (!process.env.DEBUG) return;
    console.info(
      JSON.stringify({
        event: 's3_credential_connect',
        diagnosticId,
        stage,
        elapsedMs: Date.now() - startedAt,
        ...details,
      }),
    );
  };

  const payload = await readJson(req);
  const { accessKey, secretKey } = payload;
  const accessKeyValid = typeof accessKey === 'string' && /^[!-~]{8,128}$/.test(accessKey);
  const secretKeyValid = typeof secretKey === 'string' && secretKey.length >= 16 && secretKey.length <= 512;
  if (!accessKeyValid || !secretKeyValid) {
    logDiagnostic('request_validation_failed', {
      status: 400,
      accessKeyType: typeof accessKey,
      accessKeyLength: typeof accessKey === 'string' ? accessKey.length : null,
      accessKeyValid,
      secretKeyType: typeof secretKey,
      secretKeyLength: typeof secretKey === 'string' ? secretKey.length : null,
    });
    return badRequest(res, 'A valid S3 access key and secret are required');
  }
  let encryptedSecret;
  try {
    encryptedSecret = encryptS3Secret(secretKey);
  } catch {
    logDiagnostic('local_encryption_configuration_failed', { status: 503 });
    return res.writeHead(503).end('S3 credential encryption is not configured');
  }

  const existing = await database.get(
    'SELECT id FROM user_s3_credentials WHERE user_issuer = ? AND user_subject = ? AND revoked_at IS NULL',
    [principal.issuer, principal.subject],
  );
  if (existing) {
    logDiagnostic('existing_account_conflict', { status: 409 });
    return res.writeHead(409).end('An S3 account is already connected');
  }

  try {
    await validateS3AccountCredentials(accessKey, secretKey);
  } catch (error) {
    const providerError = error as {
      name?: unknown;
      Code?: unknown;
      code?: unknown;
      $metadata?: { httpStatusCode?: unknown };
    };
    const safeCode = [providerError.Code, providerError.code].find(
      (code) => typeof code === 'string' && /^[A-Za-z0-9_.-]{1,80}$/.test(code),
    );
    logDiagnostic('s3_provider_validation_failed', {
      status: 401,
      providerErrorName:
        typeof providerError.name === 'string' && /^[A-Za-z0-9_.-]{1,80}$/.test(providerError.name)
        ? providerError.name
        : 'UnknownError',
      providerErrorCode: safeCode || null,
      providerHttpStatus: Number.isInteger(providerError.$metadata?.httpStatusCode)
        ? providerError.$metadata?.httpStatusCode
        : null,
    });
    return unauthorized(res);
  }

  const id = randomUUID();
  const now = Date.now();
  await database.run(
    `INSERT INTO user_s3_credentials
       (id, user_issuer, user_subject, access_key, secret_key, encrypted_secret, encryption_iv, encryption_tag, endpoint, region, created_at, updated_at)
     VALUES (?, ?, ?, ?, '', ?, ?, ?, ?, ?, ?, ?)`,
    [id, principal.issuer, principal.subject, accessKey, encryptedSecret.encrypted_secret, encryptedSecret.encryption_iv, encryptedSecret.encryption_tag, s3Endpoint, s3Region, now, now],
  );
  await audit(req, 's3_credential.create', id);
  res.writeHead(201, jsonHeaders).end(JSON.stringify({ id, endpoint: s3Endpoint, region: s3Region, createdAt: now }));
  logDiagnostic('connect_succeeded', { status: 201 });
}

async function validateS3AccountCredentials(accessKey, secretKey) {
  const testAdapters = (globalThis as any).__FILEBIN_TEST_ADAPTERS__;
  if (process.env.NODE_ENV === 'test' && testAdapters?.validateS3Credentials) {
    return testAdapters.validateS3Credentials(accessKey, secretKey);
  }
  const { S3Client, ListBucketsCommand } = await import('@aws-sdk/client-s3');
  const client = new S3Client({
    endpoint: s3Endpoint,
    region: s3Region,
    forcePathStyle: true,
    credentials: { accessKeyId: accessKey, secretAccessKey: secretKey },
  });
  try {
    await client.send(new ListBucketsCommand({}));
  } finally {
    client.destroy();
  }
}

async function onAuthDeleteS3Credential(req, res, args) {
  const principal = await getPrincipal(req);
  const database = await getDatabase();
  if (!principal || !database) return unauthenticated(res);
  
  const { credentialId } = args;
  const creds = await database.get(
    'SELECT id FROM user_s3_credentials WHERE id = ? AND user_issuer = ? AND user_subject = ? AND revoked_at IS NULL',
    [credentialId, principal.issuer, principal.subject],
  );
  
  if (!creds) return notFound(res);
  
  const now = Date.now();
  await database.run(
    "UPDATE user_s3_credentials SET revoked_at = ?, updated_at = ?, secret_key = '', encrypted_secret = NULL, encryption_iv = NULL, encryption_tag = NULL WHERE id = ?",
    [now, now, credentialId]
  );
  
  await audit(req, 's3_credential.revoke', credentialId);
  res.writeHead(204).end();
}

async function onAdminListUserS3Credentials(req, res, args) {
  const context = await getAdminContext(req, res);
  if (!context) return;
  const { database } = context;
  
  const { subject } = args;
  const credentials = await database.all(
    'SELECT id, user_issuer, user_subject, endpoint, region, created_at, updated_at, revoked_at FROM user_s3_credentials WHERE user_subject = ?',
    [subject]
  );
  
  res.writeHead(200, jsonHeaders).end(JSON.stringify(credentials));
}

async function onAdminRevokeUserS3Credential(req, res, args) {
  const context = await getAdminContext(req, res);
  if (!context) return;
  const { database } = context;
  
  const { subject, credentialId } = args;
  const creds = await database.get(
    'SELECT id FROM user_s3_credentials WHERE id = ? AND user_subject = ? AND revoked_at IS NULL',
    [credentialId, subject],
  );
  
  if (!creds) return notFound(res);
  
  const now = Date.now();
  await database.run(
    "UPDATE user_s3_credentials SET revoked_at = ?, updated_at = ?, secret_key = '', encrypted_secret = NULL, encryption_iv = NULL, encryption_tag = NULL WHERE id = ?",
    [now, now, credentialId]
  );
  
  await audit(req, 's3_credential.admin_revoke', credentialId);
  res.writeHead(204).end();
}

async function onAdminStats(req, res) {
  const context = await getAdminContext(req, res);
  if (!context) return;
  const { database } = context;
  const bins = await database.all(
    `SELECT b.id, b.name, b.visibility, COALESCE(SUM(f.size), 0) AS size,
            COALESCE(q.extra_bytes, 0) AS extra_bytes
     FROM storage_bins b
     LEFT JOIN storage_files f ON f.bin_id = b.id
     LEFT JOIN storage_bin_quota_overrides q ON q.bin_id = b.id
     GROUP BY b.id, b.name, b.visibility, q.extra_bytes
     ORDER BY b.created_at DESC`,
  );
  const formatted = bins.map((bin) => {
    const used = Number(bin.size || 0);
    const extra = Number(bin.extra_bytes || 0);
    const quota = binStorageQuotaBytes + extra;
    return {
      id: bin.id,
      name: bin.name,
      visibility: bin.visibility,
      storageUsedBytes: used,
      extraQuotaBytes: extra,
      storageQuotaBytes: quota || null,
      storageRemainingBytes: quota ? Math.max(0, quota - used) : null,
    };
  });
  res
    .writeHead(200, jsonHeaders)
    .end(
      JSON.stringify({ binCount: formatted.length, defaultQuotaBytes: binStorageQuotaBytes || null, bins: formatted }),
    );
}

async function onAdminQuota(req, res, args) {
  const context = await getAdminContext(req, res);
  if (!context) return;
  const { database } = context;
  const bin = await database.get('SELECT id FROM storage_bins WHERE id = ?', [args.binId]);
  if (!bin) return notFound(res);
  const payload = await readJson(req);
  const extraBytes = payload.extraBytes ?? payload.extraQuotaBytes;
  if (!Number.isSafeInteger(extraBytes) || extraBytes < 0) {
    return badRequest(res, 'extraBytes must be a non-negative integer');
  }
  if (extraBytes === 0) {
    await database.run('DELETE FROM storage_bin_quota_overrides WHERE bin_id = ?', [args.binId]);
  } else {
    await database.run(
      `INSERT INTO storage_bin_quota_overrides (bin_id, extra_bytes, updated_at) VALUES (?, ?, ?)
       ON CONFLICT(bin_id) DO UPDATE SET extra_bytes = excluded.extra_bytes, updated_at = excluded.updated_at`,
      [args.binId, extraBytes, Date.now()],
    );
  }
  await audit(req, 'bin.quota.updated', args.binId);
  res.writeHead(204).end();
}

async function reconcileStorageCatalog() {
  const database = await getDatabase();
  if (!database) return null;
  const bins = await database.all('SELECT id, owner_issuer, owner_subject FROM storage_bins');
  let missingBuckets = 0;
  let objectsWithoutMetadata = 0;
  let metadataWithoutObjects = 0;
  for (const bin of bins) {
    if (!bin.owner_issuer || !bin.owner_subject) {
      missingBuckets++;
      continue;
    }
    const storage = await getStorageBackend({ issuer: bin.owner_issuer, subject: bin.owner_subject });
    if (!(await storage.bucketExists(bin.id))) {
      missingBuckets++;
      continue;
    }
    const [objects, files] = await Promise.all([
      storage.listObjects(bin.id),
      database.all('SELECT id FROM storage_files WHERE bin_id = ?', [bin.id]),
    ]);
    const metadataIds = new Set(files.map((file) => file.id));
    const objectIds = new Set(objects);
    objectsWithoutMetadata += objects.filter((id) => !metadataIds.has(id)).length;
    metadataWithoutObjects += files.filter((file) => !objectIds.has(file.id)).length;
  }
  return { missingBuckets, objectsWithoutMetadata, metadataWithoutObjects };
}

async function onAdminReconcile(req, res) {
  const context = await getAdminContext(req, res);
  if (!context) return;
  const result = await reconcileStorageCatalog();
  await audit(req, 'admin.catalog.reconciled', 'storage');
  res.writeHead(200, jsonHeaders).end(JSON.stringify(result));
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
  if (oidcMissingConfiguration.length) {
    return authUnavailable(res);
  }
  const auth = await getAuthClient();
  if (!auth) return authUnavailable(res);
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
  if (!auth) return authUnavailable(res);
  const cookie = getCookie(req, 'filebin_oidc');
  const [state, signature] = String(cookie || '').split('.');
  const expected = Buffer.from(sign(state || ''));
  const actual = Buffer.from(signature || '');
  if (!oidcClientSecret || !state || actual.length !== expected.length || !timingSafeEqual(actual, expected))
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
  if (!database) return authUnavailable(res);
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

  if (!fileId) {
    const database = await getDatabase();
    const payload = await readJson(req);
    if (typeof payload.name !== 'string' || !payload.name.trim() || payload.name.trim().length > 80) {
      return badRequest(res, 'A bin name of 1-80 characters is required');
    }
    if (!database || !(await getStorageBin(binId))) return notFound(res);
    await database.run('UPDATE storage_bins SET name = ? WHERE id = ?', [payload.name.trim(), binId]);
    return res.writeHead(202, jsonHeaders).end(JSON.stringify({ binId, name: payload.name.trim() }));
  }

  const principal = await getPrincipal(req);
  const storage = await getStorageBackend(principal);
  const record = await readMetadataRecord(binId, fileId, storage);
  if (!record) return notFound(res);
  if (record.system.immutable) return res.writeHead(409).end('File metadata is immutable');

  tryCatch(res, async () => {
    const payload = await readJson(req);
    if (!payload || Array.isArray(payload) || typeof payload !== 'object') return badRequest(res, 'Metadata must be a JSON object');
    for (const protectedKey of ['id', 'bin', 'size', 'url', 'sha256', 'etag', 'immutable']) delete payload[protectedKey];
    const database = await getDatabase();
    await database.run(
      'UPDATE storage_files SET metadata = ?, updated_at = ? WHERE bin_id = ? AND id = ?',
      [JSON.stringify({ ...record.user, ...payload }), Date.now(), binId, fileId],
    );
    const url = String(new URL(`/f/${binId}/${fileId}`, getProxyHost(req)));
    res.writeHead(202, jsonHeaders).end(JSON.stringify({ url }));
  });
}

async function onCreateFile(req, res, args) {
  const { binId = '' } = args;

  const principal = await getPrincipal(req);
  const storage = await getStorageBackend(principal);

  tryCatch(res, async () => {
    const database = await getDatabase();
    if (!database || !(await getStorageBin(binId))) return notFound(res);
    const payload = await readJson(req);
    if (!payload || Array.isArray(payload) || typeof payload !== 'object') return badRequest(res, 'Metadata must be a JSON object');
    const hasEnvelope = payload.metadata && typeof payload.metadata === 'object' && !Array.isArray(payload.metadata);
    const metadata = hasEnvelope ? { ...payload.metadata } : { ...payload };
    const fileId = randomUUID();
    const immutable = metadata.immutable === true;
    const partSize = Number(payload.partSize || metadata.partSize || 8 * 1024 * 1024);
    delete metadata.immutable;
    delete metadata.partSize;
    if (!Number.isSafeInteger(partSize) || partSize < 5 * 1024 * 1024) return badRequest(res, 'partSize must be at least 5 MiB');

    const uploadId = await storage.createMultipartUpload(binId, fileId);
    await writeUploadState(binId, fileId, {
      total: null,
      ranges: [],
      pending: [],
      parts: [],
      metadata,
      immutable,
      partSize,
      uploadId,
    });

    res.setHeader('location', String(new URL(`/f/${binId}/${fileId}`, getProxyHost(req))));
    res.writeHead(201, jsonHeaders).end(JSON.stringify({ fileId, uploadId }));
  });
}

async function onWriteFile(req, res, args) {
  const { binId = '', fileId = '' } = args;

  const principal = await getPrincipal(req);
  const storage = await getStorageBackend(principal);

  const database = await getDatabase();
  const fileRecord = database && (await database.get('SELECT metadata, system_metadata, size FROM storage_files WHERE bin_id = ? AND id = ?', [binId, fileId]));
  const uploadState = await getUploadState(binId, fileId);

  if (!fileRecord && !uploadState) {
    return notFound(res);
  }
  const existingSystem = fileRecord ? JSON.parse(fileRecord.system_metadata || '{}') : {};
  if (existingSystem.immutable) return res.writeHead(409).end('File is immutable');

  const contentRange = parseContentRange(req.headers['content-range']);
  if (req.headers['content-range'] && !contentRange) return badRequest(res, 'Invalid Content-Range header');

  if (!contentRange) {
    const payload = await readStream(req);
    const sha256 = createHash('sha256').update(payload).digest('hex');
    const fileSize = payload.length;

    try {
      await withBinStorageLock(binId, async () => {
        const usage = await getBinStorageUsage(binId, fileId, principal);
        const quota = await getBinQuota(binId);
        if (quota && usage.used + usage.reserved + fileSize > quota) {
          throw new Error('Bin storage quota exceeded');
        }
        if (uploadState?.uploadId) await storage.abortMultipartUpload(binId, fileId, uploadState.uploadId).catch(() => {});
        await storage.writeObject(binId, fileId, payload, { sha256 });
      await recordCompletedFile(binId, fileId, payload.length, sha256, uploadState?.metadata || (fileRecord ? JSON.parse(fileRecord.metadata || '{}') : {}), Boolean(uploadState?.immutable || existingSystem.immutable));
      });
      await deleteUploadState(binId, fileId);
      sendFileReference(req, res, binId, fileId);
    } catch (error) {
      if (!res.headersSent) {
        res
          .writeHead(error instanceof Error && error.message === 'Bin storage quota exceeded' ? 413 : 500)
          .end(
            error instanceof Error && error.message === 'Bin storage quota exceeded'
              ? 'Bin storage quota exceeded'
              : 'Failed to write file',
          );
      }
    }
    return;
  }

  const digest = String(req.headers.digest || '');
  if (!/^sha-256=[A-Za-z0-9+/]+={0,2}$/.test(digest)) return badRequest(res, 'A SHA-256 Digest header is required');
  const range: ByteRange = { start: contentRange.start, end: contentRange.end };

  if (!uploadState || !uploadState.uploadId || (uploadState.total !== null && uploadState.total !== contentRange.total)) {
    if (fileRecord) {
      req.resume();
      req.on('end', () => sendFileReference(req, res, binId, fileId));
      return;
    }
    return res.writeHead(409).end('Conflicting upload range or total size');
  }

  const duplicate = uploadState.parts.some(
    (part) => part.start === range.start && part.end === range.end && part.digest === digest,
  );
  if (rangesOverlap([...uploadState.ranges, ...uploadState.pending], range) && !duplicate) {
    return res.writeHead(409).end('Conflicting upload range or total size');
  }
  if (duplicate) {
    req.resume();
    req.on('end', () => res.writeHead(202, jsonHeaders).end(JSON.stringify({ complete: false })));
    return;
  }

  if (contentRange.start % uploadState.partSize !== 0 || contentRange.end !== Math.min(contentRange.start + uploadState.partSize, contentRange.total) - 1) {
    return badRequest(res, 'Upload ranges must match the configured part size');
  }
  const partNumber = Math.floor(contentRange.start / uploadState.partSize) + 1;
  if (partNumber > 10000) return badRequest(res, 'S3 multipart uploads are limited to 10,000 parts');

  if (uploadState.total === null) {
    const usage = await storage.getBucketUsage(binId);
    const quota = await getBinQuota(binId);
    if (quota && usage.used + usage.reserved + contentRange.total > quota) {
      return res.writeHead(413).end('Bin storage quota exceeded');
    }
    uploadState.total = contentRange.total;
  }

  uploadState.pending.push(range);
  await writeUploadState(binId, fileId, uploadState);

  const hash = createHash('sha256');
  let written = 0;
  const chunks: Uint8Array[] = [];
  for await (const chunk of req) {
    written += chunk.length;
    hash.update(chunk);
    chunks.push(chunk);
  }

  if (written !== range.end - range.start + 1 || `sha-256=${hash.digest('base64')}` !== digest) {
    uploadState.pending = uploadState.pending.filter((item) => item.start !== range.start || item.end !== range.end);
    await writeUploadState(binId, fileId, uploadState);
    return badRequest(res, 'Upload part does not match its range or digest');
  }

  try {
    const partData = Buffer.concat(chunks);
    const uploadedPart = await storage.uploadPart(binId, fileId, uploadState.uploadId, partNumber, partData);
    let complete = false;
    await withUploadLock(getUploadStatePath(binId, fileId), async () => {
      await withBinStorageLock(binId, async () => {
        const current = await readUploadState(binId, fileId);
        if (!current) throw new Error('Upload session disappeared');
        current.pending = current.pending.filter((item) => item.start !== range.start || item.end !== range.end);
        current.ranges = mergeRanges([...current.ranges, range]);
        current.parts.push({ ...range, digest, partNumber, etag: uploadedPart.etag });
        complete = isUploadComplete(current);
        if (complete) {
          const completed = await storage.completeMultipartUpload(
            binId,
            fileId,
            uploadState.uploadId,
            current.parts.sort((a, b) => a.partNumber - b.partNumber).map((part) => ({ partNumber: part.partNumber, etag: part.etag! })),
          );
          await recordCompletedFile(binId, fileId, completed.size, completed.sha256, current.metadata, Boolean(current.immutable));
          await deleteUploadState(binId, fileId);
        } else {
          await writeUploadState(binId, fileId, current);
        }
      });
    });
    if (complete) {
      sendFileReference(req, res, binId, fileId);
    } else res.writeHead(202, jsonHeaders).end(JSON.stringify({ complete: false }));
  } catch {
    if (!res.headersSent) res.writeHead(500).end('Failed to finalize upload');
  }
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

async function readBin(binId: string, principal?: { issuer: string; subject: string } | null) {
  const storage = await getStorageBackend(principal);
  if (!(await storage.bucketExists(binId))) return null;
  return storage.listObjects(binId);
}

async function onReadBin(_req, res, args) {
  const { binId = '' } = args;
  const principal = await getPrincipal(_req);

  tryCatch(res, async () => {
    const objectIds = await readBin(binId, principal);
    const database = await getDatabase();
    const records = database && (await database.all('SELECT id FROM storage_files WHERE bin_id = ?', [binId]));
    const catalogIds = new Set((records || []).map((record) => record.id));
    const files = objectIds.filter((id) => catalogIds.has(id));
    res.writeHead(200, jsonHeaders).end(JSON.stringify(files));
  });
}

async function onCreateBin(req, res) {
  tryCatch(res, async () => {
    const principal = await getPrincipal(req);
    if (!principal) return unauthenticated(res);
    const database = await getDatabase();
    if (!database) return res.writeHead(503).end('Database unavailable');
    const binId = randomUUID();
    const name = generateBinName();
    const storage = await getStorageBackend(principal);
    const now = Date.now();
    await database.run(
      'INSERT INTO storage_bins (id, name, visibility, owner_issuer, owner_subject, bucket_name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [binId, name, 'private', principal.issuer, principal.subject, binId, now],
    );
    try {
      await storage.createBucket(binId);
    } catch (error) {
      await database.run('DELETE FROM storage_bins WHERE id = ?', [binId]).catch(() => {});
      throw error;
    }
    await audit(req, 'bin.create', binId);
    res.setHeader('location', String(new URL('/bin/' + binId, getProxyHost(req))));
    res.writeHead(201).end(JSON.stringify({ binId, name }));
  });
}

async function onRenameBinPatch(req, res, args) {
  const { name } = await readJson(req);
  const value = typeof name === 'string' ? name.trim() : '';
  if (!value || value.length > 80) return badRequest(res, 'Bin name must be 1-80 characters');
  const database = await getDatabase();
  if (!database || !(await getStorageBin(args.binId))) return notFound(res);
  await database.run('UPDATE storage_bins SET name = ? WHERE id = ?', [value, args.binId]);
  await audit(req, 'bin.name.updated', args.binId);
  res.writeHead(204).end();
}

async function onDeleteFile(_req, res, args) {
  const { binId = '', fileId = '' } = args;

  const principal = await getPrincipal(_req);
  const storage = await getStorageBackend(principal);
  const database = await getDatabase();
  const row = database && (await database.get('SELECT system_metadata FROM storage_files WHERE bin_id = ? AND id = ?', [binId, fileId]));
  const uploadState = await getUploadState(binId, fileId);

  if (!row && !uploadState) {
    return notFound(res);
  }
  const system = row ? JSON.parse(row.system_metadata || '{}') : {};
  if (system.immutable) return res.writeHead(409).end('File is immutable');

  tryCatch(res, async () => {
    if (uploadState?.uploadId) await storage.abortMultipartUpload(binId, fileId, uploadState.uploadId).catch(() => {});
    if (row) await storage.deleteObject(binId, fileId);
    await database.run('DELETE FROM storage_files WHERE bin_id = ? AND id = ?', [binId, fileId]);
    await deleteUploadState(binId, fileId);
    res.end('OK');
  });
}

async function onDeleteBin(_req, res, args) {
  const { binId = '' } = args;

  const principal = await getPrincipal(_req);
  const storage = await getStorageBackend(principal);
  const bin = await getStorageBin(binId);
  if (!bin) return notFound(res);

  tryCatch(res, async () => {
    if (!(await storage.bucketExists(binId))) return notFound(res);
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
  const isJson = new URL(req.url, 'http://localhost').pathname.endsWith('.json') || !new URL(req.url, 'http://localhost').pathname.endsWith('.yaml');
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
    const isAdminPage = new URL(req.url, 'http://localhost').pathname === '/admin';

    if (getCookie(req, 'filebin_session') && !state.profile && !oidcMissingConfiguration.length) {
      const loginUrl = new URL('/auth/login', getProxyHost(req));
      loginUrl.searchParams.set('url', String(new URL(req.url, getProxyHost(req))));
      res.writeHead(302, { location: String(loginUrl) }).end();
      return;
    }

    state = { ...state, adminAccess: isAdminPrincipal(state.profile && { subject: state.profile.sub }) };

    if (isAdminPage) {
      if (!(await getAdminContext(req, res))) return;
      state = { ...state, adminAccess: true };
    }

    if (requestedBinId) {
      const baseUrl = getProxyHost(req);
      const principal = await getPrincipal(req);
      const locked = await isBinLocked(requestedBinId);
      const unlocked = !locked || (await isBinAuthorized(req, requestedBinId));
      const bin = await getStorageBin(requestedBinId);
      const database = await getDatabase();
      const credential = principal && database && await database.get(
        'SELECT id FROM user_s3_credentials WHERE user_issuer = ? AND user_subject = ? AND revoked_at IS NULL LIMIT 1',
        [principal.issuer, principal.subject],
      );
      const s3Connected = Boolean(credential);
      let files: any[] = [];
      let storage = { used: 0, quota: await getBinQuota(requestedBinId) };
      if (s3Connected && unlocked) {
        const fileIds = await readBin(requestedBinId, principal);
        if (fileIds === null) return notFoundPage(res);
        files = await Promise.all(fileIds.map((id) => readMetadata(requestedBinId, id, baseUrl, principal)));
        files = files.filter(Boolean);
        storage = await getBinStorage(requestedBinId, principal);
      }

      state = {
        ...state,
        binName: bin?.name || '',
        files,
        filesLoaded: true,
        locked,
        unlocked,
        s3Connected,
        binStorage: storage,
        binDeletionRequestedAt: bin?.deletion_requested_at || null,
        binDeletionExpiresAt: bin?.deletion_expires_at || null,
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

  const principal = await getPrincipal(req);
  const storage = await getStorageBackend(principal);

  if (!(await getStorageBin(binId))) return notFound(res);

  const uid = randomUUID();
  const tmpFile = join(tmpdir(), `filebin-${uid}.zip`);

  try {
    await new Promise<void>((resolve, reject) => {
      const stream = createWriteStream(tmpFile);
      stream.on('finish', resolve);
      stream.on('error', reject);
      req.pipe(stream);
    });
    const zipSize = await getZipUncompressedSize(tmpFile);
    await withBinStorageLock(binId, async () => {
      const usage = await getBinStorageUsage(binId, undefined, principal);
      const quota = await getBinQuota(binId);
      if (quota && usage.used + usage.reserved + zipSize > quota) {
        throw new Error('Bin storage quota exceeded');
      }
      await extractZipFileToStorage(tmpFile, binId, storage);
    });

    res.writeHead(202).end(`{"binId": "${binId}"}`);
  } catch (error) {
    console.log(error);
    res
      .writeHead(error instanceof Error && error.message === 'Bin storage quota exceeded' ? 413 : 500)
      .end(
        error instanceof Error && error.message === 'Bin storage quota exceeded' ? 'Bin storage quota exceeded' : '',
      );
  } finally {
    await unlink(tmpFile).catch(() => {});
  }
}

function getZipUncompressedSize(path: string): Promise<number> {
  return new Promise((resolve, reject) => {
    yauzl.open(path, { strictFileNames: true, lazyEntries: true, decodeStrings: true }, (error, zip) => {
      if (error) return reject(error);
      let size = 0;
      zip.on('error', reject);
      zip.on('entry', (entry) => {
        size += entry.fileName.endsWith('/') ? 0 : entry.uncompressedSize;
        zip.readEntry();
      });
      zip.once('end', () => {
        zip.close();
        resolve(size);
      });
      zip.readEntry();
    });
  });
}

async function extractZipFileToStorage(path: string, binId: string, storage: StorageBackend): Promise<void> {
  return new Promise((resolve, reject) => {
    yauzl.open(path, { strictFileNames: true, lazyEntries: true, decodeStrings: true }, (error, zip) => {
      if (error) return reject(error);
      zip.on('error', reject);
      const writes: Promise<void>[] = [];
      zip.once('end', async () => {
        try {
          await Promise.all(writes);
          zip.close();
          resolve();
        } catch (writeError) {
          reject(writeError);
        }
      });
      zip.on('entry', (entry) => {
        if (entry.fileName.endsWith('/')) {
          zip.readEntry();
          return;
        }
        zip.openReadStream(entry, async (streamError, readStream) => {
          if (streamError) return reject(streamError);
          const fileId = randomUUID();
          const chunks: Buffer[] = [];
          readStream.on('data', (chunk: Buffer) => chunks.push(chunk));
          readStream.on('end', async () => {
            try {
              const data = Buffer.concat(chunks);
              writes.push((async () => {
                const { sha256, size } = await storage.writeObject(binId, fileId, data, {});
                await recordCompletedFile(binId, fileId, size, sha256, { name: entry.fileName, type: 'application/octet-stream' });
              })());
              zip.readEntry();
            } catch (e) {
              reject(e);
            }
          });
          readStream.on('error', reject);
        });
      });
      zip.readEntry();
    });
  });
}

async function onLockStatus(req, res, args) {
  const { binId = '' } = args;
  if (!(await getStorageBin(binId))) return notFound(res);

  const locked = await isBinLocked(binId);
  const unlocked = !locked || (await isBinAuthorized(req, binId));
  res.writeHead(200, jsonHeaders).end(JSON.stringify({ locked, unlocked }));
}

async function onUnlockBin(req, res, args) {
  const { binId = '' } = args;
  if (!(await getStorageBin(binId))) return notFound(res);

  const { password = '' } = await readJson(req);

  if (!(await verifyBinPassword(binId, password))) {
    return unauthorized(res);
  }

  setUnlockCookie(req, res, binId);
  res.writeHead(204).end();
}

async function onSetBinPassword(req, res, args) {
  const { binId = '' } = args;
  const database = await getDatabase();
  if (!database || !(await getStorageBin(binId))) return notFound(res);

  const { password = '' } = await readJson(req);

  if (typeof password !== 'string' || password.length < 8) {
    return badRequest(res, 'Password must contain at least 8 characters');
  }

  const salt = randomBytes(16).toString('base64url');
  const hash = Buffer.from((await scrypt(password, salt, 32)) as Buffer).toString('base64url');
  await database.run('UPDATE storage_bins SET lock_salt = ?, lock_hash = ? WHERE id = ?', [salt, hash, binId]);
  setUnlockCookie(req, res, binId);
  res.writeHead(204).end();
}

async function onRemoveBinPassword(req, res, args) {
  const { binId = '' } = args;
  const database = await getDatabase();
  if (!database || !(await getStorageBin(binId))) return notFound(res);
  await database.run('UPDATE storage_bins SET lock_salt = NULL, lock_hash = NULL WHERE id = ?', [binId]);
  clearUnlockCookie(req, res, binId);
  res.writeHead(204).end();
}

async function onDownloadZip(_req, res, args) {
  let { binId = '' } = args;
  binId = binId.replace('.zip', '');

  const principal = await getPrincipal(_req);
  const storage = await getStorageBackend(principal);
  const database = await getDatabase();
  if (!database || !(await getStorageBin(binId))) return notFound(res);

  tryCatch(res, async () => {
    const zip = new yazl.ZipFile();
    const [objects, catalog] = await Promise.all([
      storage.listObjects(binId),
      database.all('SELECT id, metadata FROM storage_files WHERE bin_id = ?', [binId]),
    ]);
    const metadataById = new Map<string, any>((catalog as any[]).map((row) => [row.id, JSON.parse(row.metadata || '{}')]));
    const files = objects.filter((fileId) => metadataById.has(fileId));

    res.setHeader('content-type', 'application/x-zip');
    res.setHeader('Content-Disposition', `attachment; filename="archive-${binId.slice(0, 8)}.zip"`);
    zip.outputStream.pipe(res);

    for (const fileId of files) {
      const { data } = await storage.readObject(binId, fileId);
      const fileName = metadataById.get(fileId)?.name || fileId;
      
      if (data && typeof (data as any).pipe === 'function') {
        // Node.js ReadStream
        await new Promise<void>((resolve, reject) => {
          const chunks: Buffer[] = [];
          (data as any).on('data', (chunk: Buffer) => chunks.push(chunk));
          (data as any).on('end', () => {
            zip.addBuffer(Buffer.concat(chunks), fileName);
            resolve();
          });
          (data as any).on('error', reject);
        });
      } else if (data && typeof (data as any)[Symbol.asyncIterator] === 'function') {
        // Web ReadableStream
        for await (const chunk of data as AsyncIterable<Uint8Array>) {
          zip.addBuffer(Buffer.from(chunk), fileName);
        }
      }
    }

    zip.end();
  });
}

function notFound(res) {
  res.writeHead(404).end('Not found');
}

function notFoundPage(res) {
  res
    .writeHead(404, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
    .end(
      `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Bin not found | File Bin</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:linear-gradient(145deg,#eff3ff,#e6edff 48%,#f4efff);color:#111a37;font-family:ui-rounded,"Avenir Next",system-ui,sans-serif}.card{box-sizing:border-box;width:min(100% - 2rem,28rem);padding:2.5rem;border:1px solid #dce4ff;border-radius:2rem;background:rgba(255,255,255,.92);box-shadow:0 18px 45px rgba(61,83,165,.14);text-align:center}.mark{display:grid;place-items:center;width:3.5rem;height:3.5rem;margin:0 auto 1.5rem;border-radius:1.1rem;background:#496ef0;color:#fff;font-size:1.5rem}h1{margin:0;font-size:1.75rem}p{margin:1rem 0 1.75rem;color:#5d6885;line-height:1.6}.actions{display:flex;justify-content:center;gap:.75rem;flex-wrap:wrap}a{padding:.75rem 1rem;border-radius:.85rem;font-weight:700;text-decoration:none;background:#496ef0;color:#fff}</style></head><body><main class="card"><div class="mark">?</div><h1>This bin is not here</h1><p>It may have been deleted, expired, or the link may be incomplete.</p><div class="actions"><a href="/app">Open File Bin</a></div></main></body></html>`,
    );
}

function badRequest(res, message = 'Bad request') {
  res.writeHead(400).end(message);
}

function unauthorized(res) {
  res
    .writeHead(401, { ...jsonHeaders, 'www-authenticate': 'Basic realm="FileBin"' })
    .end(JSON.stringify({ error: 'This bin is locked' }));
}

function forbidden(res) {
  res.writeHead(403, jsonHeaders).end(JSON.stringify({ error: 'Administrator access required' }));
}

function unauthenticated(res) {
  res.writeHead(401, jsonHeaders).end(JSON.stringify({ error: 'Authentication required' }));
}

function authUnavailable(res) {
  res
    .writeHead(503, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
    .end(
      `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Sign in unavailable | File Bin</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:linear-gradient(145deg,#eff3ff,#e6edff 48%,#f4efff);color:#111a37;font-family:ui-rounded,"Avenir Next",system-ui,sans-serif}.card{box-sizing:border-box;width:min(100% - 2rem,28rem);padding:2.5rem;border:1px solid #dce4ff;border-radius:2rem;background:rgba(255,255,255,.92);box-shadow:0 18px 45px rgba(61,83,165,.14);text-align:center}.mark{display:grid;place-items:center;width:3.5rem;height:3.5rem;margin:0 auto 1.5rem;border-radius:1.1rem;background:#496ef0;color:#fff;font-size:1.5rem}h1{margin:0;font-size:1.75rem}p{margin:1rem 0 1.75rem;color:#5d6885;line-height:1.6}.actions{display:flex;justify-content:center;gap:.75rem;flex-wrap:wrap}a{padding:.75rem 1rem;border-radius:.85rem;font-weight:700;text-decoration:none}a:first-child{background:#496ef0;color:#fff}a:last-child{border:1px solid #dce4ff;color:#4055a5}</style></head><body><main class="card"><div class="mark">!</div><h1>Sign in is taking a moment</h1><p>We could not reach the sign-in service. Your files are safe. Please try again in a moment.</p><div class="actions"><a href="/auth/login">Try again</a><a href="/">Return home</a></div></main></body></html>`,
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

async function readBinLock(binId: string) {
  const database = await getDatabase();
  if (!database) return null;
  const lock = await database.get('SELECT lock_salt, lock_hash FROM storage_bins WHERE id = ?', [binId]);
  return lock?.lock_salt && lock?.lock_hash ? { salt: lock.lock_salt, hash: lock.lock_hash } : null;
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
  if (!(await isBinLocked(binId))) return false;
  if (hasValidUnlockCookie(req, binId)) return true;

  const authorization = String(req.headers.authorization || '');

  if (authorization.startsWith('Basic ')) {
    const credentials = Buffer.from(authorization.slice(6), 'base64').toString('utf8');
    const password = credentials.slice(credentials.indexOf(':') + 1);
    return verifyBinPassword(binId, password);
  }

  return false;
}

async function canAccessBin(req, binId: string) {
  const bin = await getStorageBin(binId);
  if (!bin || bin.deletion_requested_at) return false;
  const principal = await getPrincipal(req);
  const owner = Boolean(
    principal && rtrimIssuer(bin.owner_issuer) === rtrimIssuer(principal.issuer) && bin.owner_subject === principal.subject,
  );
  const admin = isAdminPrincipal(principal);
  return owner || admin;
}

function rtrimIssuer(value) {
  return String(value || '').replace(/\/+$/, '');
}

async function cleanupAbandonedUploads() {
  const database = await getDatabase();
  if (!database || !Number.isFinite(uploadRetentionMs) || uploadRetentionMs <= 0) return;
  const cutoff = Date.now() - uploadRetentionMs;
  const expired = await database.all(
    `SELECT u.bin_id, u.file_id, u.state, b.owner_issuer, b.owner_subject
     FROM storage_uploads u JOIN storage_bins b ON b.id = u.bin_id WHERE u.updated_at < ?`,
    [cutoff],
  );
  for (const row of expired) {
    await withUploadLock(getUploadStatePath(row.bin_id, row.file_id), async () => {
      const current = await readUploadState(row.bin_id, row.file_id);
      if (!current) return;
      const storage = await getStorageBackend({ issuer: row.owner_issuer, subject: row.owner_subject });
      if (current.uploadId) await storage.abortMultipartUpload(row.bin_id, row.file_id, current.uploadId);
      await deleteUploadState(row.bin_id, row.file_id);
    });
  }
}

async function cleanupDeletedBins() {
  const database = await getDatabase();
  if (!database) return [];
  const now = Date.now();
  const bins = await database.all('SELECT id FROM storage_bins WHERE deletion_expires_at IS NOT NULL AND deletion_expires_at < ?', [now]);
  for (const { id } of bins) {
    await permanentlyDeleteBin(id);
  }
  return bins.map((bin) => bin.id);
}

async function onBinCleanup(req, res) {
  const token = String(req.headers.authorization || '').replace(/^Bearer /, '');
  if (!binCleanupToken || token !== binCleanupToken) return unauthenticated(res);
  const deleted = await cleanupDeletedBins();
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

  if (['/', '/app', '/help'].includes(url.pathname) && url.searchParams.has('bin')) {
    return url.searchParams.get('bin');
  }

  if (!['bin', 'f', 'meta', 'zip', 'lock', 'b'].includes(resource) || !rawBinId) {
    return null;
  }

  if (resource === 'bin' && req.method === 'POST') return null;
  if (resource === 'lock' && ['GET', 'POST'].includes(req.method)) return null;
  return resource === 'zip' ? rawBinId.replace(/\.zip$/, '') : rawBinId;
}

const match = router({
  'GET /': onGetUI,
  'GET /app': onGetUI,
  'GET /help': onGetUI,
  'GET /admin': onGetUI,
  'GET /settings': onGetUI,
  'GET /auth/profile': onAuthProfile,
  'GET /api/bins': onAuthBins,
  'GET /auth/s3-credentials': onAuthS3Credentials,
  'POST /auth/s3-credentials': onAuthCreateS3Credential,
  'DELETE /auth/s3-credentials/:credentialId': onAuthDeleteS3Credential,
  'GET /admin/stats': onAdminStats,
  'POST /admin/reconcile': onAdminReconcile,
  'PATCH /admin/bins/:binId/quota': onAdminQuota,
  'GET /admin/users/:subject/s3-credentials': onAdminListUserS3Credentials,
  'DELETE /admin/users/:subject/s3-credentials/:credentialId': onAdminRevokeUserS3Credential,
  'GET /auth/login': onAuthLogin,
  'GET /auth/callback': onAuthCallback,
  'POST /auth/logout': onAuthLogout,
  'POST /admin/cleanup': onBinCleanup,
  'GET /b/:binId': onGetUI,
  'GET /manifest.webmanifest': onGetManifest,
  'GET /icon.svg': onGetIcon,
  'GET /api': onApiSpec,
  'GET /api.yaml': onApiSpec,
  'GET /api.json': onApiSpec,
  'GET /index.mjs': onEsModule,
  'POST /bin': onCreateBin,
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
  const testAdapters = (globalThis as any).__FILEBIN_TEST_ADAPTERS__;
  if (!databaseModuleUrl && !(process.env.NODE_ENV === 'test' && testAdapters?.database)) {
    throw new Error('Cannot start without DATABASE_URL in environment.');
  }
  cleanupAbandonedUploads().catch((error) => console.log(error));
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

      const pathname = new URL(req.url, 'http://localhost').pathname;
      const isUiRequest = ['/', '/app', '/help', '/settings'].includes(pathname) || pathname.startsWith('/b/');
      if (binId && !(await canAccessBin(req, binId))) {
        const principal = await getPrincipal(req);
        if (!(await getStorageBin(binId))) return isUiRequest ? notFoundPage(res) : notFound(res);
        if (isUiRequest && !principal) {
          const loginUrl = new URL('/auth/login', getProxyHost(req));
          loginUrl.searchParams.set('url', String(new URL(req.url, getProxyHost(req))));
          return res.writeHead(302, { location: String(loginUrl) }).end();
        }
        return unauthenticated(res);
      }

      if (binId && !isUiRequest && !(pathname.startsWith('/lock/') && ['GET', 'POST'].includes(req.method))) {
        if ((await isBinLocked(binId)) && !(await isBinAuthorized(req, binId))) return unauthorized(res);
      }

      match(req, res);
    });
  }).listen(Number(options.port ?? process.env.PORT));
}

export default start;
