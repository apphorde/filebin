import { createHash, randomUUID } from 'node:crypto';
import { Readable } from 'node:stream';
import { DatabaseSync } from 'node:sqlite';

export const subject = 'test-user';
export const authHeaders = { 'x-test-oidc-sub': subject };

const sqlite = new DatabaseSync(':memory:');
sqlite.exec(`
  CREATE TABLE oidc_sessions (id TEXT PRIMARY KEY, profile TEXT NOT NULL, access_token TEXT, refresh_token TEXT, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL);
  CREATE TABLE user_s3_credentials (
    id TEXT PRIMARY KEY, user_issuer TEXT NOT NULL, user_subject TEXT NOT NULL,
    access_key TEXT NOT NULL, secret_key TEXT NOT NULL DEFAULT '', encrypted_secret TEXT,
    encryption_iv TEXT, encryption_tag TEXT, endpoint TEXT NOT NULL, region TEXT NOT NULL,
    bucket_name TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, revoked_at INTEGER
  );
  CREATE TABLE storage_bins (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, visibility TEXT NOT NULL DEFAULT 'private',
    owner_issuer TEXT, owner_subject TEXT, bucket_name TEXT, created_at INTEGER NOT NULL,
    last_completed_upload_at INTEGER, imported_at INTEGER, deletion_requested_at INTEGER,
    deletion_expires_at INTEGER, lock_salt TEXT, lock_hash TEXT
  );
  CREATE TABLE storage_files (
    bin_id TEXT NOT NULL, id TEXT NOT NULL, metadata TEXT NOT NULL,
    system_metadata TEXT NOT NULL, size INTEGER NOT NULL, updated_at INTEGER NOT NULL,
    PRIMARY KEY(bin_id, id)
  );
  CREATE TABLE storage_uploads (bin_id TEXT NOT NULL, file_id TEXT NOT NULL, state TEXT NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY(bin_id, file_id));
  CREATE TABLE storage_bin_quota_overrides (bin_id TEXT PRIMARY KEY, extra_bytes INTEGER NOT NULL, updated_at INTEGER NOT NULL);
  CREATE TABLE audit_events (id INTEGER PRIMARY KEY, actor_subject TEXT, action TEXT NOT NULL, target TEXT NOT NULL, created_at INTEGER NOT NULL);
`);

export const database = {
  exec: async (sql) => sqlite.exec(sql),
  get: async (sql, parameters = []) => sqlite.prepare(sql).get(...parameters),
  all: async (sql, parameters = []) => sqlite.prepare(sql).all(...parameters),
  run: async (sql, parameters = []) => sqlite.prepare(sql).run(...parameters),
};

class MemoryS3Storage {
  buckets = new Map();
  uploads = new Map();

  bucket(binId) {
    const bucket = this.buckets.get(binId);
    if (!bucket) throw new Error('NoSuchBucket');
    return bucket;
  }

  async createBucket(binId) {
    this.buckets.set(binId, this.buckets.get(binId) || new Map());
  }

  async bucketExists(binId) {
    return this.buckets.has(binId);
  }

  async writeObject(binId, fileId, data, metadata = {}) {
    const body = Buffer.from(data);
    const sha256 = createHash('sha256').update(body).digest('hex');
    this.bucket(binId).set(fileId, { body, metadata: { ...metadata }, sha256, lastModified: Date.now() });
    return { size: body.length, sha256 };
  }

  async readObject(binId, fileId, range) {
    const object = this.bucket(binId).get(fileId);
    if (!object) throw new Error('NoSuchKey');
    const body = range ? object.body.subarray(range.start, range.end + 1) : object.body;
    return { data: Readable.from([body]), size: body.length, metadata: object.metadata, sha256: object.sha256 };
  }

  async deleteObject(binId, fileId) {
    this.bucket(binId).delete(fileId);
  }

  async listObjects(binId) {
    return [...this.bucket(binId).keys()];
  }

  async getObjectMetadata(binId, fileId) {
    const object = this.bucket(binId).get(fileId);
    return object
      ? { size: object.body.length, metadata: object.metadata, sha256: object.sha256, lastModified: object.lastModified }
      : null;
  }

  async createMultipartUpload(binId, fileId) {
    this.bucket(binId);
    const uploadId = randomUUID();
    this.uploads.set(uploadId, { binId, fileId, parts: new Map() });
    return uploadId;
  }

  async uploadPart(binId, fileId, uploadId, partNumber, data) {
    const upload = this.uploads.get(uploadId);
    if (!upload || upload.binId !== binId || upload.fileId !== fileId) throw new Error('NoSuchUpload');
    const body = Buffer.from(data);
    const etag = createHash('md5').update(body).digest('hex');
    upload.parts.set(partNumber, body);
    return { etag };
  }

  async completeMultipartUpload(binId, fileId, uploadId, parts) {
    const upload = this.uploads.get(uploadId);
    if (!upload) throw new Error('NoSuchUpload');
    const body = Buffer.concat(parts.map(({ partNumber }) => upload.parts.get(partNumber)));
    this.uploads.delete(uploadId);
    return this.writeObject(binId, fileId, body, {});
  }

  async abortMultipartUpload(_binId, _fileId, uploadId) {
    this.uploads.delete(uploadId);
  }

  async getBucketUsage(binId) {
    const objects = [...this.bucket(binId).values()];
    return { used: objects.reduce((sum, object) => sum + object.body.length, 0), reserved: 0 };
  }

  async deleteBucket(binId) {
    this.buckets.delete(binId);
  }
}

export const storage = new MemoryS3Storage();

export async function startTestServer(port = 0) {
  process.env.NODE_ENV = 'test';
  process.env.SESSION_SECRET ||= 'test-session-secret-long-enough-to-derive-a-key';
  process.env.ADMIN_SUBJECTS ||= 'test-admin';
  globalThis.__FILEBIN_TEST_ADAPTERS__ = {
    database,
    storageFactory: () => storage,
    validateS3Credentials: async () => true,
  };
  const { start } = await import('../dist/index.js');
  const server = start({ port });
  await new Promise((resolve) => server.once('listening', resolve));
  return server;
}

export function requestHeaders(extra = {}) {
  return { ...authHeaders, ...extra };
}
