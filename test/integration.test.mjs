import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import * as yauzl from 'yauzl';
import * as yazl from 'yazl';
import { database, requestHeaders, startTestServer, storage, subject } from './adapters.mjs';

const server = await startTestServer();
const baseUrl = `http://127.0.0.1:${server.address().port}`;
const secret = 's3-secret-value-that-must-not-be-stored-plaintext';
await database.run(
  `INSERT INTO user_s3_credentials
    (id, user_issuer, user_subject, access_key, secret_key, encrypted_secret, encryption_iv, encryption_tag, endpoint, region, created_at, updated_at)
   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ['test-credential', 'https://test-issuer.invalid', subject, 'ACCESSKEY123456789', 'placeholder', 'encrypted-placeholder', 'iv', 'tag', 'https://s3.api.apphor.de', 'local', Date.now(), Date.now()],
);

async function api(path, init = {}, as = subject) {
  const headers = new Headers(init.headers);
  if (as) headers.set('x-test-oidc-sub', as);
  return fetch(baseUrl + path, { ...init, headers });
}

async function createBin() {
  const response = await api('/bin', { method: 'POST' });
  assert.equal(response.status, 201);
  const result = await response.json();
  assert.equal(result.binId.length, 36);
  return result;
}

async function createFile(binId, metadata = {}, partSize = 8 * 1024 * 1024) {
  const response = await api(`/f/${binId}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ metadata, partSize }),
  });
  assert.equal(response.status, 201);
  return (await response.json()).fileId;
}

async function writePart(binId, fileId, bytes, start, total) {
  const body = Buffer.from(bytes);
  return api(`/f/${binId}/${fileId}`, {
    method: 'PUT',
    headers: {
      'content-range': `bytes ${start}-${start + body.length - 1}/${total}`,
      digest: `sha-256=${createHash('sha256').update(body).digest('base64')}`,
    },
    body,
  });
}

async function makeZip(entries) {
  const zip = new yazl.ZipFile();
  const chunks = [];
  zip.outputStream.on('data', (chunk) => chunks.push(chunk));
  const done = new Promise((resolve, reject) => {
    zip.outputStream.on('end', resolve);
    zip.outputStream.on('error', reject);
  });
  for (const [name, body] of Object.entries(entries)) zip.addBuffer(Buffer.from(body), name);
  zip.end();
  await done;
  return Buffer.concat(chunks);
}

async function unzip(buffer) {
  return new Promise((resolve, reject) => {
    yauzl.fromBuffer(buffer, { lazyEntries: true }, (error, zip) => {
      if (error) return reject(error);
      const files = {};
      zip.on('error', reject);
      zip.on('end', () => resolve(files));
      zip.on('entry', (entry) => {
        zip.openReadStream(entry, (streamError, stream) => {
          if (streamError) return reject(streamError);
          const chunks = [];
          stream.on('data', (chunk) => chunks.push(chunk));
          stream.on('error', reject);
          stream.on('end', () => {
            files[entry.fileName] = Buffer.concat(chunks).toString();
            zip.readEntry();
          });
        });
      });
      zip.readEntry();
    });
  });
}

test.after(async () => {
  await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
});

test('anonymous bins are rejected; authenticated bins get private ID-matched S3 buckets', async () => {
  assert.equal((await api('/bin', { method: 'POST' }, null)).status, 401);
  const { binId } = await createBin();
  const bin = await database.get('SELECT id, name, visibility, owner_issuer, owner_subject, bucket_name FROM storage_bins WHERE id = ?', [binId]);
  assert.deepEqual({ id: bin.id, visibility: bin.visibility, owner: bin.owner_subject, bucket: bin.bucket_name }, {
    id: binId,
    visibility: 'private',
    owner: subject,
    bucket: binId,
  });
  assert.equal(await storage.bucketExists(binId), true);
  assert.equal((await api(`/bin/${binId}`, {}, 'another-user')).status, 401);
  assert.equal((await api(`/f/${binId}/missing`, {}, null)).status, 401);
});

test('file bytes and metadata remain independent and integrity fields are cataloged', async () => {
  const { binId } = await createBin();
  const fileId = await createFile(binId, { name: 'docs/report.txt', type: 'text/plain', project: 'alpha' });
  const content = 'preserve these exact bytes';
  let response = await api(`/f/${binId}/${fileId}`, { method: 'PUT', body: content });
  assert.equal(response.status, 202);

  const originalDigest = createHash('sha256').update(content).digest('hex');
  let file = await database.get('SELECT metadata, system_metadata, size FROM storage_files WHERE bin_id = ? AND id = ?', [binId, fileId]);
  assert.equal(file.size, Buffer.byteLength(content));
  assert.equal(JSON.parse(file.system_metadata).sha256, originalDigest);

  response = await api(`/meta/${binId}/${fileId}`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ name: 'docs/final-report.txt', project: 'beta' }),
  });
  assert.equal(response.status, 202);
  assert.equal(await (await api(`/f/${binId}/${fileId}`)).text(), content, 'metadata changes must not rewrite S3 object bytes');
  const metadata = await (await api(`/meta/${binId}/${fileId}`)).json();
  assert.equal(metadata.name, 'docs/final-report.txt');
  assert.equal(metadata.project, 'beta');
  assert.equal(metadata.size, Buffer.byteLength(content));
  assert.equal(metadata.sha256, originalDigest);

  response = await api(`/bin/${binId}`, { method: 'PATCH', body: JSON.stringify({ name: 'Project documents' }) });
  assert.equal(response.status, 204);
  assert.equal((await (await api(`/meta/${binId}`)).json()).name, 'Project documents');
});

test('resumable S3 multipart upload records verified ranges and publishes only after completion', async () => {
  const { binId } = await createBin();
  const partSize = 5 * 1024 * 1024;
  const fileId = await createFile(binId, { name: 'archive.bin' }, partSize);
  const first = Buffer.alloc(partSize, 0x61);
  const last = Buffer.from('tail');
  const total = first.length + last.length;

  let response = await writePart(binId, fileId, last, first.length, total);
  assert.equal(response.status, 202);
  assert.deepEqual(await response.json(), { complete: false });
  response = await api(`/f/${binId}/${fileId}`);
  assert.equal(response.status, 404, 'incomplete multipart data is not visible');

  response = await writePart(binId, fileId, first, 0, total);
  assert.equal(response.status, 202);
  assert.equal((await response.json()).id, fileId);
  const saved = await (await api(`/f/${binId}/${fileId}`)).arrayBuffer();
  assert.deepEqual(Buffer.from(saved), Buffer.concat([first, last]));
  assert.equal((await api(`/f/${binId}/${fileId}/upload`)).status, 404);
  const metadata = await (await api(`/meta/${binId}/${fileId}`)).json();
  assert.equal(metadata.sha256, createHash('sha256').update(first).update(last).digest('hex'));
});

test('password lock is additional to OIDC ownership and SSR does not reveal file metadata', async () => {
  const { binId } = await createBin();
  const fileId = await createFile(binId, { name: 'private/secret.txt' });
  await api(`/f/${binId}/${fileId}`, { method: 'PUT', body: 'secret bytes' });

  let response = await api(`/lock/${binId}`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ password: 'correct horse battery staple' }),
  });
  assert.equal(response.status, 204);
  const cookie = response.headers.get('set-cookie').split(';')[0];
  const lock = await database.get('SELECT lock_salt, lock_hash FROM storage_bins WHERE id = ?', [binId]);
  assert.ok(lock.lock_salt && lock.lock_hash);
  assert.equal(lock.lock_hash.includes('correct horse'), false);

  response = await api(`/b/${binId}`);
  assert.equal(response.status, 200);
  assert.doesNotMatch(await response.text(), /private\/secret\.txt/);
  assert.equal((await api(`/f/${binId}/${fileId}`)).status, 401);
  assert.equal((await api(`/bin/${binId}`, { headers: { cookie } }, 'other-user')).status, 401);

  response = await api(`/f/${binId}/${fileId}`, { headers: { cookie } });
  assert.equal(response.status, 200);
  assert.equal(await response.text(), 'secret bytes');
});

test('password-protected account credentials are encrypted and associated with OIDC subject', async () => {
  const accessKey = 'ACCESSKEY1234567890';
  const response = await api('/auth/s3-credentials', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ accessKey, secretKey: secret }),
  }, 's3-connect-user');
  assert.equal(response.status, 201);
  const credential = await response.json();
  assert.equal(credential.connected, undefined);
  assert.equal(credential.endpoint, 'https://s3.api.apphor.de');

  const stored = await database.get('SELECT user_issuer, user_subject, secret_key, encrypted_secret, encryption_iv, encryption_tag FROM user_s3_credentials WHERE id = ?', [credential.id]);
  assert.equal(stored.user_subject, 's3-connect-user');
  assert.equal(stored.secret_key, '');
  assert.ok(stored.encrypted_secret);
  assert.notEqual(stored.encrypted_secret, secret);
  assert.ok(stored.encryption_iv && stored.encryption_tag);
  assert.deepEqual(await (await api('/auth/s3-credentials', {}, 's3-connect-user')).json(), {
    connected: true,
    id: credential.id,
    endpoint: 'https://s3.api.apphor.de',
    region: 'local',
    created_at: credential.createdAt,
    updated_at: credential.createdAt,
  });
});

test('ZIP round trip preserves nested virtual folder paths in canonical metadata', async () => {
  const { binId } = await createBin();
  const archive = await makeZip({ 'photos/2026/image.txt': 'image data', 'docs/readme.md': '# Read me' });
  let response = await api(`/zip/${binId}.zip`, { method: 'POST', body: archive });
  assert.equal(response.status, 202);

  const fileIds = await (await api(`/bin/${binId}`)).json();
  const names = await Promise.all(fileIds.map(async (id) => (await (await api(`/meta/${binId}/${id}`)).json()).name));
  assert.deepEqual(names.sort(), ['docs/readme.md', 'photos/2026/image.txt']);

  response = await api(`/zip/${binId}.zip`);
  assert.equal(response.status, 200);
  assert.deepEqual(await unzip(Buffer.from(await response.arrayBuffer())), {
    'photos/2026/image.txt': 'image data',
    'docs/readme.md': '# Read me',
  });
});

test('OpenAPI and UI document authenticated private S3 bins without public visibility', async () => {
  const specResponse = await api('/api.json?cache-bust=1', {}, null);
  assert.equal(specResponse.status, 200);
  const spec = await specResponse.json();
  assert.equal(spec.info.version, '1.4.0');
  assert.equal(spec.paths['/auth/s3-credentials'].post.operationId, 'connectS3Account');
  assert.equal(JSON.stringify(spec).includes('enum: [public, private]'), false);

  const html = await (await api('/app')).text();
  assert.match(html, /Connect your S3 account/);
  assert.doesNotMatch(html, /Make public|public temporary bin/i);
  const ids = Object.values(spec.paths).flatMap((path) => Object.values(path).flatMap((op) => op?.operationId || []));
  assert.equal(new Set(ids).size, ids.length);
});
