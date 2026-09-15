import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import * as yazl from 'yazl';

const rootDir = await mkdtemp(join(tmpdir(), 'filebin-quota-'));
process.env.ROOT_DIR = rootDir;
process.env.BIN_MAX_STORAGE_BYTES = '8';
const { start } = await import('../dist/index.js');
const server = start({ port: 0 });
await new Promise((resolve) => server.once('listening', resolve));
const baseUrl = `http://127.0.0.1:${server.address().port}`;

async function createFile(binId) {
  const response = await fetch(`${baseUrl}/f/${binId}`, { method: 'POST' });
  assert.equal(response.status, 201);
  return (await response.json()).fileId;
}

async function writePart(binId, fileId, body, start, total) {
  const bytes = Buffer.from(body);
  return fetch(`${baseUrl}/f/${binId}/${fileId}`, {
    method: 'PUT',
    headers: {
      'content-range': `bytes ${start}-${start + bytes.length - 1}/${total}`,
      digest: `sha-256=${createHash('sha256').update(bytes).digest('base64')}`,
    },
    body: bytes,
  });
}

async function createZip(content) {
  const zip = new yazl.ZipFile();
  const chunks = [];
  zip.outputStream.on('data', (chunk) => chunks.push(chunk));
  const complete = new Promise((resolve, reject) => {
    zip.outputStream.on('end', resolve);
    zip.outputStream.on('error', reject);
  });
  zip.addBuffer(Buffer.from(content), 'oversized.txt');
  zip.end();
  await complete;
  return Buffer.concat(chunks);
}

test.after(async () => {
  await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  await rm(rootDir, { recursive: true, force: true });
});

test('quota reservations cover partial uploads and completed files', async () => {
  const binId = (await (await fetch(`${baseUrl}/bin`, { method: 'POST' })).json()).binId;
  const firstFile = await createFile(binId);

  let response = await writePart(binId, firstFile, 'abcd', 0, 8);
  assert.equal(response.status, 202);

  const reservedFile = await createFile(binId);
  response = await writePart(binId, reservedFile, 'x', 0, 1);
  assert.equal(response.status, 413);

  response = await writePart(binId, firstFile, 'efgh', 4, 8);
  assert.equal(response.status, 202);

  const fullFile = await createFile(binId);
  response = await fetch(`${baseUrl}/f/${binId}/${fullFile}`, { method: 'PUT', body: 'x' });
  assert.equal(response.status, 413);
});

test('regular uploads are rejected before they can commit past the quota', async () => {
  const binId = (await (await fetch(`${baseUrl}/bin`, { method: 'POST' })).json()).binId;
  const fileId = await createFile(binId);
  const response = await fetch(`${baseUrl}/f/${binId}/${fileId}`, { method: 'PUT', body: '123456789' });

  assert.equal(response.status, 413);
  assert.deepEqual(await (await fetch(`${baseUrl}/bin/${binId}`)).json(), []);
});

test('ZIP imports are rejected before extracting files past the quota', async () => {
  const binId = (await (await fetch(`${baseUrl}/bin`, { method: 'POST' })).json()).binId;
  const response = await fetch(`${baseUrl}/zip/${binId}.zip`, {
    method: 'POST',
    body: await createZip('123456789'),
  });

  assert.equal(response.status, 413);
  assert.deepEqual(await (await fetch(`${baseUrl}/bin/${binId}`)).json(), []);
});
