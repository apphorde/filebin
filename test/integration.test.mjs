import assert from 'node:assert/strict';
import { execFile as execFileCallback } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, truncate, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { load } from 'js-yaml';
import * as yauzl from 'yauzl';
import * as yazl from 'yazl';
import { promisify } from 'node:util';

const rootDir = await mkdtemp(join(tmpdir(), 'filebin-'));
process.env.ROOT_DIR = rootDir;
const { start } = await import('../dist/index.js');
const server = start({ port: 0 });
await new Promise((resolve) => server.once('listening', resolve));
const baseUrl = `http://127.0.0.1:${server.address().port}`;
const execFile = promisify(execFileCallback);

async function cli(...args) {
  return execFile(process.execPath, ['bin/fbin.mjs', '--server', baseUrl, ...args]);
}

async function createBin() {
  const response = await fetch(`${baseUrl}/bin`, { method: 'POST' });
  assert.equal(response.status, 201);
  assert.match(response.headers.get('location'), /\/bin\//);
  return (await response.json()).binId;
}

async function createFile(binId, metadata = {}) {
  const response = await fetch(`${baseUrl}/f/${binId}`, {
    method: 'POST',
    body: JSON.stringify(metadata),
  });
  assert.equal(response.status, 201);
  return (await response.json()).fileId;
}

async function writeFilePart(binId, fileId, body, start, total) {
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

async function createZip(entries) {
  const zip = new yazl.ZipFile();
  const chunks = [];
  zip.outputStream.on('data', (chunk) => chunks.push(chunk));
  const complete = new Promise((resolve, reject) => {
    zip.outputStream.on('end', resolve);
    zip.outputStream.on('error', reject);
  });

  for (const [name, content] of Object.entries(entries)) {
    zip.addBuffer(Buffer.from(content), name);
  }

  zip.end();
  await complete;
  return Buffer.concat(chunks);
}

async function readZip(buffer) {
  return new Promise((resolve, reject) => {
    yauzl.fromBuffer(buffer, { lazyEntries: true }, (error, zip) => {
      if (error) return reject(error);
      const entries = {};
      zip.on('error', reject);
      zip.on('end', () => resolve(entries));
      zip.on('entry', (entry) => {
        zip.openReadStream(entry, (streamError, stream) => {
          if (streamError) return reject(streamError);
          const chunks = [];
          stream.on('data', (chunk) => chunks.push(chunk));
          stream.on('error', reject);
          stream.on('end', () => {
            entries[entry.fileName] = Buffer.concat(chunks).toString();
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
  await rm(rootDir, { recursive: true, force: true });
});

test('password protection covers bin and file access without storing plaintext', async () => {
  const binId = await createBin();
  const fileId = await createFile(binId, { name: 'photos/2026/image.jpg', type: 'image/jpeg' });
  let response;
  await fetch(`${baseUrl}/f/${binId}/${fileId}`, { method: 'PUT', body: 'image' });

  response = await fetch(`${baseUrl}/lock/${binId}`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ password: 'correct horse' }),
  });
  assert.equal(response.status, 204);
  const cookie = response.headers.get('set-cookie').split(';')[0];

  assert.equal((await fetch(`${baseUrl}/bin/${binId}`)).status, 401);
  assert.equal((await fetch(`${baseUrl}/f/${binId}/${fileId}`)).status, 401);
  assert.equal((await fetch(`${baseUrl}/b/${binId}`)).status, 200);
  assert.doesNotMatch(await (await fetch(`${baseUrl}/b/${binId}`)).text(), /photos\/2026\/image\.jpg/);

  response = await fetch(`${baseUrl}/lock/${binId}`, {
    method: 'POST',
    body: JSON.stringify({ password: 'wrong password' }),
  });
  assert.equal(response.status, 401);

  response = await fetch(`${baseUrl}/bin/${binId}`, { headers: { cookie } });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), [fileId]);

  const authorization = `Basic ${Buffer.from('api:correct horse').toString('base64')}`;
  response = await fetch(`${baseUrl}/meta/${binId}/${fileId}`, { headers: { authorization } });
  assert.equal(response.status, 200);
  assert.equal((await response.json()).name, 'photos/2026/image.jpg');

  const lockFile = await readFile(join(rootDir, binId, '.bin.meta'), 'utf8');
  assert.doesNotMatch(lockFile, /correct horse/);
});

test('bin and file lifecycle preserves metadata across rename', async () => {
  const binId = await createBin();
  let response = await fetch(`${baseUrl}/meta/${binId}`, {
    method: 'PUT',
    body: JSON.stringify({ label: 'Project assets' }),
  });
  assert.equal(response.status, 202);

  const fileId = await createFile(binId, { name: 'docs/readme.txt', type: 'text/plain', custom: true });
  response = await fetch(`${baseUrl}/f/${binId}/${fileId}`, { method: 'PUT', body: 'hello' });
  assert.equal(response.status, 202);
  assert.equal((await response.json()).id, fileId);

  response = await fetch(`${baseUrl}/f/${binId}/${fileId}`, { method: 'HEAD' });
  assert.equal(response.status, 200);

  response = await fetch(`${baseUrl}/f/${binId}/${fileId}`);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('content-type'), 'text/plain');
  assert.equal(await response.text(), 'hello');

  response = await fetch(`${baseUrl}/meta/${binId}/${fileId}`);
  const metadata = await response.json();
  assert.equal(metadata.name, 'docs/readme.txt');
  assert.equal(metadata.custom, true);
  assert.equal(metadata.size, 5);
  assert.equal(metadata.id, fileId);

  const renamedId = `renamed-${Date.now()}`;
  response = await fetch(`${baseUrl}/bin/${binId}`, {
    method: 'PATCH',
    body: JSON.stringify({ newId: renamedId }),
  });
  assert.equal(response.status, 202);
  assert.equal((await response.json()).binId, renamedId);
  assert.equal((await fetch(`${baseUrl}/bin/${binId}`)).status, 404);

  response = await fetch(`${baseUrl}/meta/${renamedId}`);
  assert.equal((await response.json()).label, 'Project assets');
  response = await fetch(`${baseUrl}/meta/${renamedId}/${fileId}`);
  assert.equal((await response.json()).name, 'docs/readme.txt');

  assert.equal((await fetch(`${baseUrl}/f/${renamedId}/${fileId}`, { method: 'DELETE' })).status, 200);
  assert.equal((await fetch(`${baseUrl}/f/${renamedId}/${fileId}`, { method: 'HEAD' })).status, 404);
  assert.equal((await fetch(`${baseUrl}/bin/${renamedId}`, { method: 'DELETE' })).status, 200);
  assert.equal((await fetch(`${baseUrl}/bin/${renamedId}`)).status, 404);
});

test('parallel file parts can be resumed and publish atomically', async () => {
  const binId = await createBin();
  const fileId = await createFile(binId, { name: 'video.mp4' });
  const content = 'abcdefghijklmno';

  assert.equal((await fetch(`${baseUrl}/f/${binId}/${fileId}`)).status, 404);
  assert.deepEqual(await (await fetch(`${baseUrl}/bin/${binId}`)).json(), []);

  let response = await writeFilePart(binId, fileId, content.slice(5, 10), 5, content.length);
  assert.equal(response.status, 202);
  assert.deepEqual(await response.json(), { complete: false });

  response = await fetch(`${baseUrl}/f/${binId}/${fileId}/upload`);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    total: content.length,
    ranges: [{ start: 5, end: 9 }],
    complete: false,
  });

  response = await writeFilePart(binId, fileId, content.slice(5, 10), 5, content.length);
  assert.equal(response.status, 202, 'an exact completed part retry is idempotent');

  response = await writeFilePart(binId, fileId, 'def', 3, content.length);
  assert.equal(response.status, 409, 'overlapping parts are rejected');
  response = await writeFilePart(binId, fileId, content.slice(0, 5), 0, content.length + 1);
  assert.equal(response.status, 409, 'conflicting totals are rejected');

  const responses = await Promise.all([
    writeFilePart(binId, fileId, content.slice(0, 5), 0, content.length),
    writeFilePart(binId, fileId, content.slice(10), 10, content.length),
  ]);
  assert.deepEqual(responses.map(({ status }) => status).sort(), [202, 202]);
  const results = await Promise.all(responses.map((part) => part.json()));
  assert.ok(results.some((result) => result.url === `${baseUrl}/f/${binId}/${fileId}`));
  assert.equal(await (await fetch(`${baseUrl}/f/${binId}/${fileId}`)).text(), content);
  assert.equal((await fetch(`${baseUrl}/f/${binId}/${fileId}/upload`)).status, 404);

  const page = await (await fetch(`${baseUrl}/b/${binId}`)).text();
  assert.match(page, /"filesLoaded":true/);
  assert.match(page, /"files":\[\{"name":"video\.mp4"/);
});

test('completed upload state recovers an interrupted final rename', async () => {
  const binId = await createBin();
  const fileId = await createFile(binId, { name: 'recovered.txt' });
  const content = 'recover me';
  const range = { start: 0, end: content.length - 1 };

  await writeFile(join(rootDir, binId, `.upload-${fileId}`), content);
  await writeFile(
    join(rootDir, binId, `.upload-${fileId}.json`),
    JSON.stringify({ total: content.length, ranges: [range], pending: [], parts: [{ ...range, digest: 'test' }] }),
  );

  const response = await writeFilePart(binId, fileId, content, 0, content.length);
  assert.equal(response.status, 202);
  assert.deepEqual(await response.json(), { id: fileId, bin: binId, url: `${baseUrl}/f/${binId}/${fileId}` });
  assert.equal(await readFile(join(rootDir, binId, fileId), 'utf8'), content);
  assert.deepEqual(await (await fetch(`${baseUrl}/bin/${binId}`)).json(), [fileId]);
  assert.equal((await fetch(`${baseUrl}/f/${binId}/${fileId}/upload`)).status, 404);
});

test('file parts require a matching SHA-256 digest', async () => {
  const binId = await createBin();
  const fileId = await createFile(binId);
  const response = await fetch(`${baseUrl}/f/${binId}/${fileId}`, {
    method: 'PUT',
    headers: { 'content-range': 'bytes 0-2/3', digest: 'sha-256=invalid' },
    body: 'abc',
  });
  assert.equal(response.status, 400);
  assert.deepEqual(await (await fetch(`${baseUrl}/f/${binId}/${fileId}/upload`)).json(), {
    total: 3,
    ranges: [],
    complete: false,
  });
});

test('completed files expose a checksum, support ranges, and can be immutable', async () => {
  const binId = await createBin();
  const fileId = await createFile(binId, { name: 'backup.bin', immutable: true });
  const content = Buffer.from('0123456789');
  const digest = createHash('sha256').update(content).digest('hex');

  let response = await writeFilePart(binId, fileId, content, 0, content.length);
  assert.equal(response.status, 202);

  response = await fetch(`${baseUrl}/meta/${binId}/${fileId}`);
  const metadata = await response.json();
  assert.equal(metadata.sha256, digest);
  assert.equal(metadata.etag, `"${digest}"`);
  assert.equal(metadata.immutable, true);

  response = await fetch(`${baseUrl}/f/${binId}/${fileId}`, {
    headers: { range: 'bytes=2-5', 'if-range': `"${digest}"` },
  });
  assert.equal(response.status, 206);
  assert.equal(response.headers.get('content-range'), 'bytes 2-5/10');
  assert.equal(await response.text(), '2345');

  response = await fetch(`${baseUrl}/f/${binId}/${fileId}`, {
    method: 'PUT',
    body: 'replacement',
  });
  assert.equal(response.status, 409);
  response = await fetch(`${baseUrl}/f/${binId}/${fileId}`, { method: 'DELETE' });
  assert.equal(response.status, 409);
});

test('CLI manages bins, files, and protected access', async () => {
  const { stdout: created } = await cli('bin', 'create');
  const { binId } = JSON.parse(created);
  const localFile = join(rootDir, 'cli-source.txt');
  const downloadedFile = join(rootDir, 'cli-download.txt');
  await writeFile(localFile, 'filebin CLI upload');

  const { stdout: uploaded } = await cli('file', 'upload', binId, localFile, '--part-size', '4', '--concurrency', '2');
  const file = JSON.parse(uploaded);
  assert.equal(await readFile(join(rootDir, binId, file.id), 'utf8'), 'filebin CLI upload');

  const { stdout: listed } = await cli('file', 'list', binId);
  assert.equal(JSON.parse(listed)[0].id, file.id);
  await cli('file', 'download', binId, file.id, downloadedFile);
  assert.equal(await readFile(downloadedFile, 'utf8'), 'filebin CLI upload');
  await truncate(downloadedFile, 5);
  await cli('file', 'download', binId, file.id, downloadedFile);
  assert.equal(await readFile(downloadedFile, 'utf8'), 'filebin CLI upload');

  await cli('--password', 'correct horse', 'lock', 'set', binId);
  const { stdout: status } = await cli('lock', 'status', binId);
  assert.deepEqual(JSON.parse(status), { locked: true, unlocked: false });
  const { stdout: protectedList } = await cli('--password', 'correct horse', 'file', 'list', binId);
  assert.equal(JSON.parse(protectedList)[0].id, file.id);
  await cli('--password', 'correct horse', 'file', 'delete', binId, file.id);
  await cli('--password', 'correct horse', 'bin', 'delete', binId);
});

test('legacy MOVE rename remains supported', async () => {
  const binId = await createBin();
  const renamedId = `legacy-${Date.now()}`;
  const response = await fetch(`${baseUrl}/bin/${binId}/${renamedId}`, { method: 'MOVE' });
  assert.equal(response.status, 202);
  assert.equal((await response.json()).binId, renamedId);
  assert.equal((await fetch(`${baseUrl}/bin/${renamedId}`)).status, 200);
});

test('ZIP import and export retain nested folder paths and content', async () => {
  const binId = await createBin();
  const archive = await createZip({
    'photos/2026/image.txt': 'image data',
    'docs/readme.md': '# Read me',
  });

  let response = await fetch(`${baseUrl}/zip/${binId}.zip`, { method: 'POST', body: archive });
  assert.equal(response.status, 202);

  response = await fetch(`${baseUrl}/bin/${binId}`);
  const fileIds = await response.json();
  assert.equal(fileIds.length, 2);
  const names = await Promise.all(
    fileIds.map(async (fileId) => (await (await fetch(`${baseUrl}/meta/${binId}/${fileId}`)).json()).name),
  );
  assert.deepEqual(names.sort(), ['docs/readme.md', 'photos/2026/image.txt']);

  response = await fetch(`${baseUrl}/zip/${binId}.zip`);
  assert.equal(response.status, 200);
  assert.match(response.headers.get('content-disposition'), /attachment/);
  const exported = await readZip(Buffer.from(await response.arrayBuffer()));
  assert.deepEqual(exported, {
    'photos/2026/image.txt': 'image data',
    'docs/readme.md': '# Read me',
  });
});

test('lock lifecycle and authorization cover every protected route family', async () => {
  const binId = await createBin();
  const fileId = await createFile(binId, { name: 'secret.txt' });

  let response = await fetch(`${baseUrl}/lock/${binId}`, {
    method: 'PUT',
    body: JSON.stringify({ password: 'short' }),
  });
  assert.equal(response.status, 400);

  response = await fetch(`${baseUrl}/lock/${binId}`, {
    method: 'PUT',
    body: JSON.stringify({ password: 'first password' }),
  });
  assert.equal(response.status, 204);
  let cookie = response.headers.get('set-cookie').split(';')[0];

  response = await fetch(`${baseUrl}/lock/${binId}`);
  assert.deepEqual(await response.json(), { locked: true, unlocked: false });
  response = await fetch(`${baseUrl}/lock/${binId}`, { headers: { cookie } });
  assert.deepEqual(await response.json(), { locked: true, unlocked: true });

  const protectedRequests = [
    [`/bin/${binId}`, { method: 'GET' }],
    [`/bin/${binId}`, { method: 'PATCH', body: JSON.stringify({ newId: 'blocked-rename' }) }],
    [`/bin/${binId}`, { method: 'DELETE' }],
    [`/f/${binId}`, { method: 'POST' }],
    [`/f/${binId}/${fileId}`, { method: 'HEAD' }],
    [`/f/${binId}/${fileId}`, { method: 'GET' }],
    [`/f/${binId}/${fileId}`, { method: 'PUT', body: 'blocked' }],
    [`/f/${binId}/${fileId}`, { method: 'DELETE' }],
    [`/meta/${binId}`, { method: 'GET' }],
    [`/meta/${binId}`, { method: 'PUT', body: '{}' }],
    [`/meta/${binId}/${fileId}`, { method: 'GET' }],
    [`/meta/${binId}/${fileId}`, { method: 'PUT', body: '{}' }],
    [`/zip/${binId}`, { method: 'GET' }],
    [`/zip/${binId}`, { method: 'POST', body: 'blocked' }],
    [`/lock/${binId}`, { method: 'PUT', body: JSON.stringify({ password: 'blocked password' }) }],
    [`/lock/${binId}`, { method: 'DELETE' }],
  ];

  for (const [path, options] of protectedRequests) {
    assert.equal((await fetch(baseUrl + path, options)).status, 401, `${options.method} ${path}`);
  }

  response = await fetch(`${baseUrl}/lock/${binId}`, {
    method: 'PUT',
    headers: { cookie },
    body: JSON.stringify({ password: 'second password' }),
  });
  assert.equal(response.status, 204);
  cookie = response.headers.get('set-cookie').split(';')[0];
  const oldAuthorization = `Basic ${Buffer.from('api:first password').toString('base64')}`;
  const newAuthorization = `Basic ${Buffer.from('api:second password').toString('base64')}`;
  assert.equal((await fetch(`${baseUrl}/bin/${binId}`, { headers: { authorization: oldAuthorization } })).status, 401);
  assert.equal((await fetch(`${baseUrl}/bin/${binId}`, { headers: { authorization: newAuthorization } })).status, 200);

  response = await fetch(`${baseUrl}/lock/${binId}`, { method: 'DELETE', headers: { cookie } });
  assert.equal(response.status, 204);
  assert.match(response.headers.get('set-cookie'), /Max-Age=0/);
  assert.deepEqual(await (await fetch(`${baseUrl}/lock/${binId}`)).json(), { locked: false, unlocked: true });
  assert.equal((await fetch(`${baseUrl}/bin/${binId}`)).status, 200);
});

test('renaming a locked bin moves protection and issues a cookie for the new ID', async () => {
  const binId = await createBin();
  let response = await fetch(`${baseUrl}/lock/${binId}`, {
    method: 'PUT',
    body: JSON.stringify({ password: 'rename password' }),
  });
  const cookie = response.headers.get('set-cookie').split(';')[0];
  const renamedId = `locked-${Date.now()}`;

  response = await fetch(`${baseUrl}/bin/${binId}`, {
    method: 'PATCH',
    headers: { cookie },
    body: JSON.stringify({ newId: renamedId }),
  });
  assert.equal(response.status, 202);
  const renamedCookie = response.headers.get('set-cookie').split(';')[0];
  assert.match(renamedCookie, new RegExp(`filebin_unlock_${renamedId}=`));
  assert.equal((await fetch(`${baseUrl}/bin/${renamedId}`)).status, 401);
  assert.equal((await fetch(`${baseUrl}/bin/${renamedId}`, { headers: { cookie: renamedCookie } })).status, 200);
  assert.deepEqual(await (await fetch(`${baseUrl}/lock/${renamedId}`)).json(), { locked: true, unlocked: false });
});

test('invalid and missing resources return contract status codes', async () => {
  const binId = await createBin();
  assert.equal((await fetch(`${baseUrl}/bin/${binId}`, { method: 'PATCH', body: JSON.stringify({ newId: '../bad' }) })).status, 400);
  assert.equal((await fetch(`${baseUrl}/bin/missing`)).status, 404);
  assert.equal((await fetch(`${baseUrl}/f/missing`, { method: 'POST' })).status, 404);
  assert.equal((await fetch(`${baseUrl}/meta/${binId}/missing`)).status, 404);
  assert.equal((await fetch(`${baseUrl}/zip/missing`)).status, 404);
  assert.equal((await fetch(`${baseUrl}/lock/missing`)).status, 404);
  assert.equal((await fetch(`${baseUrl}/b/missing`)).status, 404);
});

test('OpenAPI JSON endpoint returns JSON', async () => {
  const response = await fetch(`${baseUrl}/api.json?cache-bust=1`);
  assert.equal(response.status, 200);
  assert.match(response.headers.get('content-type'), /application\/json/);
  assert.equal((await response.json()).openapi, '3.0.3');

  const specification = load(await readFile(join(process.cwd(), 'api.yaml'), 'utf8'));
  const operationIds = Object.values(specification.paths).flatMap((path) =>
    Object.values(path).flatMap((operation) => operation?.operationId || []),
  );
  assert.equal(new Set(operationIds).size, operationIds.length);
});

test('UI, module, manifest, icon, and YAML specification are served', async () => {
  const resources = [
    ['/', /Protect bin/],
    ['/index.mjs', /export async function unlockBin/],
    ['/manifest.webmanifest', /"start_url": "\/app"/],
    ['/icon.svg', /<svg/],
    ['/api.yaml', /openapi: 3\.0\.3/],
    ['/api', /openapi: 3\.0\.3/],
  ];

  for (const [path, expected] of resources) {
    const response = await fetch(baseUrl + path);
    assert.equal(response.status, 200, path);
    assert.match(await response.text(), expected);
  }

  const ui = await (await fetch(`${baseUrl}/`)).text();
  assert.match(ui, /"filebin": "\/index\.mjs"/);
  assert.match(ui, /"profile":null/);
  assert.match(ui, /"binList":\[\]/);
  assert.match(ui, /src="\/icon\.svg"/);
  assert.doesNotMatch(ui, /from ['"]\//, 'blob-compiled setup modules cannot resolve root-relative imports');
});

test('help page documents the command-line client', async () => {
  const response = await fetch(`${baseUrl}/help`);
  assert.equal(response.status, 200);
  const page = await response.text();
  assert.match(page, /File Bin guide/);
  assert.match(page, /fbin file upload/);
  assert.match(page, /fbin file upload "\$binId" \.\/video\.mp4 --name/);
  assert.match(page, /Install the CLI before running these commands/);
  assert.match(page, /aria-label="Help"/);

  const landingPage = await (await fetch(`${baseUrl}/`)).text();
  assert.match(landingPage, /class-hidden="!isLanding"/);
  assert.match(landingPage, /A little bin for all your files/);

  const appPage = await (await fetch(`${baseUrl}/app`)).text();
  assert.match(appPage, /Start with a fresh file bin/);
  assert.match(appPage, /on-click="onStartUpload\(\)"/);
});
