import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { load } from 'js-yaml';
import * as yauzl from 'yauzl';
import * as yazl from 'yazl';

const rootDir = await mkdtemp(join(tmpdir(), 'filebin-'));
process.env.ROOT_DIR = rootDir;
const { start } = await import('../dist/index.js');
const server = start({ port: 0 });
await new Promise((resolve) => server.once('listening', resolve));
const baseUrl = `http://127.0.0.1:${server.address().port}`;

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
  const response = await fetch(`${baseUrl}/api.json`);
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
    ['/manifest.webmanifest', /FileBin/],
    ['/icon.svg', /<svg/],
    ['/api.yaml', /openapi: 3\.0\.3/],
    ['/api', /openapi: 3\.0\.3/],
  ];

  for (const [path, expected] of resources) {
    const response = await fetch(baseUrl + path);
    assert.equal(response.status, 200, path);
    assert.match(await response.text(), expected);
  }
});
