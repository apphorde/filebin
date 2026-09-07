#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { open, stat } from 'node:fs/promises';
import { basename } from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { parseArgs } from 'node:util';

const usage = `
Usage: fbin [--server URL] [--password PASSWORD] <command>

Bins:
  fbin bin create
  fbin bin list <bin-id>
  fbin bin rename <bin-id> <new-id>
  fbin bin delete <bin-id>

Files:
  fbin file list <bin-id>
  fbin file info <bin-id> <file-id>
  fbin file download <bin-id> <file-id> ./file
  fbin file delete <bin-id> <file-id>

Archives:
  fbin zip upload <bin-id> ./archive.zip
  fbin zip download <bin-id> ./archive.zip

Protection:
  fbin lock status <bin-id>
  fbin lock set <bin-id>
  fbin lock remove <bin-id>

Environment: 
  FILEBIN_URL        Server URL, e.g. https://bin.example.com
  FILEBIN_PASSWORD   Password to use with protected bins. env keeps password out of shell history

Upload options: 
  --part-size BYTES (default: 8388608), --concurrency COUNT (default: 3)
`;

function fail(message) {
  console.error(message);
  process.exitCode = 1;
}

function parseArguments(args) {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: {
      server: { type: 'string' },
      password: { type: 'string' },
      name: { type: 'string' },
      'file-id': { type: 'string' },
      'part-size': { type: 'string' },
      concurrency: { type: 'string' },
      help: { type: 'boolean' },
    },
  });
  const options = {
    server: values.server || process.env.FILEBIN_URL,
    password: values.password || process.env.FILEBIN_PASSWORD,
    name: values.name,
    fileId: values['file-id'],
    partSize: Number(values['part-size'] || 8 * 1024 * 1024),
    concurrency: Number(values.concurrency || 3),
  };
  if (!Number.isSafeInteger(options.partSize) || options.partSize < 1 || !Number.isSafeInteger(options.concurrency) || options.concurrency < 1) {
    throw new Error('--part-size and --concurrency must be positive integers');
  }
  return { options, positional: values.help ? ['help'] : positionals };
}

function createClient(options) {
  if (!options.server) throw new Error('Provide --server URL or FILEBIN_URL');
  const server = new URL(options.server);
  const authorization = options.password ? `Basic ${Buffer.from(`api:${options.password}`).toString('base64')}` : undefined;

  return async function request(path, init = {}) {
    const headers = new Headers(init.headers);
    if (authorization) headers.set('authorization', authorization);
    const response = await fetch(new URL(path, server), { ...init, headers });
    if (!response.ok) throw new Error(`${init.method || 'GET'} ${path}: ${response.status} ${await response.text()}`);
    return response;
  };
}

async function json(request, path, init) {
  const response = await request(path, init);
  if (response.status === 204) return null;
  const body = await response.text();
  try {
    return JSON.parse(body);
  } catch {
    return body;
  }
}

function missingRanges(ranges, total, partSize) {
  const missing = [];
  let cursor = 0;
  for (const range of [...ranges].sort((a, b) => a.start - b.start)) {
    for (; cursor < range.start; cursor += partSize) missing.push({ start: cursor, end: Math.min(cursor + partSize - 1, range.start - 1) });
    cursor = Math.max(cursor, range.end + 1);
  }
  for (; cursor < total; cursor += partSize) missing.push({ start: cursor, end: Math.min(cursor + partSize - 1, total - 1) });
  return missing;
}

async function upload(request, binId, path, options) {
  const file = await stat(path);
  let fileId = options.fileId;
  if (!fileId) {
    const metadata = { name: options.name || basename(path) };
    fileId = (await json(request, `/f/${binId}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(metadata) })).fileId;
    console.error(`Created upload session ${fileId}`);
  }

  if (file.size === 0) {
    const response = await json(request, `/f/${binId}/${fileId}`, { method: 'PUT', body: Buffer.alloc(0) });
    console.log(JSON.stringify(response));
    return;
  }

  const status = await json(request, `/f/${binId}/${fileId}/upload`);
  if (status.total !== null && status.total !== file.size) throw new Error(`Upload ${fileId} expects ${status.total} bytes, but ${path} has ${file.size}`);
  const ranges = missingRanges(status.ranges, file.size, options.partSize);
  const handle = await open(path, 'r');
  let result;
  let next = 0;
  const worker = async () => {
    while (next < ranges.length) {
      const range = ranges[next++];
      const body = Buffer.alloc(range.end - range.start + 1);
      await handle.read(body, 0, body.length, range.start);
      const digest = createHash('sha256').update(body).digest('base64');
      const response = await json(request, `/f/${binId}/${fileId}`, {
        method: 'PUT',
        headers: { 'content-range': `bytes ${range.start}-${range.end}/${file.size}`, digest: `sha-256=${digest}` },
        body,
      });
      if (response.url) result = response;
    }
  };
  try {
    await Promise.all(Array.from({ length: Math.min(options.concurrency, ranges.length) }, worker));
  } finally {
    await handle.close();
  }
  console.log(JSON.stringify(result || { id: fileId, bin: binId, complete: false }));
}

async function download(request, remotePath, localPath) {
  const response = await request(remotePath);
  await pipeline(Readable.fromWeb(response.body), createWriteStream(localPath));
}

async function main() {
  const { options, positional } = parseArguments(process.argv.slice(2));
  const [resource, command, ...args] = positional;
  if (!resource || resource === 'help') return console.log(usage);
  const request = createClient(options);

  if (resource === 'bin') {
    if (command === 'create') return console.log(JSON.stringify(await json(request, '/bin', { method: 'POST' })));
    if (command === 'list') return console.log(JSON.stringify(await json(request, `/bin/${args[0]}`)));
    if (command === 'rename') return console.log(JSON.stringify(await json(request, `/bin/${args[0]}`, { method: 'PATCH', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ newId: args[1] }) })));
    if (command === 'delete') return json(request, `/bin/${args[0]}`, { method: 'DELETE' });
  }
  if (resource === 'file') {
    if (command === 'list') {
      const ids = await json(request, `/bin/${args[0]}`);
      return console.log(JSON.stringify(await Promise.all(ids.map((id) => json(request, `/meta/${args[0]}/${id}`)))));
    }
    if (command === 'info') return console.log(JSON.stringify(await json(request, `/meta/${args[0]}/${args[1]}`)));
    if (command === 'upload') return upload(request, args[0], args[1], options);
    if (command === 'download') return download(request, `/f/${args[0]}/${args[1]}`, args[2]);
    if (command === 'delete') return json(request, `/f/${args[0]}/${args[1]}`, { method: 'DELETE' });
  }
  if (resource === 'zip' && command === 'upload') return console.log(JSON.stringify(await json(request, `/zip/${args[0]}`, { method: 'POST', body: createReadStream(args[1]), duplex: 'half' })));
  if (resource === 'zip' && command === 'download') return download(request, `/zip/${args[0]}`, args[1]);
  if (resource === 'lock') {
    if (command === 'status') return console.log(JSON.stringify(await json(request, `/lock/${args[0]}`)));
    if (command === 'set') return json(request, `/lock/${args[0]}`, { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ password: options.password }) });
    if (command === 'remove') return json(request, `/lock/${args[0]}`, { method: 'DELETE' });
  }
  throw new Error(usage);
}

main().catch((error) => fail(error.message));
