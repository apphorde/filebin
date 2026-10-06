#!/usr/bin/env node

const DATABASE_URL = process.env.DATABASE_URL;
const S3_API_URL = (process.env.S3_API_URL || 'https://s3.api.apphor.de').replace(/\/+$/, '');
const S3_ADMIN_TOKEN = process.env.S3_ADMIN_TOKEN;

async function loadDatabase() {
  if (!DATABASE_URL) throw new Error('DATABASE_URL is required');
  const response = await fetch(DATABASE_URL);
  if (!response.ok) throw new Error(`Database module request failed: ${response.status}`);
  const source = await response.text();
  return import(`data:text/javascript,${encodeURIComponent(source)}`);
}

function validateBucketName(name) {
  return (
    typeof name === 'string' &&
    name.length >= 3 &&
    name.length <= 63 &&
    /^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(name) &&
    !name.includes('..') &&
    !/^\d+\.\d+\.\d+\.\d+$/.test(name)
  );
}

async function snapshotBins(database) {
  const bins = await database.all('SELECT id, name, visibility, owner_subject FROM storage_bins ORDER BY id');
  const files = await database.all(
    'SELECT bin_id, COUNT(*) AS count, COALESCE(SUM(size), 0) AS bytes FROM storage_files GROUP BY bin_id',
  );
  const counts = new Map(files.map((row) => [row.bin_id, row]));
  return bins.map((bin) => ({
    ...bin,
    fileCount: Number(counts.get(bin.id)?.count || 0),
    bytes: Number(counts.get(bin.id)?.bytes || 0),
  }));
}

async function adminRequest(path, init = {}) {
  if (!S3_ADMIN_TOKEN) throw new Error('S3_ADMIN_TOKEN is required for S3 bucket operations');
  const response = await fetch(`${S3_API_URL}${path}`, {
    ...init,
    headers: {
      authorization: `Bearer ${S3_ADMIN_TOKEN}`,
      ...(init.body ? { 'content-type': 'application/json' } : {}),
      ...init.headers,
    },
  });
  if (!response.ok) throw new Error(`S3 API ${init.method || 'GET'} ${path} failed (${response.status})`);
  return response.status === 204 ? null : response.json();
}

async function inspect(database) {
  const bins = await snapshotBins(database);
  const uploads = await database.get('SELECT COUNT(*) AS count FROM storage_uploads');
  const summary = {
    bins: bins.length,
    ownedBins: bins.filter((bin) => bin.owner_subject).length,
    unownedBins: bins.filter((bin) => !bin.owner_subject).length,
    nonPrivateBins: bins.filter((bin) => bin.visibility !== 'private').length,
    files: bins.reduce((total, bin) => total + bin.fileCount, 0),
    bytes: bins.reduce((total, bin) => total + bin.bytes, 0),
    incompleteUploads: Number(uploads?.count || 0),
    invalidBucketNames: bins.filter((bin) => !validateBucketName(bin.id)).map((bin) => bin.id),
    binsWithoutFiles: bins.filter((bin) => bin.fileCount === 0).map((bin) => bin.id),
  };
  console.log(JSON.stringify(summary, null, 2));
}

async function provisionEmptyBuckets(database, apply) {
  const bins = await snapshotBins(database);
  const invalid = bins.filter((bin) => !validateBucketName(bin.id));
  if (invalid.length) throw new Error(`${invalid.length} bin IDs are not valid S3 bucket names`);

  const existing = new Set((await adminRequest('/admin/buckets')).map((bucket) => bucket.name));
  const missing = bins.filter((bin) => !existing.has(bin.id));
  if (!apply) {
    console.log(JSON.stringify({ mode: 'dry-run', total: bins.length, existing: bins.length - missing.length, toCreate: missing.map((bin) => bin.id) }, null, 2));
    return;
  }

  let created = 0;
  for (const bin of missing) {
    await adminRequest('/admin/buckets', {
      method: 'POST',
      body: JSON.stringify({ name: bin.id }),
    });
    created++;
  }
  console.log(JSON.stringify({ mode: 'apply', total: bins.length, created, alreadyPresent: bins.length - missing.length }));
}

async function verifyBuckets(database) {
  const bins = await snapshotBins(database);
  const existing = new Set((await adminRequest('/admin/buckets')).map((bucket) => bucket.name));
  const missing = bins.filter((bin) => !existing.has(bin.id)).map((bin) => bin.id);
  console.log(JSON.stringify({ bins: bins.length, matchingBuckets: bins.length - missing.length, missing }, null, 2));
  if (missing.length) process.exitCode = 1;
}

async function main() {
  const [command = 'help', ...flags] = process.argv.slice(2);
  if (command === 'help' || command === '--help') {
    console.log(`
FileBin snapshot/S3 preparation (does not copy or delete file objects)

Usage:
  node bin/migrate.mjs inspect
  node bin/migrate.mjs buckets [--apply]
  node bin/migrate.mjs verify-buckets

Environment:
  DATABASE_URL   Read-only snapshot database module URL
  S3_API_URL     S3MINI API URL (default: https://s3.api.apphor.de)
  S3_ADMIN_TOKEN S3MINI admin/operator bearer token for bucket APIs

"buckets" is a dry run unless --apply is specified. Bucket names are the bin IDs.
The database is only queried; this tool never inserts or updates database records.
`);
    return;
  }

  const database = await loadDatabase();
  if (command === 'inspect') return inspect(database);
  if (command === 'buckets') return provisionEmptyBuckets(database, flags.includes('--apply'));
  if (command === 'verify-buckets') return verifyBuckets(database);
  throw new Error(`Unknown command: ${command}`);
}

main().catch((error) => {
  console.error(`Migration preparation failed: ${error.message}`);
  process.exitCode = 1;
});
