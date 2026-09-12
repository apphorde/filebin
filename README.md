# File storage service

A file bin service for all your quick and easy storage needs.

## API

See `api.yaml` for API specification.

## Usage

### With docker

```sh
docker pull ghcr.io/cloud-cli/storage:latest
docker run --rm -e ROOT_DIR=/opt/data -e PORT=1234 -v$PWD/data:/opt/data ghcr.io/cloud-cli/storage:latest
```

See also [the release page](https://github.com/cloud-cli/storage/pkgs/container/storage).

### As a standalone server with Node.JS

```ts
import start from '@cloud-cli/storage';

process.env.ROOT_DIR = process.cwd() + '/data';
start({ port: 1234 });
```

### As an ESM Module

Consuming it as an ESM module: if the server is running at `https://bin.example.com`, import it as a module in a project:

```ts
import { createBin, createFile, writeFile, readFile } from 'https://bin.example.com/index.mjs';

async function save(content) {
  const { binId } = await createBin();
  const { fileId } = await createFile(binId);

  return await writeFile(binId, fileId, content);
}

const { bin: binId, id: fileId, url } = await save('hello');
const content = await readFile(binId, fileId);
// or directly
const hello = await (await fetch(url)).text();
```

File metadata names may use slash-separated relative paths (for example,
`photos/2026/image.jpg`). Folder paths are retained when importing or exporting
ZIP archives. The web UI also supports selecting and uploading a directory.
Bins keep UUID identifiers for URLs and API operations, while the web UI assigns
each bin a generated display name that can be renamed without changing its URL.

### Public and private bins

Bins created without signing in are public, temporary bins. They are not
claimable and are deleted after a period without completed uploads. The timer is
reset only when a file upload completes, not when a bin is read or modified.
Public bins are limited to 5 MiB per file and 50 completed files.

Sign in before creating a bin to create a private bin. Private bins are owned
by the authenticated user and are the basis for future sharing permissions and
storage plans. Owned bins can be switched between public and private from the
web app. An unclaimed public bin cannot be converted to private, which avoids
granting ownership based only on knowledge of a bin ID.

At startup, FileBin imports existing disk bins, committed files, metadata, system
metadata, and incomplete upload state into the configured SQLite catalog.
Imported bins remain public and unclaimed by default because disk state cannot
prove an OIDC owner. New authenticated bins are recorded as owned at creation
time. Ownership is stored in the `storage_bins` catalog.

Schedule `POST /admin/cleanup` nightly with
`Authorization: Bearer $PUBLIC_BIN_CLEANUP_TOKEN` to remove expired public
unclaimed bins. The endpoint returns the deleted bin IDs.

Deleting a bin is a soft delete. `DELETE /bin/{binId}` marks it for removal
after `BIN_DELETION_GRACE_HOURS` (168 by default); the cleanup scheduler then
permanently removes its files and catalog records. The authenticated owner can
cancel the deletion with `POST /bin/{binId}/restore` during that grace period.

### Large, resumable uploads

`createFile()` returns an incomplete upload session. For ordinary uploads, use
`writeFile()` as above. API clients can upload non-overlapping byte ranges in
parallel with `writeFilePart(binId, fileId, part, start, total)`. Each part is
verified with SHA-256 and is durably recorded; use `readUploadStatus()` to list
received ranges after an interruption, then submit only the missing ranges.
The file is not available for download or listing until all bytes from `0` to
`total - 1` have been received. See `api.yaml` for the `Content-Range` and
`Digest` request header contract.

Upload sessions are cleaned up after 72 hours by default. Set
`UPLOAD_RETENTION_HOURS` to change the retention period and
`UPLOAD_CLEANUP_INTERVAL_MINUTES` to change the cleanup interval.

For backup objects, create the file with `{ immutable: true }` metadata. The
object remains writable while incomplete, then becomes immutable after commit;
replacement and deletion return `409`. Completed files expose a lowercase
SHA-256 checksum in metadata and as a quoted `ETag`.

File downloads support single-byte HTTP ranges. Clients can send
`Range: bytes=<offset>-` with `If-Range: <ETag>` and receive `206 Partial
Content`. The `fbin file download` command automatically resumes an existing
partial local file when the remote ETag is available.

### Command-line client

Install the package globally or run `node bin/fbin.mjs`. Set `FILEBIN_URL`
once, then use JSON-producing commands that map directly to the API:

```sh
export FILEBIN_URL=https://bin.example.com
fbin bin create
fbin file upload <bin-id> ./video.mp4 --concurrency 3
fbin file list <bin-id>
fbin file download <bin-id> <file-id> ./video.mp4
fbin zip download <bin-id> ./archive.zip
```

`fbin file upload` creates an upload session and prints its ID to stderr.
If interrupted, repeat the command with `--file-id <id>` and the same source
file; the CLI queries received ranges and uploads only missing parts. Use
`--part-size` to control chunk size (8 MiB by default).

Bin management is available through `fbin bin list`, `rename`, and
`delete`; file management through `file list`, `info`, and `delete`; and
protection through `fbin lock status`, `set`, and `remove`. Pass a password
with `--password` or `FILEBIN_PASSWORD`; the CLI uses HTTP Basic authentication
for protected operations. Prefer `FILEBIN_PASSWORD` to avoid recording a
password in shell history.

### Password-protected bins

Protection is opt-in from the bin UI. Locked bins reject all bin, file,
metadata, and ZIP operations until unlocked. Browser unlocks use an HttpOnly
cookie valid for 12 hours. API clients can instead use HTTP Basic auth with any
username and the bin password:

```js
await fetch(`${server}/bin/${binId}`, {
  headers: { authorization: `Basic ${btoa(`api:${password}`)}` },
});
```

Passwords are stored as salted scrypt hashes. A bin ID remains the management
capability, so protect a bin immediately after creating it when this matters.

## Environment variables

| env                        | description                                                                   |
| -------------------------- | ----------------------------------------------------------------------------- |
| ROOT_DIR                   | String. Path to a folder where all data is stored                             |
| PORT                       | Number. HTTP port                                                             |
| AUTH_PROVIDER              | Required OIDC provider URL                                                    |
| OIDC_CLIENT_ID             | Required OIDC client ID                                                       |
| OIDC_CLIENT_SECRET         | OIDC client secret used at `/auth/callback`                                   |
| DATABASE_URL               | Private SQLite-over-HTTPS ESM module URL                                      |
| SESSION_SECRET             | Shared secret for signing session cookies                                     |
| PUBLIC_BIN_RETENTION_HOURS | Public-bin inactivity period after the last completed upload, defaults to 168 |
| PUBLIC_BIN_CLEANUP_TOKEN   | Bearer token accepted by the external cleanup scheduler endpoint              |
