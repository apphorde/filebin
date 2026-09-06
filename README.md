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

### Large, resumable uploads

`createFile()` returns an incomplete upload session. For ordinary uploads, use
`writeFile()` as above. API clients can upload non-overlapping byte ranges in
parallel with `writeFilePart(binId, fileId, part, start, total)`. Each part is
verified with SHA-256 and is durably recorded; use `readUploadStatus()` to list
received ranges after an interruption, then submit only the missing ranges.
The file is not available for download or listing until all bytes from `0` to
`total - 1` have been received. See `api.yaml` for the `Content-Range` and
`Digest` request header contract.

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

| env      | description                                       |
| -------- | ------------------------------------------------- |
| ROOT_DIR | String. Path to a folder where all data is stored |
| PORT     | Number. HTTP port                                 |
