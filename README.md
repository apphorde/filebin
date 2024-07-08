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

start({ rootDir: process.cwd() + '/data', port: 1234 });
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

const { binId, fileID, url } = await save('hello');
const content = await readFile(binId, fileId);
// or directly
const hello = await (await fetch(url)).text();
```

## Environment variables

| env      | description                                       |
| -------- | ------------------------------------------------- |
| ROOT_DIR | String. Path to a folder where all data is stored |
| PORT     | Number. HTTP port                                 |
