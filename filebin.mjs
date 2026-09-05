const API_URL = '__API_HOST__';

const u = (s) => new URL(s, API_URL);
const h = { method: 'HEAD', mode: 'cors', credentials: 'include' };
const g = { method: 'GET', mode: 'cors', credentials: 'include' };
const p = { method: 'POST', mode: 'cors', credentials: 'include' };
const d = { method: 'DELETE', mode: 'cors', credentials: 'include' };

/**
 * @returns {Promise<{ binId: string }>}
 */
export async function createBin() {
  const req = await fetch(u('/bin'), p);

  return req.ok ? await req.json() : Promise.reject(new Error('Failed to create bin'));
}

/**
 * @param {string} bin
 * @returns {Promise<boolean>} OK
 */
export async function removeBin(bin) {
  const req = await fetch(u(`/bin/${bin}`), d);

  return req.ok || Promise.reject(new Error('Failed to remove bin'));
}

/**
 * @param {string} bin
 * @param {string} newId
 * @returns {Promise<boolean>} OK
 */
export async function renameBin(bin, newId) {
  if (!bin || !newId) {
    return Promise.reject(new Error('Invalid bin id'));
  }

  const req = await fetch(u(`/bin/${bin}`), {
    method: 'PATCH',
    mode: 'cors',
    credentials: 'include',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ newId }),
  });

  return req.ok || Promise.reject(new Error('Failed to rename bin'));
}

/**
 * @param {string} bin
 * @returns {Promise<string[]>} file ids
 */
export async function listFiles(bin) {
  if (!bin) {
    return Promise.reject(new Error('Invalid bin id'));
  }

  const req = await fetch(u(`/bin/${bin}`), g);
  return req.ok ? await req.json() : Promise.reject(new Error('Failed to fetch files in this bin'));
}

/**
 * @param {string} bin
 * @returns {Promise<ArrayBuffer>} zip file
 */
export async function downloadZip(bin) {
  const req = await fetch(getZipUrl(bin), g);

  return req.ok ? await req : Promise.reject(new Error('Failed to generate a zip for this bin'));
}

/**
 * @param {string} bin
 * @param {BodyInit} zipContent
 * @returns {Promise<ArrayBuffer>} zip file
 */
export async function uploadZip(bin, zipContent) {
  const req = await fetch(getZipUrl(bin), { ...p, body: zipContent });

  return req.ok ? await req.json() : Promise.reject(new Error('Failed to import a zip in this bin'));
}

/**
 * Returns an URL pointing to a zip with the entire bin
 * @param {string} bin
 * @returns {string} url
 */
export function getZipUrl(bin) {
  return u(`/zip/${bin}.zip`).toString();
}

/**
 * @param {string} bin
 * @returns {Promise<{ fileId: string }>}
 */
export async function createFile(bin, metadata) {
  const req = await fetch(u(`/f/${bin}`), {
    ...p,
    body: metadata ? JSON.stringify(metadata) : undefined,
  });

  return req.ok ? await req.json() : Promise.reject(new Error('Failed to create file'));
}

/**
 * @param {string} bin
 * @param {string} file
 * @returns {Promise<boolean>} OK
 */
export async function removeFile(bin, file) {
  const req = await fetch(u(`/f/${bin}/${file}`), d);

  return req.ok || Promise.reject(new Error('Failed to remove file'));
}

/**
 * @param {string} bin
 * @param {string} file
 * @returns {Promise<Response>} OK
 */
export async function readFile(bin, file) {
  const req = await fetch(u(`/f/${bin}/${file}`), g);

  return req.ok ? req : Promise.reject(new Error('Failed to retrieve this file'));
}

/**
 * @param {string} bin
 * @param {string} file
 * @returns {Promise<Response>} OK
 */
export async function fileExists(bin, file) {
  const req = await fetch(u(`/f/${bin}/${file}`), h);

  return req.ok && req.status === 200;
}

/**
 * @param {string} bin
 * @param {string} file
 * @param {BodyInit} content
 * @returns {Promise<{ binId: string, fileId: string, url: string }>}
 */
export async function writeFile(bin, file, content) {
  const req = await fetch(u(`/f/${bin}/${file}`), {
    method: 'PUT',
    mode: 'cors',
    body: content,
  });
  return req.ok ? await req.json() : Promise.reject(new Error('Failed to update file'));
}

/**
 * @param {string} bin
 * @param {string} file
 * @param {Object} metadata
 * @returns {Promise<boolean>}
 */
export async function writeMetadata(bin, file, content) {
  const req = await fetch(u('/' + ['meta', bin, file].filter(Boolean).join('/')), {
    method: 'PUT',
    mode: 'cors',
    body: JSON.stringify(content),
  });
  return req.ok || Promise.reject(new Error('Failed to update metadata'));
}

/**
 * @param {string} bin
 * @param {string} file
 * @returns {Promise<Object>}
 */
export async function readMetadata(bin, file) {
  const req = await fetch(u('/' + ['meta', bin, file].filter(Boolean).join('/')), g);
  return req.ok ? await req.json() : Promise.reject(new Error('Failed to fetch file metadata'));
}

export async function getBinLock(bin) {
  const req = await fetch(u(`/lock/${bin}`), g);
  return req.ok ? await req.json() : Promise.reject(new Error('Failed to read bin protection status'));
}

export async function unlockBin(bin, password) {
  const req = await fetch(u(`/lock/${bin}`), {
    ...p,
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ password }),
  });
  return req.ok || Promise.reject(new Error('Incorrect password'));
}

export async function setBinPassword(bin, password) {
  const req = await fetch(u(`/lock/${bin}`), {
    method: 'PUT',
    mode: 'cors',
    credentials: 'include',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ password }),
  });
  return req.ok || Promise.reject(new Error(await req.text() || 'Failed to protect bin'));
}

export async function removeBinPassword(bin) {
  const req = await fetch(u(`/lock/${bin}`), d);
  return req.ok || Promise.reject(new Error('Failed to remove bin protection'));
}
