const API_URL = '__API_HOST__';

const u = (s) => new URL(s, API_URL);
const h = { method: 'HEAD', mode: 'cors' };
const g = { method: 'GET', mode: 'cors' };
const p = { method: 'POST', mode: 'cors' };
const d = { method: 'DELETE', mode: 'cors' };

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
  const req = await fetch(u(`/bin/${bin}/${newId}`), { method: 'MOVE', mode: 'cors' });

  return req.ok || Promise.reject(new Error('Failed to rename bin'));
}

/**
 * @param {string} bin
 * @returns {Promise<string[]>} file ids
 */
export async function listFiles(bin) {
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
export async function createFile(bin) {
  const req = await fetch(u(`/f/${bin}`), p);

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
  const req = await fetch(u(`/meta/${bin}/${file}`), g);
  return req.ok ? await req.json() : Promise.reject(new Error('Failed to fetch file metadata'));
}
