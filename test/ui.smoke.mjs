import { test, expect } from '@playwright/test';

test('the app mounts without a startup module error', async ({ page }) => {
  const startupErrors = [];

  page.on('console', (message) => {
    if (
      message.type() === 'error' &&
      /Expected a JavaScript-or-Wasm module script|Failed to fetch dynamically imported module/.test(message.text())
    ) {
      startupErrors.push(message.text());
    }
  });

  page.on('pageerror', (error) => {
    if (/Expected a JavaScript-or-Wasm module script|Failed to fetch dynamically imported module/.test(error.message)) {
      startupErrors.push(error.message);
    }
  });

  await page.goto('/', { waitUntil: 'networkidle' });
  await expect(page.getByRole('button', { name: 'Sign in' }).last()).toBeVisible();

  await page.goto('/app', { waitUntil: 'networkidle' });

  await expect(page.getByRole('link', { name: 'File Bin' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Help' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'New bin' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();
  await expect(page.locator('lucide-icon').first()).toBeAttached();
  await page.getByRole('link', { name: 'Help' }).click();
  await expect(page.getByRole('heading', { name: 'Store files from anywhere.' })).toBeVisible();
  expect(startupErrors).toEqual([]);
});

test('bin actions open the rename dialog', async ({ page }) => {
  const binId = await page.request.post('/bin').then(async (response) => (await response.json()).binId);

  await page.goto(`/app?bin=${binId}`, { waitUntil: 'networkidle' });
  await page.getByRole('button', { name: 'Bin actions' }).click();
  await page.getByRole('button', { name: 'Rename bin' }).click();

  await expect(page.getByRole('heading', { name: 'Rename bin' })).toBeVisible();
  await expect(page.locator('#binactioninput')).toHaveValue(binId);
});

test('image uploads render a thumbnail preview', async ({ page }) => {
  const { binId } = await page.request.post('/bin').then(async (response) => await response.json());
  const { fileId } = await page.request
    .post(`/f/${binId}`, { data: { name: 'sunset.png', type: 'image/png', lastModified: Date.now() } })
    .then(async (response) => await response.json());

  await page.request.put(`/f/${binId}/${fileId}`, { data: 'image fixture' });
  await page.goto(`/app?bin=${binId}`, { waitUntil: 'networkidle' });

  await expect(page.locator('img[alt="sunset.png"]')).toHaveAttribute('src', new RegExp(`/f/${binId}/${fileId}$`));
  await page.getByRole('button', { name: 'File actions' }).click();
  await page.getByRole('button', { name: 'Show details' }).click();
  await expect(page.getByRole('heading', { name: 'sunset.png' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Download' })).toHaveAttribute(
    'href',
    new RegExp(`/f/${binId}/${fileId}$`),
  );
});
