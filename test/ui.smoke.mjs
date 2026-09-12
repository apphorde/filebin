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

test('bin actions open and rename the active bin', async ({ page }) => {
  const binId = await page.request.post('/bin').then(async (response) => (await response.json()).binId);
  const renamedBinId = `renamed-${Date.now()}`;

  await page.goto(`/app?bin=${binId}`, { waitUntil: 'networkidle' });
  await page.getByRole('button', { name: 'Bin actions' }).click();
  await page.getByRole('button', { name: 'Rename bin' }).click();
  await page.locator('#binactioninput').fill(renamedBinId);
  await page.getByRole('button', { name: 'Rename', exact: true }).click();

  await expect(page).toHaveURL(new RegExp(`\\?bin=${renamedBinId}$`));
  await expect(page.getByRole('heading', { name: renamedBinId })).toBeVisible();
});
