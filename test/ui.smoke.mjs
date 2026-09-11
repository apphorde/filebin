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
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();

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
