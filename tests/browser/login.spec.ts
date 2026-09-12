import { test, expect } from '@playwright/test';
import { mkdirSync, readFileSync } from 'node:fs';

test('login supports password visibility, pending and error recovery, keyboard and small screens', async ({ page }) => {
  const screenshots = '/tmp/sshlogger-login-results';
  mkdirSync(screenshots, { recursive: true });
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto('/');
  const username = page.getByLabel('관리자 계정', { exact: true });
  const password = page.getByLabel('비밀번호', { exact: true });
  await expect(username).toHaveValue('');
  const card = await page.locator('.login-card').boundingBox();
  expect(Math.abs(card!.x + card!.width / 2 - 720)).toBeLessThan(1);
  await page.screenshot({ path: screenshots + '/login-desktop.png', fullPage: true });
  for (const size of [{ width: 375, height: 812 }, { width: 812, height: 375 }]) {
    await page.setViewportSize(size);
    await page.emulateMedia({ reducedMotion: 'reduce' });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.screenshot({ path: screenshots + `/login-${size.width}.png`, fullPage: true });
  }
  await page.setViewportSize({ width: 375, height: 812 });
  await page.evaluate(() => { document.documentElement.style.fontSize = '28px'; });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await expect(page.getByRole('button', { name: '대시보드 로그인' })).toBeVisible();
  await page.evaluate(() => { document.documentElement.style.fontSize = ''; });
  await username.focus();
  await username.fill('admin');
  await page.keyboard.press('Tab');
  await expect(password).toBeFocused();
  await password.fill('incorrect-password');
  await page.keyboard.press('Tab');
  const toggle = page.getByRole('button', { name: '비밀번호 표시', exact: true });
  await expect(toggle).toBeFocused();
  await page.keyboard.press('Space');
  await expect(password).toHaveAttribute('type', 'text');
  await page.keyboard.press('Space');
  await expect(password).toHaveAttribute('type', 'password');

  let release!: () => void;
  const pending = new Promise<void>(resolve => { release = resolve; });
  await page.route('**/api/login', async route => {
    await pending;
    await route.fulfill({ status: 401, json: { error: '계정 또는 비밀번호를 확인하세요.' } });
  });
  await password.press('Enter');
  await expect(page.getByRole('button', { name: '로그인 중…', exact: true })).toBeDisabled();
  await expect(username).toBeDisabled();
  await expect(toggle).toBeDisabled();
  release();
  const error = page.getByRole('alert');
  await expect(error).toContainText('계정 또는 비밀번호를 확인하세요.');
  await expect(error).toBeFocused();
  await expect(username).toHaveValue('admin');
  await page.screenshot({ path: screenshots + '/login-error.png', fullPage: true });
  await page.unroute('**/api/login');
  await password.fill(readFileSync(process.env.TEST_PASSWORD_FILE || '/run/test-password', 'utf8').trim());
  await password.press('Enter');
  await expect(page.getByRole('heading', { name: '전체 현황', exact: true })).toBeVisible();
  await page.getByRole('button', { name: '로그아웃' }).click();
  await expect(password).toHaveValue('');
  await expect(password).toHaveAttribute('type', 'password');
  expect(errors).toEqual([]);
});
