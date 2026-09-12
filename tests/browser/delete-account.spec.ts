import { test, expect } from '@playwright/test';
import { readFileSync, mkdirSync } from 'node:fs';

test('only super admins can delete ordinary admins, with confirmation and session revocation', async ({ page, browser }) => {
  await page.goto('/');
  await page.getByLabel('관리자 계정', { exact: true }).fill('admin');
  await page.getByLabel('비밀번호', { exact: true }).fill(readFileSync(process.env.TEST_PASSWORD_FILE || '/run/test-password', 'utf8').trim());
  await page.getByRole('button', { name: '대시보드 로그인' }).click();
  await expect(page.getByRole('heading', { name: '전체 현황', exact: true })).toBeVisible();
  const me = await (await page.request.get('/api/me')).json();
  const origin = new URL(page.url()).origin;
  const name = 'remove-fixture-' + Date.now();
  const password = 'remove-fixture-password';
  expect((await page.request.post('/api/admins', { headers: { 'X-CSRF-Token': me.csrf, Origin: origin }, data: { username: name, password } })).status()).toBe(201);
  const operator = await browser.newContext({ baseURL: origin });
  try {
    const op = await operator.newPage();
    await op.goto('/');
    await op.getByLabel('관리자 계정', { exact: true }).fill(name);
    await op.getByLabel('비밀번호', { exact: true }).fill(password);
    await op.getByRole('button', { name: '대시보드 로그인' }).click();
    await op.getByRole('button', { name: '관리자 계정', exact: true }).click();
    await expect(op.getByRole('heading', { name: '내 계정', exact: true })).toBeVisible();
    await expect(op.getByRole('button', { name: /계정 삭제/ })).toHaveCount(0);
    const opMe = await (await op.request.get('/api/me')).json();
    expect((await op.request.delete('/api/admins/' + name, { headers: { 'X-CSRF-Token': opMe.csrf, Origin: origin } })).status()).toBe(403);
    await page.getByRole('button', { name: '관리자 계정', exact: true }).click();
    await expect(page.getByRole('button', { name: 'admin 계정 삭제', exact: true })).toBeDisabled();
    const remove = page.getByRole('button', { name: name + ' 계정 삭제', exact: true });
    await remove.click();
    const dialog = page.getByRole('dialog', { name: '관리자 계정 삭제', exact: true });
    await expect(dialog).toContainText(name);
    await expect(dialog.getByRole('button', { name: '취소', exact: true })).toBeFocused();
    await page.keyboard.press('Escape');
    await expect(remove).toBeFocused();
    expect((await op.request.get('/api/me')).status()).toBe(200);
    await page.setViewportSize({ width: 375, height: 812 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await remove.click();
    mkdirSync('/tmp/sshlogger-account-results', { recursive: true });
    await page.screenshot({ path: '/tmp/sshlogger-account-results/delete-mobile.png', animations: 'disabled' });
    await dialog.getByRole('button', { name: '계정 삭제', exact: true }).click();
    await expect(dialog).toHaveCount(0);
    await expect(remove).toHaveCount(0);
    await expect(page.getByRole('status')).toContainText(name + ' 관리자 계정을 삭제했습니다.');
    await expect(page.getByRole('button', { name: '관리자 추가', exact: true })).toBeFocused();
    expect((await op.request.get('/api/me')).status()).toBe(401);
    await op.reload();
    await expect(op.getByRole('button', { name: '대시보드 로그인' })).toBeVisible();
    await page.reload();
    await page.getByRole('button', { name: '관리자 계정', exact: true }).click();
    await expect(page.getByRole('heading', { name: '등록된 관리자' })).toBeVisible();
    await expect(remove).toHaveCount(0);
  } finally {
    await operator.close();
  }
});
