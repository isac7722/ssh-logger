import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';

test('regular admins register and manage only assigned servers', async ({ page }) => {
  const password = readFileSync(process.env.TEST_PASSWORD_FILE || '/run/test-password', 'utf8').trim();
  const login = async (username: string, secret: string) => {
    await page.goto('/');
    await page.getByLabel('관리자 계정', { exact: true }).fill(username);
    await page.getByLabel('비밀번호', { exact: true }).fill(secret);
    await page.getByRole('button', { name: '대시보드 로그인' }).click();
    await page.getByRole('heading', { name: '전체 현황', exact: true }).waitFor();
  };
  await login('admin', password);
  const me = await (await page.request.get('/api/me')).json();
  const headers = { 'X-CSRF-Token': me.csrf, Origin: 'http://localhost:18080' };
  const suffix = Date.now();
  const username = 'server-operator-' + suffix;
  expect((await page.request.post('/api/admins', { headers, data: { username, password: 'operator-password-123' } })).status()).toBe(201);
  const hidden = 'hidden-' + suffix;
  expect((await page.request.post('/api/servers', { headers, data: { name: hidden } })).status()).toBe(201);
  await page.request.post('/api/logout', { headers });
  await login(username, 'operator-password-123');
  await page.getByRole('button', { name: '서버 관리', exact: true }).click();
  await expect(page.getByRole('button', { name: '보관 설정', exact: true })).toHaveCount(0);
  await expect(page.getByText(hidden, { exact: true })).toHaveCount(0);
  await expect(page.getByText('등록 시점의 모든 일반 관리자에게 이 서버가 자동 배정됩니다.')).toBeVisible();
  const name = 'operator-host-' + suffix;
  await page.getByLabel('서버 이름', { exact: true }).fill(name);
  await page.getByRole('button', { name: '서버 등록', exact: true }).click();
  await expect(page.getByLabel('발급 토큰')).not.toHaveValue('');
  const token = await page.getByLabel('발급 토큰').inputValue();
  // A normal refresh must retain the operator's issued token and management view.
  await page.waitForResponse(response => response.url().endsWith('/api/me') && response.ok(), { timeout: 10000 });
  await expect(page.getByLabel('발급 토큰')).toHaveValue(token);
  let row = page.getByRole('row').filter({ hasText: name });
  await row.getByRole('button', { name: '정보 수정', exact: true }).click();
  const dialog = page.getByRole('dialog');
  const renamed = name + '-renamed';
  await dialog.getByLabel('서버 이름', { exact: true }).fill(renamed);
  await dialog.getByRole('button', { name: '저장', exact: true }).click();
  row = page.getByRole('row').filter({ hasText: renamed });
  await expect(row).toBeVisible();
  page.on('dialog', dialog => dialog.accept());
  await row.getByRole('button', { name: '토큰 재발급', exact: true }).click();
  await expect(page.getByLabel('발급 토큰')).not.toHaveValue(token);
  await row.getByRole('button', { name: '폐기', exact: true }).click();
  await expect(row).toHaveCount(0);
  await expect(page.getByLabel('발급 토큰')).toHaveCount(0);
});
