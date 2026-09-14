import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';

test('optional Passkey enrollment, second factor, cancellation, last-key deletion and disable', async ({ page, context }) => {
  const origin = new URL(test.info().project.use.baseURL as string).origin;
  const adminPassword = readFileSync(process.env.TEST_PASSWORD_FILE || '/run/test-password', 'utf8').trim();
  const username = 'passkey-' + Date.now();
  const password = 'passkey-fixture-password';
  const loginResponse = await page.request.post('/api/login', { headers: { Origin: origin }, data: { username: 'admin', password: adminPassword } });
  const adminSession = await loginResponse.json();
  expect(loginResponse.status()).toBe(200);
  expect((await page.request.post('/api/admins', { headers: { Origin: origin, 'X-CSRF-Token': adminSession.csrf }, data: { username, password } })).status()).toBe(201);
  await context.clearCookies();
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
    protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
    hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
  } });
  async function passwordLogin() {
    await page.getByLabel('관리자 계정', { exact: true }).fill(username);
    await page.getByLabel('비밀번호', { exact: true }).fill(password);
    await page.getByRole('button', { name: '대시보드 로그인', exact: true }).click();
  }
  async function accounts() { await page.getByRole('button', { name: '관리자 계정', exact: true }).click(); }
  async function register(name: string) {
    await page.getByRole('button', { name: 'Passkey 추가', exact: true }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('Passkey 이름').fill(name);
    await dialog.getByLabel('현재 비밀번호', { exact: true }).fill(password);
    await dialog.getByRole('button', { name: '확인하고 계속' }).click();
    await expect(page.getByRole('heading', { name: '워크스페이스 로그인' })).toBeVisible();
  }
  await page.goto('/');
  await passwordLogin();
  await accounts();
  await expect(page.getByText('비활성화됨', { exact: false })).toBeVisible();
  await register('브라우저 테스트 키');
  await passwordLogin();
  await expect(page.getByRole('button', { name: 'Passkey로 인증', exact: true })).toBeVisible();
  expect((await page.request.get('/api/me')).status()).toBe(401);
  // Simulate a user cancelling the browser prompt once; the pending login remains retryable.
  await page.evaluate(() => {
    const original = navigator.credentials.get.bind(navigator.credentials);
    navigator.credentials.get = async () => {
      navigator.credentials.get = original;
      throw new DOMException('Cancelled', 'NotAllowedError');
    };
  });
  await page.getByRole('button', { name: 'Passkey로 인증', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('취소');
  expect((await page.request.get('/api/me')).status()).toBe(401);
  await page.getByRole('button', { name: 'Passkey로 인증', exact: true }).click();
  await accounts();
  await expect(page.getByText('활성화됨', { exact: true })).toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.getByRole('button', { name: '브라우저 테스트 키 삭제' })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.getByRole('button', { name: '브라우저 테스트 키 삭제' }).click();
  await expect(page.getByRole('dialog')).toContainText('모든 기기에서 로그아웃');
  await page.getByRole('dialog').getByLabel('현재 비밀번호', { exact: true }).fill(password);
  await page.getByRole('button', { name: '2차 인증 해제 확인' }).click();
  await expect(page.getByRole('heading', { name: '워크스페이스 로그인' })).toBeVisible();
  await page.setViewportSize({ width: 1280, height: 900 });
  await passwordLogin();
  await accounts();
  await register('다시 등록한 키');
  await passwordLogin();
  await page.getByRole('button', { name: 'Passkey로 인증', exact: true }).click();
  await accounts();
  await page.getByRole('button', { name: '2차 인증 해제', exact: true }).click();
  await page.getByRole('dialog').getByLabel('현재 비밀번호', { exact: true }).fill(password);
  await page.getByRole('button', { name: '2차 인증 해제 확인' }).click();
  await expect(page.getByRole('heading', { name: '워크스페이스 로그인' })).toBeVisible();
  await passwordLogin();
  await accounts();
  await expect(page.getByText('비활성화됨', { exact: false })).toBeVisible();
});
