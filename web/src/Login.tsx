import { useEffect, useRef, type FormEvent } from "react";
import { Icon, PasswordField } from "./UI";

type Props = {
  mfa: boolean;
  onReset: () => void;
  username: string;
  password: string;
  onUsernameChange: (value: string) => void;
  onPasswordChange: (value: string) => void;
  onSubmit: (event: FormEvent) => void;
  busy: boolean;
  checking: boolean;
  error: string;
  notice: string;
};

export function Login({
  mfa,
  onReset,
  username,
  password,
  onUsernameChange,
  onPasswordChange,
  onSubmit,
  busy,
  checking,
  error,
  notice,
}: Props) {
  const errorRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (error && !busy) errorRef.current?.focus();
  }, [error, busy]);

  return (
    <main className="login-shell">
      <div className="login-layout">
        <div className="login-brand">
          <span className="logo-mark" aria-hidden="true">
            &gt;_
          </span>
          <span>
            SSH Logger<small>서버 운영 워크스페이스</small>
          </span>
        </div>
        <section className="login-card" aria-labelledby="login-title">
          <div className="login-heading">
            <span className="login-heading-icon">
              <Icon name="lock" />
            </span>
            <h1 id="login-title">워크스페이스 로그인</h1>
            <p>
              {mfa
                ? "등록한 Passkey로 2차 인증을 완료하세요."
                : "관리자 계정으로 접속하세요."}
            </p>
          </div>
          {checking ? (
            <div className="login-checking" role="status">
              <span className="login-spinner" aria-hidden="true" />
              로그인 상태 확인 중…
            </div>
          ) : (
            <form onSubmit={onSubmit} aria-labelledby="login-title">
              {notice && (
                <div className="notice" role="status">
                  {notice}
                </div>
              )}
              {!mfa && (
                <fieldset className="login-fields" disabled={busy}>
                  <legend className="sr-only">로그인 정보</legend>
                  <label htmlFor="login-username">
                    관리자 계정
                    <input
                      id="login-username"
                      name="username"
                      autoComplete="username"
                      autoCapitalize="none"
                      spellCheck={false}
                      placeholder="계정 이름을 입력하세요"
                      value={username}
                      onChange={(event) => onUsernameChange(event.target.value)}
                      required
                    />
                  </label>
                  <PasswordField
                    label="비밀번호"
                    value={password}
                    onChange={onPasswordChange}
                    current
                  />
                </fieldset>
              )}
              {error && (
                <div
                  className="alert login-error"
                  role="alert"
                  tabIndex={-1}
                  ref={errorRef}
                >
                  {error}
                </div>
              )}
              <button
                className="primary login-submit"
                disabled={busy}
                aria-live="polite"
              >
                {busy && <span className="login-spinner" aria-hidden="true" />}
                <span>
                  {busy
                    ? "로그인 중…"
                    : mfa
                      ? "Passkey로 인증"
                      : "대시보드 로그인"}
                </span>
              </button>
              {mfa && (
                <button type="button" disabled={busy} onClick={onReset}>
                  로그인 처음으로
                </button>
              )}
              <p className="login-help">
                계정이나 비밀번호를 모르면 최고 관리자에게 문의하세요.
              </p>
            </form>
          )}
        </section>
        <p className="login-caption">접속 세션 · 활동 기록 · SSH 접근 제어</p>
      </div>
    </main>
  );
}
