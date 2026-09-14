import { useEffect, useState, type FormEvent } from "react";
import {
  startAuthentication,
  startRegistration,
  browserSupportsWebAuthn,
} from "@simplewebauthn/browser";
import { Dialog, EmptyState, Icon, PasswordField } from "./UI";

type API = (path: string, method?: string, body?: unknown) => Promise<any>;
type Key = { id: string; name: string; created: number; last_used: number };
const passkeyDate = new Intl.DateTimeFormat("ko-KR", {
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  hour12: false,
});

type Action = {
  action: "add" | "delete" | "disable";
  target?: string;
  name?: string;
};
export function passkeyError(error: unknown): string {
  if (
    error instanceof Error &&
    (error.name === "NotAllowedError" || error.name === "AbortError")
  )
    return "Passkey 인증을 취소했거나 시간이 초과되었습니다. 다시 시도하세요.";
  return error instanceof Error
    ? error.message
    : "Passkey 인증에 실패했습니다.";
}
export function Passkeys({
  api,
  onLogout,
}: {
  api: API;
  onLogout: () => void;
}) {
  const [keys, setKeys] = useState<Key[]>([]);
  const [available, setAvailable] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [action, setAction] = useState<Action | null>(null);
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [reload, setReload] = useState(0);
  useEffect(() => {
    let active = true;
    setLoading(true);
    api("/me/passkeys")
      .then((data) => {
        if (!active) return;
        setKeys(data.passkeys || []);
        setAvailable(data.available && browserSupportsWebAuthn());
        setError("");
      })
      .catch((e) => {
        if (active) setError(e.message);
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [api, reload]);
  function open(next: Action) {
    setAction(next);
    setPassword("");
    setName("");
    setError("");
    setNotice("");
  }
  const disabling =
    action?.action === "disable" ||
    (action?.action === "delete" && keys.length === 1);
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!action || busy) return;
    setBusy(true);
    setError("");
    try {
      let next = await api("/me/passkeys/begin", "POST", {
        ...action,
        password,
        name: action.action === "add" ? name : "",
      });
      setPassword("");
      if (next.step === "authenticate") {
        const credential = await startAuthentication({
          optionsJSON: next.options,
        });
        next = await api("/me/passkeys/finish", "POST", {
          request_id: next.request_id,
          credential,
        });
      }
      if (next.step === "register") {
        const credential = await startRegistration({
          optionsJSON: next.options,
        });
        next = await api("/me/passkeys/register/finish", "POST", {
          request_id: next.request_id,
          credential,
        });
      }
      setAction(null);
      if (next.logout) {
        onLogout();
        return;
      }
      setNotice(
        "Passkey 설정을 변경했습니다. 다른 기기의 로그인은 해제되었습니다.",
      );
      setReload((v) => v + 1);
    } catch (e) {
      setError(passkeyError(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="panel passkey-panel" aria-labelledby="passkey-heading">
      <div className="panel-head passkey-header">
        <div className="identity-main">
          <span className="identity-avatar">
            <Icon name="firewall" />
          </span>
          <div>
            <div className="passkey-title">
              <h2 id="passkey-heading">Passkey 2차 인증</h2>
              {!loading && !(error && !action) && (
                <span
                  className={`passkey-status${keys.length ? " is-active" : ""}`}
                >
                  {keys.length > 0 && <Icon name="check" />}
                  {keys.length ? "활성화됨" : "비활성화됨"}
                </span>
              )}
            </div>
            <p className="section-description">
              로그인 시 비밀번호에 Passkey 인증을 더해 계정을 보호합니다.
            </p>
          </div>
        </div>
        <button
          className="passkey-add"
          onClick={() => open({ action: "add" })}
          disabled={loading || !available}
        >
          <Icon name="plus" />
          Passkey 추가
        </button>
      </div>
      <div className="passkey-body">
        {!action && error && (
          <div className="alert" role="alert">
            {error}
            <button onClick={() => setReload((v) => v + 1)}>다시 시도</button>
          </div>
        )}
        {notice && (
          <div className="notice" role="status">
            {notice}
          </div>
        )}
        {!loading && !available && !error && (
          <div className="passkey-help" role="note">
            <Icon name="info" />
            <p>
              Passkey를 지원하는 브라우저와 HTTPS 연결이 필요합니다. 로컬
              개발에서는 localhost를 사용하세요.
            </p>
          </div>
        )}
        {loading ? (
          <div className="passkey-loading" role="status">
            Passkey를 확인하는 중…
          </div>
        ) : keys.length > 0 ? (
          <div>
            <h3 className="passkey-list-heading">
              등록된 Passkey <span className="count-pill">{keys.length}</span>
            </h3>
            <ul className="passkey-list" aria-label="등록된 Passkey">
              {keys.map((key) => (
                <li key={key.id}>
                  <span className="passkey-key-icon">
                    <Icon name="key" />
                  </span>
                  <div className="passkey-detail">
                    <strong>{key.name}</strong>
                    <dl className="passkey-dates">
                      <div>
                        <dt>등록일</dt>
                        <dd>
                          <time dateTime={new Date(key.created).toISOString()}>
                            {passkeyDate.format(key.created)}
                          </time>
                        </dd>
                      </div>
                      <div>
                        <dt>최근 사용</dt>
                        <dd>
                          {key.last_used ? (
                            <time
                              dateTime={new Date(key.last_used).toISOString()}
                            >
                              {passkeyDate.format(key.last_used)}
                            </time>
                          ) : (
                            "아직 사용하지 않음"
                          )}
                        </dd>
                      </div>
                    </dl>
                  </div>
                  <button
                    className="danger passkey-delete"
                    disabled={loading || !available}
                    onClick={() =>
                      open({ action: "delete", target: key.id, name: key.name })
                    }
                    aria-label={`${key.name} 삭제`}
                  >
                    삭제
                  </button>
                </li>
              ))}
            </ul>
          </div>
        ) : !error ? (
          <EmptyState icon="key" title="등록된 Passkey가 없습니다.">
            Passkey 추가 버튼에서 첫 번째 키를 등록하고 2차 인증을 시작하세요.
          </EmptyState>
        ) : null}
        <div className="passkey-help">
          <Icon name="info" />
          <div>
            <p>1Password 등 원하는 저장소에 Passkey를 보관할 수 있습니다.</p>
            <p>모든 Passkey를 분실하면 서버 운영자에게 복구를 요청하세요.</p>
          </div>
        </div>
      </div>
      {!loading && keys.length > 0 && (
        <div className="passkey-footer">
          <div>
            <h3>2차 인증 해제</h3>
            <p>
              등록된 Passkey가 모두 삭제되며, 이후 비밀번호만으로 로그인합니다.
            </p>
          </div>
          <button
            className="danger"
            disabled={!available}
            onClick={() => open({ action: "disable" })}
          >
            2차 인증 해제
          </button>
        </div>
      )}
      {action && (
        <Dialog
          title={
            disabling
              ? "2차 인증 해제"
              : action.action === "add"
                ? "Passkey 추가"
                : "Passkey 삭제"
          }
          description={
            disabling
              ? "모든 Passkey를 삭제하고 모든 기기에서 로그아웃합니다. 이후 비밀번호만으로 로그인합니다."
              : keys.length
                ? "현재 비밀번호와 등록된 Passkey로 본인을 확인합니다."
                : "등록이 완료되면 모든 기기에서 로그아웃합니다. 비밀번호와 새 Passkey로 다시 로그인하세요."
          }
          busy={busy}
          onClose={() => {
            setAction(null);
            setPassword("");
            setError("");
          }}
        >
          <form className="stack-form" onSubmit={submit}>
            {error && (
              <div className="alert" role="alert">
                {error}
              </div>
            )}
            {action.action === "delete" && <p>삭제할 Passkey: {action.name}</p>}
            <fieldset disabled={busy} className="passkey-fields">
              {action.action === "add" && (
                <label>
                  Passkey 이름
                  <input
                    required
                    maxLength={80}
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="예: 1Password"
                  />
                </label>
              )}
              <PasswordField
                label="현재 비밀번호"
                value={password}
                onChange={setPassword}
                current
              />
            </fieldset>
            <div className="dialog-actions">
              <button
                type="button"
                disabled={busy}
                onClick={() => {
                  setAction(null);
                  setPassword("");
                  setError("");
                }}
              >
                취소
              </button>
              <button
                className={action.action === "add" ? "primary" : "danger-solid"}
                disabled={
                  busy || !password || (action.action === "add" && !name.trim())
                }
              >
                {busy
                  ? "인증 중…"
                  : disabling
                    ? "2차 인증 해제 확인"
                    : "확인하고 계속"}
              </button>
            </div>
          </form>
        </Dialog>
      )}
    </section>
  );
}
