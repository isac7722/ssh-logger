import { useEffect, useState, type FormEvent } from "react";
import {
  startAuthentication,
  startRegistration,
  browserSupportsWebAuthn,
} from "@simplewebauthn/browser";
import { Dialog, PasswordField } from "./UI";

type API = (path: string, method?: string, body?: unknown) => Promise<any>;
type Key = { id: string; name: string; created: number; last_used: number };
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
    <section className="panel">
      <div className="panel-head">
        <div>
          <h2>Passkey 2차 인증</h2>
          <p>
            {loading
              ? "확인 중…"
              : keys.length
                ? "활성화됨 · 로그인 시 비밀번호와 Passkey를 확인합니다."
                : "비활성화됨 · 현재 비밀번호 확인 후 Passkey를 등록하세요."}
          </p>
        </div>
        <button
          onClick={() => open({ action: "add" })}
          disabled={loading || !available}
        >
          Passkey 추가
        </button>
      </div>
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
      {!loading && !available && (
        <p>
          Passkey를 지원하는 브라우저와 HTTPS 도메인(로컬 개발은 localhost)이
          필요합니다.
        </p>
      )}
      <p>
        1Password 등 원하는 저장소에 보관할 수 있습니다. 모두 분실하면 서버
        운영자에게 복구를 요청하세요.
      </p>
      {keys.length > 0 && (
        <ul className="passkey-list">
          {keys.map((key) => (
            <li key={key.id}>
              <div>
                <strong>{key.name}</strong>
                <p>
                  등록: {new Date(key.created).toLocaleString()} · 최근 사용:{" "}
                  {key.last_used
                    ? new Date(key.last_used).toLocaleString()
                    : "없음"}
                </p>
              </div>
              <button
                disabled={!available}
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
      )}
      {keys.length > 0 && (
        <button
          disabled={!available}
          onClick={() => open({ action: "disable" })}
        >
          2차 인증 해제
        </button>
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
                className="primary"
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
