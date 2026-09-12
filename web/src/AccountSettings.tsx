import { useEffect, useState, type FormEvent } from "react";
import { Dialog, EmptyState, Icon, PasswordField } from "./UI";

type Admin = { username: string; role: string; server_ids: string };
type Props = {
  username: string;
  superAdmin: boolean;
  servers: Record<string, any>[];
  api: (path: string, method?: string, body?: unknown) => Promise<any>;
  onPasswordChanged: () => void;
};
const roleName = (role: string) =>
  role === "super_admin" ? "최고 관리자" : "일반 관리자";

export function AccountSettings({
  username,
  api,
  onPasswordChanged,
  superAdmin,
  servers,
}: Props) {
  const [admins, setAdmins] = useState<Admin[]>([]);
  const [loading, setLoading] = useState(superAdmin);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [reload, setReload] = useState(0);
  const [modal, setModal] = useState<"password" | "create" | Admin | null>(
    null,
  );
  useEffect(() => {
    let active = true;
    if (!superAdmin) return;
    setLoading(true);
    api("/admins")
      .then((rows) => {
        if (active) {
          setAdmins(rows);
          setError("");
        }
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
  }, [api, superAdmin, reload]);
  function open(next: typeof modal) {
    setNotice("");
    setModal(next);
  }
  return (
    <div className="account-settings management-page">
      {error && (
        <div className="alert" role="alert">
          {error}
          <button onClick={() => setReload((value) => value + 1)}>
            다시 시도
          </button>
        </div>
      )}
      {notice && (
        <div className="notice" role="status">
          {notice}
        </div>
      )}
      <section className="panel identity-card">
        <div className="identity-main">
          <span className="identity-avatar">
            <Icon name="lock" />
          </span>
          <div>
            <h2>내 계정</h2>
            <div className="identity-detail">
              <strong>{username}</strong>
              <span className="role-label">
                {roleName(superAdmin ? "super_admin" : "admin")}
              </span>
            </div>
          </div>
        </div>
        <button onClick={() => open("password")}>비밀번호 변경</button>
      </section>
      {superAdmin && (
        <section className="panel">
          <div className="panel-head">
            <div>
              <h2>
                등록된 관리자{" "}
                <span className="count-pill">
                  {loading ? "—" : admins.length}
                </span>
              </h2>
              <p className="section-description">
                계정별 권한과 접근 가능한 서버를 관리합니다.
              </p>
            </div>
            <button className="primary" onClick={() => open("create")}>
              <Icon name="plus" />
              관리자 추가
            </button>
          </div>
          {loading ? (
            <div className="loading-state" role="status">
              관리자 목록을 불러오는 중…
            </div>
          ) : admins.length ? (
            <div className="table-wrap">
              <table className="management-table account-table">
                <thead>
                  <tr>
                    <th scope="col">계정</th>
                    <th scope="col">권한</th>
                    <th scope="col">접근 가능 서버</th>
                    <th scope="col" className="action-cell">
                      관리
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {admins.map((admin) => {
                    const ids: string[] = JSON.parse(admin.server_ids);
                    const assigned = ids.map(
                      (id) =>
                        servers.find((server) => server.id === id)?.name || id,
                    );
                    return (
                      <tr key={admin.username}>
                        <td>
                          <span className="account-name">{admin.username}</span>
                          {admin.username === username && (
                            <span className="self-label">나</span>
                          )}
                        </td>
                        <td data-label="권한">
                          <span className="role-label">
                            {roleName(admin.role)}
                          </span>
                        </td>
                        <td data-label="접근 가능 서버">
                          {admin.role === "super_admin" ? (
                            "모든 서버"
                          ) : assigned.length ? (
                            <span className="server-tags">
                              {assigned.map((name, i) => (
                                <span key={ids[i]}>{name}</span>
                              ))}
                            </span>
                          ) : (
                            <span className="unassigned">서버 미배정</span>
                          )}
                        </td>
                        <td className="action-cell">
                          <button
                            aria-label={`${admin.username} 권한 편집`}
                            onClick={() => open(admin)}
                          >
                            편집
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState
              icon="accounts"
              title={
                error
                  ? "관리자 목록을 확인할 수 없습니다."
                  : "등록된 관리자가 없습니다."
              }
            >
              관리자 추가 버튼에서 새 계정을 생성할 수 있습니다.
            </EmptyState>
          )}
          <div className="panel-footnote">
            <Icon name="lock" />
            일반 관리자는 배정된 서버에만 접근할 수 있습니다.
          </div>
        </section>
      )}
      {typeof modal === "string" && (
        <AccountForm
          key={modal}
          mode={modal}
          api={api}
          onClose={() => setModal(null)}
          onPasswordChanged={onPasswordChanged}
          onCreated={(name) => {
            setAdmins((rows) =>
              [
                ...rows,
                { username: name, role: "admin", server_ids: "[]" },
              ].sort((a, b) => a.username.localeCompare(b.username)),
            );
            setModal(null);
            setNotice(
              `${name} 관리자 계정을 생성했습니다. 권한 편집에서 서버를 배정하세요.`,
            );
          }}
        />
      )}
      {modal && typeof modal === "object" && (
        <AccessEditor
          admin={modal}
          servers={servers}
          api={api}
          onClose={() => setModal(null)}
          onSaved={(updated) => {
            setAdmins((rows) =>
              rows.map((admin) =>
                admin.username === updated.username ? updated : admin,
              ),
            );
            setModal(null);
            setNotice(`${updated.username}의 권한과 서버 배정을 저장했습니다.`);
          }}
        />
      )}
    </div>
  );
}

function AccountForm({
  mode,
  api,
  onClose,
  onCreated,
  onPasswordChanged,
}: {
  mode: "password" | "create";
  api: Props["api"];
  onClose: () => void;
  onCreated: (name: string) => void;
  onPasswordChanged: () => void;
}) {
  const change = mode === "password";
  const [username, setUsername] = useState("");
  const [current, setCurrent] = useState("");
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [errors, setErrors] = useState({ password: "", confirmation: "" });
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    const bytes = new TextEncoder().encode(password).length;
    const next = {
      password:
        bytes < 12 || bytes > 72
          ? "비밀번호는 UTF-8 기준 12–72바이트로 입력하세요."
          : "",
      confirmation:
        password !== confirmation
          ? "비밀번호가 일치하지 않습니다. 다시 확인하세요."
          : "",
    };
    setErrors(next);
    setError("");
    if (next.password || next.confirmation) {
      const inputs = event.currentTarget.querySelectorAll<HTMLInputElement>(
        'input[autocomplete="new-password"]',
      );
      inputs[next.password ? 0 : 1]?.focus();
      return;
    }
    setBusy(true);
    try {
      if (change) {
        await api("/me/password", "PUT", {
          current_password: current,
          new_password: password,
        });
        onPasswordChanged();
      } else {
        const created = await api("/admins", "POST", { username, password });
        onCreated(created.username);
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Dialog
      title={change ? "비밀번호 변경" : "관리자 추가"}
      description={
        change
          ? "현재 비밀번호를 확인하고 새 비밀번호를 설정합니다."
          : "서버를 관리할 새 계정을 생성합니다."
      }
      onClose={onClose}
      busy={busy}
    >
      <form className="stack-form" onSubmit={submit}>
        <div className="form-callout">
          {change
            ? "변경하면 현재 기기를 포함한 모든 기기에서 로그아웃됩니다."
            : "일반 관리자로 생성됩니다. 생성 후 서버를 배정해야 접근할 수 있습니다."}
        </div>
        {error && (
          <div className="alert" role="alert">
            {error}
          </div>
        )}
        <fieldset className="form-fields" disabled={busy}>
          {change ? (
            <PasswordField
              label="현재 비밀번호"
              value={current}
              onChange={setCurrent}
              current
            />
          ) : (
            <div className="form-field">
              <label htmlFor="new-admin-username">새 관리자 계정</label>
              <input
                id="new-admin-username"
                autoComplete="off"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                maxLength={64}
                pattern="[A-Za-z0-9][A-Za-z0-9_.\-]*"
                required
                aria-describedby="username-hint"
              />
              <small id="username-hint">
                영문·숫자로 시작하는 1–64자. 점·밑줄·하이픈 사용 가능.
              </small>
            </div>
          )}
          <PasswordField
            label={change ? "새 비밀번호" : "초기 비밀번호"}
            value={password}
            onChange={(value) => {
              setPassword(value);
              setErrors((old) => ({ ...old, password: "" }));
            }}
            error={errors.password}
            hint="12–72바이트. 영문·숫자는 한 글자당 1바이트입니다."
          />
          <PasswordField
            label={change ? "새 비밀번호 확인" : "초기 비밀번호 확인"}
            value={confirmation}
            onChange={(value) => {
              setConfirmation(value);
              setErrors((old) => ({ ...old, confirmation: "" }));
            }}
            error={errors.confirmation}
          />
          {!change && (
            <p className="field-hint">
              생성 후 비밀번호를 다시 조회할 수 없습니다.
            </p>
          )}
        </fieldset>
        <div className="dialog-actions">
          <button type="button" onClick={onClose} disabled={busy}>
            취소
          </button>
          <button className="primary" disabled={busy}>
            {busy ? "저장 중…" : change ? "비밀번호 변경" : "관리자 생성"}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

function AccessEditor({
  admin,
  servers,
  api,
  onClose,
  onSaved,
}: {
  admin: Admin;
  servers: Props["servers"];
  api: Props["api"];
  onClose: () => void;
  onSaved: (admin: Admin) => void;
}) {
  const [role, setRole] = useState(admin.role);
  const [selected, setSelected] = useState<string[]>(() =>
    JSON.parse(admin.server_ids),
  );
  const [busy, setBusy] = useState(false);
  const [review, setReview] = useState(false);
  const [error, setError] = useState("");
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (busy) return;
    if (!review) {
      setReview(true);
      return;
    }
    setBusy(true);
    setError("");
    try {
      await api(`/admins/${encodeURIComponent(admin.username)}/access`, "PUT", {
        role,
        server_ids: selected,
      });
      onSaved({ ...admin, role, server_ids: JSON.stringify(selected) });
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Dialog
      title={review ? "권한 변경 확인" : "관리자 권한 편집"}
      description={`${admin.username}의 권한과 서버 접근 범위를 설정합니다.`}
      busy={busy}
      onClose={onClose}
    >
      <form className="stack-form" onSubmit={submit}>
        {error && (
          <div className="alert" role="alert">
            {error}
          </div>
        )}
        {review ? (
          <div className="confirmation-summary" role="status">
            <dl>
              <div>
                <dt>계정</dt>
                <dd>{admin.username}</dd>
              </div>
              <div>
                <dt>변경할 권한</dt>
                <dd>{roleName(role)}</dd>
              </div>
              <div>
                <dt>접근 가능 서버</dt>
                <dd>
                  {role === "super_admin"
                    ? "모든 서버"
                    : selected
                        .map(
                          (id) =>
                            servers.find((server) => server.id === id)?.name ||
                            id,
                        )
                        .join(", ") || "없음"}
                </dd>
              </div>
            </dl>
            <p>저장하면 이 계정의 접근 권한에 바로 반영됩니다.</p>
          </div>
        ) : (
          <>
            <label>
              계정 권한
              <select value={role} onChange={(e) => setRole(e.target.value)}>
                <option value="admin">일반 관리자</option>
                <option value="super_admin">최고 관리자 (모든 서버)</option>
              </select>
            </label>
            {role === "admin" ? (
              <fieldset className="server-assignment">
                <legend>
                  배정할 서버{" "}
                  <span className="count-pill">{selected.length}</span>
                </legend>
                <p>선택한 서버의 기록 조회와 SSH 접근을 관리할 수 있습니다.</p>
                {servers.map((server) => (
                  <label className="check-label" key={server.id}>
                    <input
                      type="checkbox"
                      checked={selected.includes(server.id)}
                      onChange={(e) =>
                        setSelected((ids) =>
                          e.target.checked
                            ? [...ids, server.id]
                            : ids.filter((id) => id !== server.id),
                        )
                      }
                    />
                    {server.name}
                  </label>
                ))}
                {!servers.length && <p>등록된 서버가 없습니다.</p>}
              </fieldset>
            ) : (
              <div className="form-callout">
                최고 관리자는 모든 서버와 관리자 계정을 관리할 수 있습니다.
              </div>
            )}
          </>
        )}
        <div className="dialog-actions">
          <button
            type="button"
            disabled={busy}
            onClick={
              review
                ? () => {
                    setReview(false);
                    setError("");
                  }
                : onClose
            }
          >
            {review ? "뒤로" : "취소"}
          </button>
          <button className="primary" disabled={busy}>
            {busy ? "저장 중…" : review ? "변경 확인" : "권한 저장"}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
