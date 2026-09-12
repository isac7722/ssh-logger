import { useEffect, useState, type FormEvent } from "react";

type Props = {
  username: string;
  superAdmin: boolean;
  servers: Record<string, any>[];
  api: (path: string, method?: string, body?: unknown) => Promise<any>;
  onPasswordChanged: () => void;
};

export function AccountSettings({
  username,
  api,
  onPasswordChanged,
  superAdmin,
  servers,
}: Props) {
  const [admins, setAdmins] = useState<
    { username: string; role: string; server_ids: string }[]
  >([]);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [newUsername, setNewUsername] = useState("");
  const [initialPassword, setInitialPassword] = useState("");
  const [initialConfirmation, setInitialConfirmation] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  useEffect(() => {
    let active = true;
    if (!superAdmin) return;
    api("/admins")
      .then((rows) => {
        if (active) setAdmins(rows);
      })
      .catch((e) => {
        if (active) setError(e.message);
      });
    return () => {
      active = false;
    };
  }, [api, superAdmin]);

  async function submit(e: FormEvent, change: boolean) {
    e.preventDefault();
    setError("");
    setNotice("");
    const password = change ? newPassword : initialPassword;
    const repeated = change ? confirmation : initialConfirmation;
    if (password !== repeated) {
      setError("비밀번호 확인이 일치하지 않습니다.");
      return;
    }
    const bytes = new TextEncoder().encode(password).length;
    if (bytes < 12 || bytes > 72) {
      setError("비밀번호는 UTF-8 기준 12–72바이트여야 합니다.");
      return;
    }
    setBusy(true);
    try {
      if (change) {
        await api("/me/password", "PUT", {
          current_password: currentPassword,
          new_password: newPassword,
        });
        setCurrentPassword("");
        setNewPassword("");
        setConfirmation("");
        onPasswordChanged();
      } else {
        const created = await api("/admins", "POST", {
          username: newUsername,
          password: initialPassword,
        });
        setAdmins(await api("/admins"));
        setNewUsername("");
        setInitialPassword("");
        setInitialConfirmation("");
        setNotice(`${created.username} 관리자 계정을 생성했습니다.`);
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="account-settings">
      {error && (
        <div className="alert" role="alert">
          {error}
        </div>
      )}
      {notice && (
        <div className="notice" role="status">
          {notice}
        </div>
      )}
      <section className="panel account-panel">
        <h2>내 비밀번호 변경</h2>
        <p>
          로그인 계정: <strong>{username}</strong>. 변경하면 이 계정으로 접속한
          모든 기기에서 로그아웃됩니다.
        </p>
        <form onSubmit={(e) => submit(e, true)}>
          <label>
            현재 비밀번호
            <input
              type="password"
              autoComplete="current-password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              required
            />
          </label>
          <label>
            새 비밀번호
            <input
              type="password"
              autoComplete="new-password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              required
            />
          </label>
          <label>
            새 비밀번호 확인
            <input
              type="password"
              autoComplete="new-password"
              value={confirmation}
              onChange={(e) => setConfirmation(e.target.value)}
              required
            />
          </label>
          <small>12–72바이트. 영문·숫자는 한 글자당 1바이트입니다.</small>
          <button className="primary" disabled={busy}>
            비밀번호 변경
          </button>
        </form>
      </section>
      {superAdmin && (
        <>
          <section className="panel account-panel">
            <h2>관리자 계정 생성</h2>
            <p>
              새 계정은 일반 관리자로 생성되며, 서버를 배정하기 전에는 어떤
              서버에도 접근할 수 없습니다.
            </p>
            <form onSubmit={(e) => submit(e, false)}>
              <label>
                새 관리자 계정
                <input
                  autoComplete="off"
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  maxLength={64}
                  pattern="[A-Za-z0-9][A-Za-z0-9_.\-]*"
                  required
                />
              </label>
              <small>
                영문·숫자로 시작하는 1–64자. 점·밑줄·하이픈을 사용할 수
                있습니다.
              </small>
              <label>
                초기 비밀번호
                <input
                  type="password"
                  autoComplete="new-password"
                  value={initialPassword}
                  onChange={(e) => setInitialPassword(e.target.value)}
                  required
                />
              </label>
              <label>
                초기 비밀번호 확인
                <input
                  type="password"
                  autoComplete="new-password"
                  value={initialConfirmation}
                  onChange={(e) => setInitialConfirmation(e.target.value)}
                  required
                />
              </label>
              <small>
                12–72바이트. 생성 후 비밀번호를 다시 조회할 수 없습니다.
              </small>
              <button className="primary" disabled={busy}>
                관리자 생성
              </button>
            </form>
          </section>
          <section className="panel">
            <div className="panel-head">
              <h2>등록된 관리자</h2>
              <span>{admins.length}명</span>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>계정</th>
                    <th>권한</th>
                  </tr>
                </thead>
                <tbody>
                  {admins.map((admin) => (
                    <tr key={admin.username}>
                      <td>
                        {admin.username}
                        {admin.username === username && " (내 계정)"}
                      </td>
                      <td>
                        <AccessEditor
                          admin={admin}
                          servers={servers}
                          api={api}
                          onSaved={async () => setAdmins(await api("/admins"))}
                        />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}
    </div>
  );
}

function AccessEditor({
  admin,
  servers,
  api,
  onSaved,
}: {
  admin: { username: string; role: string; server_ids: string };
  servers: Record<string, any>[];
  api: Props["api"];
  onSaved: () => Promise<void>;
}) {
  const [role, setRole] = useState(admin.role);
  const [selected, setSelected] = useState<string[]>(
    JSON.parse(admin.server_ids),
  );
  const [busy, setBusy] = useState(false),
    [message, setMessage] = useState("");
  useEffect(() => {
    setRole(admin.role);
    setSelected(JSON.parse(admin.server_ids));
  }, [admin.role, admin.server_ids]);
  return (
    <form
      onSubmit={async (e) => {
        e.preventDefault();
        if (!confirm(`${admin.username}의 권한과 서버 배정을 변경할까요?`))
          return;
        setBusy(true);
        setMessage("");
        try {
          await api(
            `/admins/${encodeURIComponent(admin.username)}/access`,
            "PUT",
            { role, server_ids: selected },
          );
          await onSaved();
          setMessage("저장했습니다.");
        } catch (e) {
          setMessage((e as Error).message);
        } finally {
          setBusy(false);
        }
      }}
    >
      <label>
        계정 권한
        <select
          aria-label="계정 권한"
          value={role}
          onChange={(e) => setRole(e.target.value)}
        >
          <option value="admin">일반 관리자</option>
          <option value="super_admin">Super admin (모든 서버)</option>
        </select>
      </label>
      {role === "admin" && (
        <fieldset>
          <legend>배정할 서버</legend>
          {servers.map((s) => (
            <label className="check-label" key={s.id}>
              <input
                type="checkbox"
                checked={selected.includes(s.id)}
                onChange={(e) =>
                  setSelected((ids) =>
                    e.target.checked
                      ? [...ids, s.id]
                      : ids.filter((id) => id !== s.id),
                  )
                }
              />
              {s.name}
            </label>
          ))}
          {!servers.length && <p>등록된 서버가 없습니다.</p>}
        </fieldset>
      )}
      <button disabled={busy}>권한 저장</button>
      {message && <small role="status">{message}</small>}
    </form>
  );
}
