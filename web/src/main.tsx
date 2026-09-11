import React, { useCallback, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";
import { AccountSettings } from "./AccountSettings";
import {
  ActivityControls,
  CommandText,
  type ActivityMode,
  type ActivitySummary,
} from "./ActivityControls";

type Row = Record<string, any>;
type View =
  "overview" | "sessions" | "events" | "servers" | "settings" | "accounts";
const labels: Record<string, string> = {
  overview: "전체 현황",
  sessions: "접속 세션",
  events: "활동 기록",
  servers: "서버 관리",
  settings: "보관 설정",
  accounts: "관리자 계정",
  session_start: "세션 시작",
  session_end: "세션 종료",
  login_success: "인증 성공",
  login_failure: "인증 실패",
  exec: "프로그램 실행",
};
const fmt = (v: number) => (v ? new Date(v).toLocaleString("ko-KR") : "—");
const health = (s: Row) =>
  s.revoked
    ? "인증 폐기"
    : !s.last_seen
      ? "연결 대기"
      : Date.now() - s.last_seen > 60000
        ? "연결 끊김"
        : s.health === "ok"
          ? "정상"
          : (
              {
                collection_gap: "수집 공백 발생",
                audit_read_error: "로그 읽기 오류",
                session_scan_error: "세션 확인 오류",
              } as Record<string, string>
            )[s.health] || s.health;
const localDay = () => new Date().setHours(0, 0, 0, 0);
let csrf = "";
async function api(path: string, method = "GET", body?: unknown) {
  const res = await fetch("/api" + path, {
    method,
    headers: {
      "Content-Type": "application/json",
      ...(method === "GET" ? {} : { "X-CSRF-Token": csrf }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok) {
    if (res.status === 401 && path !== "/login")
      window.dispatchEvent(new Event("auth-expired"));
    throw new Error(data.error || "요청에 실패했습니다.");
  }
  return data;
}
function App() {
  const [activityMode, setActivityMode] = useState<ActivityMode>("important");
  const [activitySummary, setActivitySummary] =
    useState<ActivitySummary | null>(null);
  const [detailMode, setDetailMode] = useState<ActivityMode>("important");
  const [detailSummary, setDetailSummary] = useState<ActivitySummary | null>(
    null,
  );
  const [detailLoading, setDetailLoading] = useState(false);
  const [auth, setAuth] = useState<boolean | null>(null),
    [user, setUser] = useState("admin"),
    [password, setPassword] = useState(""),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  const [view, setView] = useState<View>("overview"),
    [servers, setServers] = useState<Row[]>([]),
    [rows, setRows] = useState<Row[]>([]),
    [stats, setStats] = useState<Row>({}),
    [sessions, setSessions] = useState<Row[]>([]);
  const [server, setServer] = useState(""),
    [account, setAccount] = useState(""),
    [ip, setIP] = useState(""),
    [query, setQuery] = useState(""),
    [kind, setKind] = useState(""),
    [days, setDays] = useState("1"),
    [page, setPage] = useState(0),
    [updated, setUpdated] = useState(0);
  const [selected, setSelected] = useState<Row | null>(null),
    [detail, setDetail] = useState<Row[]>([]),
    [detailPage, setDetailPage] = useState(0),
    [detailError, setDetailError] = useState("");
  const [serverName, setServerName] = useState(""),
    [credential, setCredential] = useState<Row | null>(null),
    [retention, setRetention] = useState(30),
    [notice, setNotice] = useState(""),
    [loading, setLoading] = useState(true);
  useEffect(() => {
    api("/me")
      .then((x) => {
        csrf = x.csrf;
        setUser(x.username);
        setAuth(true);
      })
      .catch(() => setAuth(false));
    const f = () => {
      setAuth(false);
      setCredential(null);
      csrf = "";
    };
    window.addEventListener("auth-expired", f);
    return () => window.removeEventListener("auth-expired", f);
  }, []);
  const load = useCallback(async () => {
    const p = new URLSearchParams({
      from: String(Date.now() - Number(days) * 86400000),
      to: String(Date.now()),
      page: String(page),
      activity: activityMode,
      summary: "1",
    });
    if (server) p.set("server_id", server);
    if (account) p.set("user", account);
    if (ip) p.set("ip", ip);
    if (query) p.set("q", query);
    if (kind) p.set("kind", kind);
    const [ss, overview, ev, se] = await Promise.all([
      api("/servers"),
      api("/overview?day_start=" + localDay()),
      view === "overview" || view === "events"
        ? api("/events?" + p)
        : Promise.resolve([]),
      view === "overview" || view === "sessions"
        ? api(
            "/sessions?" +
              new URLSearchParams({
                server_id: server,
                user: account,
                ip,
                page: String(view === "overview" ? 0 : page),
                active: view === "overview" ? "1" : "",
              }),
          )
        : Promise.resolve([]),
    ]);
    return { ss, overview, ev, se };
  }, [view, server, account, ip, query, kind, days, page, activityMode]);
  useEffect(() => {
    if (!auth) return;
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    setLoading(true);
    const tick = async () => {
      try {
        const x = await load();
        if (alive) {
          setServers(x.ss);
          setStats(x.overview[0] || {});
          setRows(x.ev.items || []);
          setActivitySummary(x.ev.items ? x.ev : null);
          setSessions(x.se);
          setUpdated(Date.now());
          setError("");
        }
      } catch (e) {
        if (alive) setError((e as Error).message);
      } finally {
        if (alive) {
          setLoading(false);
          timer = setTimeout(tick, 5000);
        }
      }
    };
    tick();
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [auth, load]);
  useEffect(() => {
    if (auth && view === "settings")
      api("/settings")
        .then((x) => setRetention(x[0].retention_days))
        .catch((e) => setError(e.message));
  }, [auth, view]);
  useEffect(() => {
    if (!selected || !auth) return;
    let alive = true;
    setDetailError("");
    setDetail([]);
    setDetailSummary(null);
    setDetailLoading(true);
    api(
      "/events?" +
        new URLSearchParams({
          server_id: selected.server_id,
          session_id: selected.id,
          from: String(selected.started),
          to: String(
            Math.min(
              selected.ended || Date.now(),
              selected.started + 366 * 86400000,
            ),
          ),
          page: String(detailPage),
          activity: detailMode,
          summary: "1",
        }),
    )
      .then((x) => {
        if (alive) {
          setDetail(x.items);
          setDetailSummary(x);
        }
      })
      .catch((e) => {
        if (alive) setDetailError(e.message);
      })
      .finally(() => {
        if (alive) setDetailLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [selected, detailPage, auth, detailMode]);
  async function login(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const x = await api("/login", "POST", { username: user, password });
      csrf = x.csrf;
      setUser(x.username);
      setPassword("");
      setNotice("");
      setAuth(true);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  function navigate(v: View) {
    setView(v);
    setPage(0);
    setNotice("");
    setError("");
  }
  async function action(fn: () => Promise<void>) {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await fn();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  const pager = (items: Row[], p: number, set: (v: number) => void) => (
    <div className="pager">
      <span>{p + 1} 페이지 · 최대 50건</span>
      <button disabled={p === 0} onClick={() => set(p - 1)}>
        이전
      </button>
      <button disabled={items.length <= 50} onClick={() => set(p + 1)}>
        다음
      </button>
    </div>
  );
  const eventTable = (items: Row[]) => (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>시각</th>
            <th>서버 / 계정</th>
            <th>활동</th>
            <th>실행 프로그램 / 인자</th>
            <th>프로세스</th>
            <th>접속 IP</th>
            <th>세션 연결</th>
          </tr>
        </thead>
        <tbody>
          {items.slice(0, 50).map((r) => (
            <tr key={r.seq}>
              <td className="time">{fmt(r.time)}</td>
              <td>
                <strong>{r.server_name}</strong>
                <small>
                  {r.user || "알 수 없음"}
                  {r.kind === "exec" &&
                  r.effective_user &&
                  r.effective_user !== r.user
                    ? " → " + r.effective_user
                    : ""}
                </small>
              </td>
              <td>
                <span
                  className={
                    "badge " + (r.kind === "login_failure" ? "bad" : "")
                  }
                >
                  {labels[r.kind]}
                </span>
              </td>
              <td className="command">
                <CommandText
                  text={
                    r.kind === "exec"
                      ? r.args?.length
                        ? r.args.join(" ")
                        : r.program
                      : r.program || "—"
                  }
                />
                {r.routine_reason && (
                  <small className="routine-reason">{r.routine_reason}</small>
                )}
                {r.kind === "exec" && r.outcome !== "yes" && (
                  <small
                    className={
                      r.outcome === "no" ? "execution-failed" : "muted"
                    }
                  >
                    {r.outcome === "no"
                      ? "실행 요청 실패"
                      : "실행 요청 결과 불명"}
                  </small>
                )}
              </td>
              <td className="process-ids">
                {r.pid == null && r.ppid == null ? (
                  <span className="muted">미수집</span>
                ) : (
                  <>
                    <span>PID {r.pid ?? "미수집"}</span>
                    <small>부모 PID {r.ppid ?? "미수집"}</small>
                  </>
                )}
              </td>
              <td>{r.ip || "—"}</td>
              <td>
                {r.linked ? (
                  <span className="dot-label">연결됨</span>
                ) : (
                  <span className="muted">연결 불명</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {!items.length && (
        <div className="empty">
          표시할 활동 기록이 없습니다.
          <small>서버를 연결하거나 검색 조건을 변경하세요.</small>
        </div>
      )}
    </div>
  );
  const sessionTable = (items: Row[]) => (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>서버</th>
            <th>계정 / IP</th>
            <th>접속 시각</th>
            <th>종료 시각</th>
            <th>상태</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {items.slice(0, 50).map((s) => (
            <tr key={s.server_id + s.id}>
              <td>
                <strong>{s.server_name}</strong>
              </td>
              <td>
                {s.user || "알 수 없음"}
                <small>{s.ip || "IP 없음"}</small>
              </td>
              <td className="time">{fmt(s.started)}</td>
              <td className="time">{fmt(s.ended)}</td>
              <td>
                <span
                  className={
                    "badge " +
                    (s.status === "active"
                      ? "good"
                      : s.status === "unknown"
                        ? "warn"
                        : "")
                  }
                >
                  {s.status === "active"
                    ? "접속 중"
                    : s.status === "ended"
                      ? "종료"
                      : "상태 확인 불가"}
                </span>
              </td>
              <td>
                <button
                  onClick={() => {
                    setDetailPage(0);
                    setDetailMode("important");
                    setSelected(s);
                  }}
                >
                  상세 보기 ↗
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {!items.length && (
        <div className="empty">표시할 접속 세션이 없습니다.</div>
      )}
    </div>
  );
  if (auth === null)
    return <div className="login-shell">로그인 상태 확인 중…</div>;
  if (!auth)
    return (
      <div className="login-shell">
        <form className="login-card" onSubmit={login}>
          <div className="logo-mark">&gt;_</div>
          <div className="eyebrow">SERVER ACTIVITY MONITOR</div>
          <h1>SSH Logger</h1>
          <p>
            서버에 접속한 사람과
            <br />그 순간의 활동을 한곳에서.
          </p>
          {notice && (
            <div className="notice" role="status">
              {notice}
            </div>
          )}
          {error && (
            <div className="alert" role="alert">
              {error}
            </div>
          )}
          <label>
            관리자 계정
            <input
              autoComplete="username"
              value={user}
              onChange={(e) => setUser(e.target.value)}
              required
            />
          </label>
          <label>
            비밀번호
            <input
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </label>
          <button className="primary" disabled={busy}>
            {busy ? "로그인 중…" : "대시보드 로그인 →"}
          </button>
          <small>설치 시 설정한 관리자 계정으로 로그인하세요.</small>
        </form>
      </div>
    );
  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <span className="logo-mark">&gt;_</span>
          <span>
            SSH Logger<small>ACTIVITY CONSOLE</small>
          </span>
        </div>
        <div className="nav-label">WORKSPACE</div>
        <nav>
          {(
            [
              "overview",
              "sessions",
              "events",
              "servers",
              "settings",
              "accounts",
            ] as View[]
          ).map((v, i) => (
            <button
              key={v}
              className={view === v ? "selected" : ""}
              onClick={() => navigate(v)}
            >
              <span aria-hidden="true">
                {["◫", "⇄", "≡", "▤", "⚙", "♙"][i]}
              </span>
              {labels[v]}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <span className="dot-label">중앙 로그 관리</span>
          <small>SSH 접속 · 실행 감사 기록</small>
          <button
            onClick={() =>
              action(async () => {
                await api("/logout", "POST");
                csrf = "";
                setAuth(false);
                setCredential(null);
              })
            }
          >
            로그아웃 ↗
          </button>
        </div>
      </aside>
      <main>
        <header>
          <span className="breadcrumb">
            워크스페이스 <span>/</span> {labels[view]}
          </span>
          <span className="update">
            {loading
              ? "불러오는 중…"
              : updated
                ? "갱신 " + new Date(updated).toLocaleTimeString("ko-KR")
                : ""}{" "}
            · 5초 간격
          </span>
        </header>
        <div className="content">
          <div className="page-title">
            <div>
              <div className="eyebrow">SSH LOGGER / MONITORING</div>
              <h1>{labels[view]}</h1>
              <p>
                {view === "overview"
                  ? "서버 접속과 사용자 활동을 확인하세요."
                  : view === "servers"
                    ? "수집기를 연결하고 서버별 수집 상태를 관리하세요."
                    : view === "accounts"
                      ? "내 비밀번호와 관리자 계정을 관리하세요."
                      : view === "settings"
                        ? "기록 보관 기간을 관리하세요."
                        : "계정과 서버별 기록을 탐색하세요."}
              </p>
            </div>
            <span className="date">
              {new Date().toLocaleDateString("ko-KR", {
                year: "numeric",
                month: "long",
                day: "numeric",
              })}
            </span>
          </div>
          {error && (
            <div className="alert" role="alert">
              {error}{" "}
              <span>갱신 실패 시 이전 데이터가 표시될 수 있습니다.</span>
            </div>
          )}
          {notice && (
            <div className="notice" role="status">
              {notice}
            </div>
          )}
          {view === "overview" && (
            <>
              <div className="metrics">
                {[
                  [
                    "현재 접속",
                    stats.active,
                    "상태 확인 불가 " + (stats.unknown || 0) + "개",
                  ],
                  ["오늘 접속", stats.logins, "브라우저 시간대 기준 세션 시작"],
                  [
                    "오늘 인증 실패 기록",
                    stats.failures,
                    "SSH·PAM 감사 이벤트 기준",
                  ],
                  [
                    "수집 정상",
                    `${stats.healthy || 0} / ${stats.total || 0}`,
                    "등록된 서버",
                  ],
                ].map(([title, n, sub]) => (
                  <section className="metric" key={title}>
                    <span>{title}</span>
                    <strong>{n ?? "—"}</strong>
                    <small>{sub}</small>
                  </section>
                ))}
              </div>
              {!servers.length && (
                <div className="onboarding">
                  <div>
                    <h2>첫 번째 서버를 연결하세요</h2>
                    <p>
                      서버를 등록하고 수집기를 설치하면 접속과 실행 기록이
                      여기에 표시됩니다.
                    </p>
                  </div>
                  <button
                    className="primary"
                    onClick={() => navigate("servers")}
                  >
                    서버 등록 →
                  </button>
                </div>
              )}
            </>
          )}
          {(view === "overview" ||
            view === "events" ||
            view === "sessions") && (
            <div className="filters">
              <label>
                서버
                <select
                  aria-label="서버"
                  value={server}
                  onChange={(e) => {
                    setServer(e.target.value);
                    setPage(0);
                  }}
                >
                  <option value="">전체 서버</option>
                  {servers.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.name}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                계정
                <input
                  placeholder="전체 계정"
                  value={account}
                  onChange={(e) => {
                    setAccount(e.target.value);
                    setPage(0);
                  }}
                />
              </label>
              <label>
                접속 IP
                <input
                  placeholder="전체 IP"
                  value={ip}
                  onChange={(e) => {
                    setIP(e.target.value);
                    setPage(0);
                  }}
                />
              </label>
              {view !== "sessions" && (
                <>
                  <label>
                    기간
                    <select
                      value={days}
                      onChange={(e) => {
                        setDays(e.target.value);
                        setPage(0);
                      }}
                    >
                      <option value="1">최근 24시간</option>
                      <option value="7">최근 7일</option>
                      <option value="30">최근 30일</option>
                      <option value="365">최근 365일</option>
                    </select>
                  </label>
                  <label>
                    활동
                    <select
                      value={kind}
                      onChange={(e) => {
                        setKind(e.target.value);
                        setPage(0);
                      }}
                    >
                      <option value="">전체 활동</option>
                      {[
                        "session_start",
                        "session_end",
                        "login_success",
                        "login_failure",
                        "exec",
                      ].map((k) => (
                        <option key={k} value={k}>
                          {labels[k]}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="grow">
                    명령 검색
                    <input
                      placeholder="프로그램 또는 인자 검색"
                      value={query}
                      onChange={(e) => {
                        setQuery(e.target.value);
                        setPage(0);
                      }}
                    />
                  </label>
                </>
              )}
            </div>
          )}
          {(view === "overview" || view === "sessions") && (
            <section className="panel">
              <div className="panel-head">
                <h2>
                  {view === "overview" ? "현재 접속 세션" : "접속 세션 기록"}
                </h2>
                <span className="muted">세션을 선택해 활동 확인</span>
              </div>
              {sessionTable(sessions)}
              {view === "sessions" && pager(sessions, page, setPage)}
            </section>
          )}
          {(view === "overview" || view === "events") && (
            <section className="panel">
              <div className="panel-head">
                <h2>{view === "overview" ? "최근 활동" : "활동 기록"}</h2>
                <span className="muted">프로그램 실행과 인자</span>
              </div>
              <ActivityControls
                mode={activityMode}
                summary={activitySummary}
                loading={loading}
                onChange={(mode) => {
                  setActivityMode(mode);
                  setPage(0);
                }}
              />
              {eventTable(rows)}
              {view === "events" && pager(rows, page, setPage)}
              <div className="panel-note">
                프로그램 실행은 시작 요청의 결과이며 종료 결과가 아닙니다. 셸
                내장 명령과 터미널 출력은 수집하지 않습니다. 연결 불명 실행은
                SSH 세션에서 발생했다고 확정할 수 없습니다.
              </div>
            </section>
          )}
          {view === "servers" && (
            <>
              <section className="panel">
                <div className="panel-head">
                  <h2>서버 등록</h2>
                  <span className="muted">
                    토큰은 발급 시 한 번만 표시됩니다.
                  </span>
                </div>
                <form
                  className="inline-form"
                  onSubmit={(e) => {
                    e.preventDefault();
                    action(async () => {
                      const x = await api("/servers", "POST", {
                        name: serverName,
                      });
                      setCredential({ ...x, name: serverName });
                      setServerName("");
                      setServers(await api("/servers"));
                    });
                  }}
                >
                  <label className="grow">
                    서버 이름
                    <input
                      placeholder="예: production-01"
                      value={serverName}
                      onChange={(e) => setServerName(e.target.value)}
                      maxLength={100}
                      required
                    />
                  </label>
                  <button className="primary" disabled={busy}>
                    서버 등록
                  </button>
                </form>
              </section>
              {credential && (
                <section className="panel token-panel">
                  <div className="panel-head">
                    <h2>{credential.name || "서버"} 수집기 연결</h2>
                    <button onClick={() => setCredential(null)}>닫기</button>
                  </div>
                  <p>
                    Ubuntu 24.04 x86_64 또는 ARM64 대상 서버에서 아래 명령을 실행하세요.
                    중앙 서버 주소와 토큰은 설치 중 입력합니다.
                  </p>
                  <pre>
                    bash &lt;(curl -fsSL
                    https://raw.githubusercontent.com/isac7722/ssh-logger/main/install.sh)
                  </pre>
                  <label>
                    중앙 서버 주소
                    <input readOnly value={location.origin} />
                  </label>
                  <label>
                    발급 토큰
                    <input
                      readOnly
                      value={credential.token}
                      onFocus={(e) => e.target.select()}
                    />
                  </label>
                  <small>
                    원격 서버에서는 접근 가능한 HTTPS 주소를 사용하세요.
                    설치·감사 규칙 설정은 README의 수집기 설치 절차를 따르세요.
                  </small>
                </section>
              )}
              <section className="panel">
                <div className="panel-head">
                  <h2>등록된 서버</h2>
                  <span>{servers.length}대</span>
                </div>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>서버</th>
                        <th>수집 상태</th>
                        <th>마지막 수신</th>
                        <th>전송 대기 / 손실·공백</th>
                        <th>인증 관리</th>
                      </tr>
                    </thead>
                    <tbody>
                      {servers.map((s) => (
                        <tr key={s.id}>
                          <td>
                            <strong>{s.name}</strong>
                          </td>
                          <td>
                            <span
                              className={
                                "badge " +
                                (health(s) === "정상" ? "good" : "warn")
                              }
                            >
                              {health(s)}
                            </span>
                          </td>
                          <td>{fmt(s.last_seen)}</td>
                          <td>
                            {s.backlog} / {s.dropped}
                          </td>
                          <td className="actions">
                            <button
                              disabled={busy}
                              onClick={() => {
                                if (
                                  confirm(
                                    "기존 토큰은 즉시 무효화됩니다. 새 토큰을 발급할까요?",
                                  )
                                )
                                  action(async () => {
                                    setCredential({
                                      ...(await api(
                                        "/servers/" + s.id + "/rotate",
                                        "POST",
                                      )),
                                      name: s.name,
                                    });
                                    setServers(await api("/servers"));
                                  });
                              }}
                            >
                              토큰 재발급
                            </button>
                            <button
                              className="danger"
                              disabled={busy || !!s.revoked}
                              onClick={() => {
                                if (
                                  confirm(
                                    "이 서버를 폐기할까요? 수집을 차단하고 서버와 관련 기록을 화면에서 숨깁니다. DB 기록은 보관 기간에 따라 유지됩니다.",
                                  )
                                )
                                  action(async () => {
                                    await api(
                                      "/servers/" + s.id + "/revoke",
                                      "POST",
                                    );
                                    setCredential((current) =>
                                      current?.id === s.id ? null : current,
                                    );
                                    if (server === s.id) setServer("");
                                    setSelected((current) =>
                                      current?.server_id === s.id
                                        ? null
                                        : current,
                                    );
                                    setRows((current) =>
                                      current.filter(
                                        (row) => row.server_id !== s.id,
                                      ),
                                    );
                                    setSessions((current) =>
                                      current.filter(
                                        (row) => row.server_id !== s.id,
                                      ),
                                    );
                                    setServers(await api("/servers"));
                                    setStats(
                                      (
                                        await api(
                                          "/overview?day_start=" + localDay(),
                                        )
                                      )[0] || {},
                                    );
                                    setNotice(
                                      "서버를 폐기했습니다. 관련 기록은 보관 기간에 따라 DB에 유지됩니다.",
                                    );
                                  });
                              }}
                            >
                              폐기
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {!servers.length && (
                    <div className="empty">아직 등록된 서버가 없습니다.</div>
                  )}
                </div>
              </section>
            </>
          )}
          {view === "accounts" && (
            <AccountSettings
              username={user}
              api={api}
              onPasswordChanged={() => {
                csrf = "";
                setAuth(false);
                setCredential(null);
                setPassword("");
                setError("");
                setNotice(
                  "비밀번호를 변경했습니다. 새 비밀번호로 다시 로그인하세요.",
                );
              }}
            />
          )}
          {view === "settings" && (
            <section className="panel settings">
              <h2>기록 보관 기간</h2>
              <p>
                설정한 기간이 지난 활동 기록은 자동으로 삭제됩니다. 보관 기간을
                줄이면 이전 기록이 삭제될 수 있습니다.
              </p>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  if (
                    confirm(
                      `${retention}일 이전 기록을 자동 삭제하도록 저장할까요?`,
                    )
                  )
                    action(async () => {
                      await api("/settings", "PUT", {
                        retention_days: retention,
                      });
                      setNotice("보관 기간을 저장했습니다.");
                    });
                }}
              >
                <label>
                  보관 기간 (일)
                  <input
                    type="number"
                    min={1}
                    max={365}
                    value={retention}
                    onChange={(e) => setRetention(Number(e.target.value))}
                    required
                  />
                </label>
                <button className="primary" disabled={busy}>
                  설정 저장
                </button>
              </form>
              <hr />
              <h2>백업과 복원</h2>
              <p>
                관리 서버에서 <code>make backup</code>으로 일관성 있는 백업
                파일을 만드세요. 복원 절차는 README에 안내되어 있습니다.
              </p>
            </section>
          )}
          <footer>
            SSH LOGGER{" "}
            <span>접속 기록은 개인별 SSH 계정을 기준으로 확인하세요.</span>
          </footer>
        </div>
      </main>
      {selected && (
        <div className="modal-backdrop" onClick={() => setSelected(null)}>
          <section
            className="modal"
            role="dialog"
            aria-modal="true"
            aria-label="세션 상세"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="panel-head">
              <h2>세션 상세</h2>
              <button autoFocus onClick={() => setSelected(null)}>
                닫기 ✕
              </button>
            </div>
            <div className="session-info">
              <strong>
                {selected.server_name} / {selected.user}
              </strong>
              <span>{selected.ip || "IP 없음"}</span>
              <span>
                {fmt(selected.started)} → {fmt(selected.ended)}
              </span>
            </div>
            {detailError && <div className="alert">{detailError}</div>}
            <ActivityControls
              mode={detailMode}
              summary={detailSummary}
              loading={detailLoading}
              onChange={(mode) => {
                setDetailMode(mode);
                setDetailPage(0);
              }}
            />
            {eventTable(detail)}
            {pager(detail, detailPage, setDetailPage)}
          </section>
        </div>
      )}
    </div>
  );
}

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
