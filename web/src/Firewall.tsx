import { useEffect, useRef, useState } from "react";
import { Dialog, EmptyState, Icon } from "./UI";
type Row = Record<string, any>;
type Props = {
  api: (path: string, method?: string, body?: unknown) => Promise<any>;
  servers: Row[];
  superAdmin: boolean;
  initial?: { server: string; ip: string };
};
type Tab = "bans" | "history" | "settings";
type Pending = {
  title: string;
  path: string;
  method: string;
  body?: unknown;
  ip?: string;
  detail: string;
};
const tabs: { id: Tab; label: string }[] = [
  { id: "bans", label: "차단 목록" },
  { id: "history", label: "변경 이력" },
  { id: "settings", label: "방화벽 설정" },
];
const fmt = (v: number) => (v ? new Date(v).toLocaleString("ko-KR") : "—");
export function Firewall({ api, servers, superAdmin, initial }: Props) {
  const [server, setServer] = useState(initial?.server || "");
  const [ip, setIP] = useState(initial?.ip || "");
  const [disconnect, setDisconnect] = useState(false);
  const [data, setData] = useState<Row | null>(null);
  const [ports, setPorts] = useState("22");
  const [protectedIPs, setProtected] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [fetchError, setFetchError] = useState("");
  const [notice, setNotice] = useState("");
  const [page, setPage] = useState(0);
  const [refresh, setRefresh] = useState(0);
  const [tab, setTab] = useState<Tab>("bans");
  const [pending, setPending] = useState<Pending | null>(null);
  const [awaitingPolicy, setAwaitingPolicy] = useState(false);
  const dirty = useRef(false);
  const mutationVersion = useRef(0);
  const host = servers.find((s) => s.id === server);
  useEffect(() => {
    if (!server || !host) return;
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    const tick = async () => {
      try {
        const version = mutationVersion.current;
        const x = await api(`/servers/${server}/firewall?page=${page}`);
        if (alive) {
          // Ignore an in-flight poll from before the most recent mutation.
          if (version !== mutationVersion.current) return;
          setAwaitingPolicy(false);
          setData(x);
          setFetchError("");
          if (!dirty.current) {
            setPorts(x.policy.ports.join(", "));
            setProtected(x.policy.protected.join("\n"));
          }
        }
      } catch (e) {
        if (alive) setFetchError((e as Error).message);
      } finally {
        if (alive) timer = setTimeout(tick, 5000);
      }
    };
    tick();
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [api, server, !!host, page, refresh]);
  function selectServer(value: string) {
    setServer(value);
    setData(null);
    setPage(0);
    setNotice("");
    setError("");
    setFetchError("");
    setPending(null);
    setDisconnect(false);
    setIP("");
    setPorts("22");
    setProtected("");
    dirty.current = false;
    mutationVersion.current += 1;
    setAwaitingPolicy(false);
  }
  function confirmAction(next: Pending) {
    setError("");
    setPending(next);
  }
  async function change() {
    if (!pending || busy) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await api(
        `/servers/${server}${pending.path}`,
        pending.method,
        pending.body,
      );
      mutationVersion.current += 1;
      setAwaitingPolicy(true);
      if (pending.path === "/firewall/settings") dirty.current = false;
      if (pending.method === "POST") {
        setIP("");
        setDisconnect(false);
      }
      setPending(null);
      setNotice("요청을 저장했습니다.");
      setRefresh((value) => value + 1);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  const state = data?.state[0];
  const online = host && Date.now() - host.last_seen < 60000;
  const applied =
    !awaitingPolicy &&
    online &&
    state?.capable &&
    state?.applied_revision === data?.policy.revision &&
    !state?.error;
  const status = fetchError
    ? "상태 확인 불가"
    : !online
      ? "연결 끊김"
      : !state?.capable
        ? "에이전트 확인 필요"
        : awaitingPolicy
          ? "적용 대기"
          : state.error
            ? "적용 실패"
            : applied
              ? "적용 완료"
              : "적용 대기";
  const tone =
    fetchError || state?.error ? "error" : applied ? "success" : "warning";
  const controlsDisabled = busy || awaitingPolicy || !!fetchError;
  return (
    <div className="firewall-page management-page">
      <section className="server-toolbar">
        <label>
          대상 서버
          <select
            aria-label="대상 서버"
            value={server}
            disabled={busy}
            onChange={(e) => selectServer(e.target.value)}
          >
            <option value="">서버 선택</option>
            {servers.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          </select>
        </label>
        {data && host && (
          <div className="server-status">
            <span className={`status-pill ${tone}`}>{status}</span>
            <small>마지막 적용 보고 {fmt(state?.reported)}</small>
          </div>
        )}
      </section>
      {fetchError && (
        <div className="alert" role="alert">
          {fetchError} · 최신 상태를 확인할 수 없습니다.
          <button onClick={() => setRefresh((value) => value + 1)}>
            다시 시도
          </button>
        </div>
      )}
      {notice && (
        <div className="notice" role="status">
          {notice} <strong>{status}</strong>
        </div>
      )}
      {!host ? (
        <section className="panel">
          <EmptyState
            icon="servers"
            title={
              servers.length
                ? "관리할 서버를 선택하세요."
                : "접근 가능한 서버가 없습니다."
            }
          >
            {servers.length
              ? "서버를 선택하면 차단된 IP와 방화벽 적용 상태를 확인할 수 있습니다."
              : superAdmin
                ? "서버 관리에서 서버를 먼저 등록하세요."
                : "관리자에게 서버 배정을 요청하세요."}
          </EmptyState>
        </section>
      ) : !data ? (
        !fetchError && (
          <div className="panel loading-state" role="status">
            방화벽 정보를 불러오는 중…
          </div>
        )
      ) : (
        <>
          {!state?.capable && (
            <div className="form-callout">
              이 서버에서 IP 차단을 적용하려면 에이전트 업데이트와 nftables
              설치가 필요합니다.
            </div>
          )}
          {state?.error && !awaitingPolicy && (
            <div className="alert" role="alert">
              방화벽 적용 실패: {state.error}
            </div>
          )}
          <div
            className="management-tabs"
            role="tablist"
            aria-label="방화벽 관리"
          >
            {tabs.map((item, index) => (
              <button
                key={item.id}
                id={`firewall-tab-${item.id}`}
                type="button"
                role="tab"
                aria-selected={tab === item.id}
                aria-controls="firewall-panel"
                tabIndex={tab === item.id ? 0 : -1}
                onClick={() => setTab(item.id)}
                onKeyDown={(event) => {
                  let next = index;
                  if (event.key === "ArrowRight")
                    next = (index + 1) % tabs.length;
                  else if (event.key === "ArrowLeft")
                    next = (index + tabs.length - 1) % tabs.length;
                  else if (event.key === "Home") next = 0;
                  else if (event.key === "End") next = tabs.length - 1;
                  else return;
                  event.preventDefault();
                  setTab(tabs[next].id);
                  document
                    .getElementById(`firewall-tab-${tabs[next].id}`)
                    ?.focus();
                }}
              >
                {item.label}
                {item.id === "bans" && (
                  <span className="count-pill">{data.policy.bans.length}</span>
                )}
              </button>
            ))}
          </div>
          <div
            id="firewall-panel"
            role="tabpanel"
            aria-labelledby={`firewall-tab-${tab}`}
            tabIndex={0}
          >
            {tab === "bans" && (
              <>
                <section className="panel panel-body">
                  <div className="section-intro">
                    <span className="section-icon">
                      <Icon name="firewall" />
                    </span>
                    <div>
                      <h2>IP 차단 추가</h2>
                      <p>
                        {host.name}의 SSH 포트{" "}
                        <span className="numeric">
                          {data.policy.ports.join(", ")}
                        </span>
                        에 적용됩니다.
                      </p>
                    </div>
                  </div>
                  <form
                    className="ban-form stack-form"
                    onSubmit={(event) => {
                      event.preventDefault();
                      confirmAction({
                        title: "IP 차단 확인",
                        path: "/bans",
                        method: "POST",
                        ip: ip.trim(),
                        body: { ip: ip.trim(), disconnect },
                        detail: disconnect
                          ? "기존 SSH 연결의 트래픽도 차단됩니다. 이 IP로 접속 중이라면 원격 접속을 잃을 수 있습니다."
                          : "기존 SSH 연결은 유지하고, 이 IP의 새 SSH 연결을 차단합니다.",
                      });
                    }}
                  >
                    <div className="ban-input-row">
                      <label>
                        차단할 IP
                        <input
                          required
                          value={ip}
                          onChange={(e) => setIP(e.target.value)}
                          placeholder="203.0.113.10 또는 2001:db8::10"
                          autoComplete="off"
                          spellCheck={false}
                          disabled={controlsDisabled}
                        />
                      </label>
                      <button
                        className="danger-solid"
                        disabled={controlsDisabled}
                      >
                        IP 차단
                      </button>
                    </div>
                    <div>
                      <label className="check-label">
                        <input
                          type="checkbox"
                          checked={disconnect}
                          onChange={(e) => setDisconnect(e.target.checked)}
                          disabled={controlsDisabled}
                          aria-describedby="disconnect-hint"
                        />
                        기존 SSH 연결도 차단
                      </label>
                      <small id="disconnect-hint" className="checkbox-hint">
                        {disconnect
                          ? "기존 연결의 패킷도 차단됩니다. 실행 중인 프로세스 종료는 세션 종료 기능을 사용하세요."
                          : "기본적으로 새 연결만 차단하며, 기존 SSH 연결은 유지합니다."}
                      </small>
                    </div>
                  </form>
                </section>
                <section className="panel">
                  <div className="panel-head">
                    <h2>
                      차단된 IP{" "}
                      <span className="count-pill">
                        {data.policy.bans.length}
                      </span>
                    </h2>
                    <span className="section-meta">{host.name}</span>
                  </div>
                  {data.policy.bans.length ? (
                    <div className="table-wrap">
                      <table className="management-table">
                        <thead>
                          <tr>
                            <th scope="col">IP</th>
                            <th scope="col">차단 범위</th>
                            <th scope="col">상태</th>
                            <th scope="col" className="action-cell">
                              관리
                            </th>
                          </tr>
                        </thead>
                        <tbody>
                          {data.policy.bans.map((ban: Row) => (
                            <tr key={ban.ip}>
                              <td className="numeric">{ban.ip}</td>
                              <td>
                                {ban.disconnect ? "기존 + 새 연결" : "새 연결"}
                              </td>
                              <td>
                                <span className={`status-pill ${tone}`}>
                                  {applied && !fetchError ? "차단됨" : status}
                                </span>
                              </td>
                              <td className="action-cell">
                                <button
                                  disabled={controlsDisabled}
                                  onClick={() =>
                                    confirmAction({
                                      title: "차단 해제 확인",
                                      path: `/bans/${encodeURIComponent(ban.ip)}`,
                                      method: "DELETE",
                                      ip: ban.ip,
                                      detail:
                                        "SSH Logger가 만든 이 IP의 차단 규칙을 제거합니다. 다른 방화벽 규칙은 유지됩니다.",
                                    })
                                  }
                                >
                                  차단 해제
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <EmptyState
                      icon="firewall"
                      title="등록된 차단 IP가 없습니다."
                    >
                      위에서 IP를 입력하면 이 서버의 SSH 접근을 차단합니다.
                    </EmptyState>
                  )}
                  <div className="panel-footnote">
                    차단 해제는 SSH Logger가 만든 규칙만 제거합니다.
                  </div>
                </section>
              </>
            )}
            {tab === "settings" && (
              <section className="panel panel-body">
                <div className="section-intro">
                  <span className="section-icon">
                    <Icon name="settings" />
                  </span>
                  <div>
                    <h2>SSH 포트 · 보호 IP</h2>
                    <p>
                      차단 규칙이 적용될 포트와 차단에서 보호할 관리 IP를
                      설정합니다.
                    </p>
                  </div>
                </div>
                {superAdmin ? (
                  <form
                    className="stack-form settings-form"
                    onSubmit={(event) => {
                      event.preventDefault();
                      confirmAction({
                        title: "방화벽 설정 확인",
                        path: "/firewall/settings",
                        method: "PUT",
                        body: {
                          ports: ports
                            .split(/[\s,]+/)
                            .filter(Boolean)
                            .map(Number),
                          protected: protectedIPs
                            .split(/[\s,]+/)
                            .filter(Boolean),
                        },
                        detail: `SSH 포트: ${ports}\n보호 IP: ${protectedIPs || "없음"}`,
                      });
                    }}
                  >
                    <label>
                      SSH 포트 (쉼표로 구분)
                      <input
                        required
                        aria-label="SSH 포트 (쉼표로 구분)"
                        value={ports}
                        disabled={controlsDisabled}
                        onChange={(e) => {
                          dirty.current = true;
                          setPorts(e.target.value);
                        }}
                        aria-describedby="ports-hint"
                      />
                      <small id="ports-hint">예: 22, 2222</small>
                    </label>
                    <label>
                      보호할 관리 IP (줄바꿈 또는 쉼표로 구분)
                      <textarea
                        aria-label="보호할 관리 IP (줄바꿈 또는 쉼표로 구분)"
                        value={protectedIPs}
                        disabled={controlsDisabled}
                        onChange={(e) => {
                          dirty.current = true;
                          setProtected(e.target.value);
                        }}
                        rows={4}
                        placeholder="예: 203.0.113.1"
                        aria-describedby="protected-hint"
                      />
                      <small id="protected-hint">
                        보호 IP는 차단할 수 없습니다. 이미 차단 중인 IP는 먼저
                        차단 해제한 뒤 등록하세요.
                      </small>
                    </label>
                    <div className="form-footer">
                      <button className="primary" disabled={controlsDisabled}>
                        방화벽 설정 저장
                      </button>
                      {dirty.current && (
                        <span className="section-meta">
                          저장하지 않은 변경사항
                        </span>
                      )}
                    </div>
                  </form>
                ) : (
                  <div className="settings-summary">
                    <dl>
                      <div>
                        <dt>SSH 포트</dt>
                        <dd>{data.policy.ports.join(", ")}</dd>
                      </div>
                      <div>
                        <dt>보호 IP</dt>
                        <dd>{data.policy.protected.join(", ") || "없음"}</dd>
                      </div>
                    </dl>
                    <div className="form-callout">
                      <Icon name="lock" />
                      방화벽 설정은 최고 관리자가 변경할 수 있습니다.
                    </div>
                  </div>
                )}
              </section>
            )}
            {tab === "history" && (
              <section className="panel">
                <div className="panel-head">
                  <div>
                    <h2>변경 이력</h2>
                    <p className="section-description">
                      IP 차단·해제와 설정 변경 결과를 확인합니다.
                    </p>
                  </div>
                </div>
                {data.history.length ? (
                  <div className="table-wrap">
                    <table className="management-table history-table">
                      <thead>
                        <tr>
                          <th scope="col">시각</th>
                          <th scope="col">요청자</th>
                          <th scope="col">작업</th>
                          <th scope="col">IP</th>
                          <th scope="col">결과</th>
                        </tr>
                      </thead>
                      <tbody>
                        {data.history.slice(0, 50).map((h: Row) => (
                          <tr key={h.id}>
                            <td className="numeric">{fmt(h.created)}</td>
                            <td>{h.requested_by}</td>
                            <td>
                              {{
                                ban: "차단",
                                unban: "차단 해제",
                                settings: "설정 변경",
                              }[h.action as string] || h.action}
                            </td>
                            <td className="numeric">{h.ip || "—"}</td>
                            <td>
                              <span
                                className={`status-pill ${h.status === "succeeded" ? "success" : h.status === "failed" ? "error" : "warning"}`}
                              >
                                {{
                                  pending: "적용 대기",
                                  succeeded: "적용 완료",
                                  failed: "실패",
                                  superseded: "후속 정책으로 대체",
                                }[h.status as string] || h.status}
                              </span>
                              {h.error && (
                                <small className="field-error">{h.error}</small>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <EmptyState icon="history" title="아직 변경 이력이 없습니다.">
                    차단·해제 또는 설정을 변경하면 이곳에 기록됩니다.
                  </EmptyState>
                )}
                {(page > 0 || data.history.length > 50) && (
                  <div className="table-pagination">
                    <button
                      disabled={!page}
                      onClick={() => setPage((p) => p - 1)}
                    >
                      이전
                    </button>
                    <span>{page + 1}페이지</span>
                    <button
                      disabled={data.history.length <= 50}
                      onClick={() => setPage((p) => p + 1)}
                    >
                      다음
                    </button>
                  </div>
                )}
              </section>
            )}
          </div>
        </>
      )}
      {pending && host && (
        <Dialog
          title={pending.title}
          description="적용할 서버와 변경 내용을 확인하세요."
          onClose={() => {
            setPending(null);
            setError("");
          }}
          busy={busy}
        >
          <div className="stack-form">
            <dl className="confirmation-summary">
              <div>
                <dt>대상 서버</dt>
                <dd>{host.name}</dd>
              </div>
              {pending.ip && (
                <div>
                  <dt>IP 주소</dt>
                  <dd className="numeric">{pending.ip}</dd>
                </div>
              )}
            </dl>
            <div
              className={
                pending.method === "POST"
                  ? "form-callout warning-callout"
                  : "form-callout"
              }
            >
              {pending.detail}
            </div>
            {error && (
              <div className="alert" role="alert">
                {error}
              </div>
            )}
            <div className="dialog-actions">
              <button
                disabled={busy}
                onClick={() => {
                  setPending(null);
                  setError("");
                }}
              >
                취소
              </button>
              <button
                className={
                  pending.method === "POST" ? "danger-solid" : "primary"
                }
                disabled={busy}
                onClick={change}
              >
                {busy ? "요청 중…" : "확인"}
              </button>
            </div>
          </div>
        </Dialog>
      )}
    </div>
  );
}
