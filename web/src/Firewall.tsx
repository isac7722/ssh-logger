import { useEffect, useRef, useState } from "react";
import { Dialog, EmptyState, Icon } from "./UI";
type Row = Record<string, any>;
type Props = {
  api: (path: string, method?: string, body?: unknown) => Promise<any>;
  servers: Row[];
  superAdmin: boolean;
  initial?: { server: string; ip: string };
};
type Tab = "allowed" | "history" | "settings";
type Pending = {
  title: string;
  path: string;
  method: string;
  body?: unknown;
  ip?: string;
  detail: string;
};
const tabs: { id: Tab; label: string }[] = [
  { id: "allowed", label: "허용 IP" },
  { id: "history", label: "변경 이력" },
  { id: "settings", label: "방화벽 설정" },
];
const fmt = (v: number) => (v ? new Date(v).toLocaleString("ko-KR") : "—");
export function Firewall({ api, servers, superAdmin, initial }: Props) {
  const [server, setServer] = useState(initial?.server || "");
  const [ip, setIP] = useState(initial?.ip || "");

  const [data, setData] = useState<Row | null>(null);
  const [ports, setPorts] = useState("22");
  const [mode, setMode] = useState("off");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [fetchError, setFetchError] = useState("");
  const [notice, setNotice] = useState("");
  const [page, setPage] = useState(0);
  const [refresh, setRefresh] = useState(0);
  const [tab, setTab] = useState<Tab>("allowed");
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
            setMode(x.policy.mode || (x.policy.bans.length ? "legacy" : "off"));
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

    setIP("");
    setPorts("22");
    setMode("off");
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
    (data?.policy.mode !== "allowlist" || state.capable >= 2) &&
    state?.applied_revision === data?.policy.revision &&
    !state?.error;
  const status = fetchError
    ? "상태 확인 불가"
    : !online
      ? "연결 끊김"
      : !state?.capable ||
          (data?.policy.mode === "allowlist" && state.capable < 2)
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
  const allowed: string[] = data?.policy.allowed || [];
  const enabled = data?.policy.mode === "allowlist";
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
            onChange={(event) => selectServer(event.target.value)}
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
              ? "서버를 선택하면 SSH 허용 IP와 적용 상태를 확인할 수 있습니다."
              : superAdmin
                ? "서버 관리에서 서버를 먼저 등록하세요."
                : "관리자에게 서버 배정을 요청하세요."}
          </EmptyState>
        </section>
      ) : !data ? (
        !fetchError && (
          <div className="panel loading-state" role="status">
            접근 정책을 불러오는 중…
          </div>
        )
      ) : (
        <>
          {state?.capable < 2 || !state ? (
            <div className="form-callout">
              화이트리스트를 사용하려면 이 서버의 에이전트를 업데이트하고
              nftables를 설치하세요. 허용 IP는 미리 등록할 수 있습니다.
            </div>
          ) : null}
          {state?.error && !awaitingPolicy && (
            <div className="alert" role="alert">
              접근 정책 적용 실패: {state.error}
            </div>
          )}
          <div className="form-callout access-policy-summary">
            <strong>
              {enabled ? "화이트리스트 사용 중" : "화이트리스트 꺼짐"}
            </strong>
            <p>
              {enabled
                ? "허용 IP만 새 SSH 연결을 시작할 수 있습니다. 이미 연결된 세션은 유지합니다."
                : "허용 IP를 등록한 뒤 방화벽 설정에서 화이트리스트를 켜세요. 등록만으로는 접속을 제한하지 않습니다."}
            </p>
          </div>
          {!data.policy.mode && data.policy.bans.length > 0 && (
            <details className="form-callout legacy-policy">
              <summary>
                기존 차단 규칙 {data.policy.bans.length}개 유지 중
              </summary>
              <p>
                화이트리스트를 켜거나 접근 제어를 끄면 기존 차단 규칙을
                대체합니다. 기존 차단 IP는 허용 목록으로 옮기지 않습니다.
              </p>
              <ul>
                {data.policy.bans.map((ban: Row) => (
                  <li key={ban.ip}>
                    <span className="numeric">{ban.ip}</span> ·{" "}
                    {ban.disconnect ? "기존 + 새 연결 차단" : "새 연결 차단"}
                  </li>
                ))}
              </ul>
              {data.policy.protected.length > 0 && (
                <p>
                  기존 보호 IP: {data.policy.protected.join(", ")}. 전환 후에도
                  허용하려면 허용 목록에 직접 등록하세요.
                </p>
              )}
            </details>
          )}
          <div
            className="management-tabs"
            role="tablist"
            aria-label="SSH 접근 관리"
          >
            {tabs.map((item, index) => (
              <button
                key={item.id}
                id={`firewall-tab-${item.id}`}
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
                {item.id === "allowed" && (
                  <span className="count-pill">{allowed.length}</span>
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
            {tab === "allowed" && (
              <>
                <section className="panel panel-body">
                  <div className="section-intro">
                    <span className="section-icon">
                      <Icon name="firewall" />
                    </span>
                    <div>
                      <h2>허용 IP 추가</h2>
                      <p>{host.name}의 SSH에 접속할 IP를 등록합니다.</p>
                    </div>
                  </div>
                  <form
                    className="ban-form stack-form"
                    onSubmit={(event) => {
                      event.preventDefault();
                      confirmAction({
                        title: "허용 IP 추가 확인",
                        path: "/allowlist",
                        method: "POST",
                        ip: ip.trim(),
                        body: { ip: ip.trim() },
                        detail: enabled
                          ? "이 IP에서 새 SSH 연결을 시작할 수 있도록 허용합니다. 다른 방화벽과 SSH 인증 설정은 유지됩니다."
                          : "허용 목록에 IP를 등록합니다. 접속을 제한하려면 방화벽 설정에서 화이트리스트를 켜세요.",
                      });
                    }}
                  >
                    <div className="ban-input-row">
                      <label>
                        허용할 IP
                        <input
                          required
                          value={ip}
                          onChange={(event) => setIP(event.target.value)}
                          placeholder="203.0.113.10 또는 2001:db8::10"
                          disabled={controlsDisabled}
                          autoComplete="off"
                          spellCheck={false}
                          aria-describedby="allowed-ip-hint"
                        />
                      </label>
                      <button className="primary" disabled={controlsDisabled}>
                        <Icon name="plus" />
                        IP 추가
                      </button>
                    </div>
                    <small id="allowed-ip-hint">
                      IPv4 또는 IPv6 단일 주소를 입력하세요. 서버에서 실제로
                      보이는 접속 출발지 IP를 등록해야 합니다.
                    </small>
                  </form>
                </section>
                <section className="panel">
                  <div className="panel-head">
                    <h2>
                      등록된 허용 IP{" "}
                      <span className="count-pill">{allowed.length}</span>
                    </h2>
                    <span className="section-meta">
                      SSH 포트 {data.policy.ports.join(", ")}
                    </span>
                  </div>
                  {allowed.length ? (
                    <div className="table-wrap">
                      <table className="management-table">
                        <thead>
                          <tr>
                            <th scope="col">IP</th>
                            <th scope="col">상태</th>
                            <th scope="col" className="action-cell">
                              관리
                            </th>
                          </tr>
                        </thead>
                        <tbody>
                          {allowed.map((address) => (
                            <tr key={address}>
                              <td className="numeric">{address}</td>
                              <td>
                                <span
                                  className={`status-pill ${enabled ? tone : "warning"}`}
                                >
                                  {!enabled
                                    ? "등록됨 · 정책 꺼짐"
                                    : applied && !fetchError
                                      ? "허용됨"
                                      : status}
                                </span>
                              </td>
                              <td className="action-cell">
                                <button
                                  className="danger"
                                  disabled={
                                    controlsDisabled ||
                                    (enabled && allowed.length === 1)
                                  }
                                  aria-describedby={
                                    enabled && allowed.length === 1
                                      ? "last-allowed-hint"
                                      : undefined
                                  }
                                  onClick={() =>
                                    confirmAction({
                                      title: "허용 IP 삭제 확인",
                                      path: `/allowlist/${encodeURIComponent(address)}`,
                                      method: "DELETE",
                                      ip: address,
                                      detail: enabled
                                        ? "이 IP의 새 SSH 연결이 제한됩니다. 이미 연결된 SSH 세션은 유지됩니다."
                                        : "허용 목록에서 IP를 삭제합니다. 화이트리스트가 꺼져 있으므로 현재 접속에는 영향을 주지 않습니다.",
                                    })
                                  }
                                >
                                  삭제
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
                      title="등록된 허용 IP가 없습니다."
                    >
                      관리자와 필요한 사용자의 IP를 먼저 등록하세요.
                    </EmptyState>
                  )}
                  <div className="panel-footnote" id="last-allowed-hint">
                    {enabled && allowed.length === 1
                      ? "마지막 허용 IP입니다. 다른 IP를 추가하거나 화이트리스트를 끈 뒤 삭제할 수 있습니다."
                      : "허용 목록을 변경해도 이미 연결된 SSH 세션은 유지합니다."}
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
                    <h2>화이트리스트 설정</h2>
                    <p>
                      지정한 SSH 포트의 새 연결에만 적용합니다. 다른 서비스
                      포트는 변경하지 않습니다.
                    </p>
                  </div>
                </div>
                {superAdmin ? (
                  <form
                    className="stack-form settings-form"
                    onSubmit={(event) => {
                      event.preventDefault();
                      confirmAction({
                        title: "접근 정책 변경 확인",
                        path: "/firewall/settings",
                        method: "PUT",
                        body: {
                          ports: ports
                            .split(/[\s,]+/)
                            .filter(Boolean)
                            .map(Number),
                          ...(mode === "legacy" ? {} : { mode }),
                        },
                        detail: `SSH 포트: ${ports}\n${mode === "allowlist" ? `허용 IP: ${allowed.join(", ")}\n목록에 없는 IP의 새 SSH 연결을 제한합니다. 기존 연결은 유지합니다. 관리에 사용할 IP가 포함되어 있는지 확인하세요.` : mode === "legacy" ? "기존 차단 규칙을 유지합니다." : "이 도구가 관리하는 SSH 접근 제한을 해제합니다. 다른 방화벽의 규칙은 유지됩니다."}${data.policy.bans.length && mode !== "legacy" ? "\n기존 차단 규칙은 이 정책으로 대체됩니다." : ""}`,
                      });
                    }}
                  >
                    <label>
                      접근 정책
                      <select
                        aria-label="접근 정책"
                        value={mode}
                        disabled={controlsDisabled}
                        onChange={(event) => {
                          dirty.current = true;
                          setMode(event.target.value);
                        }}
                        aria-describedby="policy-hint"
                      >
                        {!data.policy.mode && data.policy.bans.length > 0 && (
                          <option value="legacy">기존 차단 정책 유지</option>
                        )}
                        <option value="off">
                          꺼짐 · 이 도구의 접근 제한 해제
                        </option>
                        <option
                          value="allowlist"
                          disabled={
                            state?.capable < 2 || !state || !allowed.length
                          }
                        >
                          화이트리스트 · 허용 IP만 접속
                        </option>
                      </select>
                      <small id="policy-hint">
                        허용 IP를 1개 이상 등록하고 에이전트 업데이트를 완료해야
                        켤 수 있습니다.
                      </small>
                    </label>
                    <label>
                      SSH 포트 (쉼표로 구분)
                      <input
                        aria-label="SSH 포트 (쉼표로 구분)"
                        required
                        value={ports}
                        disabled={controlsDisabled}
                        onChange={(event) => {
                          dirty.current = true;
                          setPorts(event.target.value);
                        }}
                        aria-describedby="ports-hint"
                      />
                      <small id="ports-hint">
                        예: 22, 2222. 실제 SSH 서비스가 사용하는 포트를
                        지정하세요.
                      </small>
                    </label>
                    <div className="form-callout">
                      <strong>기존 SSH 연결 유지</strong>
                      <p>
                        화이트리스트를 켜거나 IP를 삭제해도 기존 세션은
                        유지합니다. 필요한 경우 접속 세션 화면에서 별도로 종료할
                        수 있습니다.
                      </p>
                    </div>
                    <div className="form-footer">
                      <button
                        className="primary"
                        disabled={
                          controlsDisabled ||
                          (mode === "allowlist" &&
                            (!allowed.length || !state || state.capable < 2))
                        }
                      >
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
                        <dt>접근 정책</dt>
                        <dd>
                          {enabled
                            ? "화이트리스트"
                            : data.policy.bans.length
                              ? "기존 차단 정책"
                              : "꺼짐"}
                        </dd>
                      </div>
                      <div>
                        <dt>SSH 포트</dt>
                        <dd>{data.policy.ports.join(", ")}</dd>
                      </div>
                    </dl>
                    <div className="form-callout">
                      <Icon name="lock" />
                      화이트리스트 활성화와 포트 설정은 최고 관리자가 변경할 수
                      있습니다.
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
                      허용 IP와 접근 정책의 변경 결과를 확인합니다.
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
                                allow: "허용 IP 추가",
                                remove_allow: "허용 IP 삭제",
                                ban: "IP 차단 (이전)",
                                unban: "차단 해제 (이전)",
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
                    허용 IP나 접근 정책을 변경하면 이곳에 기록됩니다.
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
            <div className="form-callout">{pending.detail}</div>
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
                  pending.method === "DELETE" ? "danger-solid" : "primary"
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
