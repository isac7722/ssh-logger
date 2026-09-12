import { useEffect, useState } from "react";
type Row = Record<string, any>;
type Props = {
  api: (path: string, method?: string, body?: unknown) => Promise<any>;
  servers: Row[];
  superAdmin: boolean;
  initial?: { server: string; ip: string };
};
const fmt = (v: number) => (v ? new Date(v).toLocaleString("ko-KR") : "—");
export function Firewall({ api, servers, superAdmin, initial }: Props) {
  const [server, setServer] = useState(initial?.server || "");
  const [ip, setIP] = useState(initial?.ip || "");
  const [disconnect, setDisconnect] = useState(false);
  const [data, setData] = useState<Row | null>(null),
    [ports, setPorts] = useState("22"),
    [protectedIPs, setProtected] = useState("");
  const [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [notice, setNotice] = useState(""),
    [page, setPage] = useState(0),
    [refresh, setRefresh] = useState(0);
  const host = servers.find((s) => s.id === server);
  useEffect(() => {
    setData(null);
    setPage(0);
    setNotice("");
    setError("");
  }, [server]);
  useEffect(() => {
    if (!server || !host) {
      setData(null);
      return;
    }
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    const tick = async () => {
      try {
        const x = await api(`/servers/${server}/firewall?page=${page}`);
        if (alive) {
          setData(x);
          setError("");
        }
      } catch (e) {
        if (alive) {
          setData(null);
          setError((e as Error).message);
        }
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
  useEffect(() => {
    if (data) {
      setPorts(data.policy.ports.join(", "));
      setProtected(data.policy.protected.join("\n"));
    }
  }, [server, data?.policy.revision]);
  async function change(path: string, method: string, body?: unknown) {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await api(`/servers/${server}${path}`, method, body);
      setNotice("요청을 저장했습니다. 에이전트 적용 결과를 기다리고 있습니다.");
      setRefresh((v) => v + 1);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  const state = data?.state[0];
  const online = host && Date.now() - host.last_seen < 60000;
  const applied =
    online &&
    state?.capable &&
    state?.applied_revision === data?.policy.revision &&
    !state?.error;
  const status = !online
    ? "연결 끊김 · 적용 상태 확인 불가"
    : !state?.capable
      ? "에이전트 업데이트 또는 nftables 설치 필요"
      : state.error
        ? "적용 실패"
        : applied
          ? "적용 완료"
          : "적용 대기";
  return (
    <div>
      <section className="panel">
        <h2>IP 차단 관리</h2>
        <p>
          선택한 서버의 SSH 포트에만 적용됩니다. 차단 해제는 SSH Logger가 만든
          규칙을 제거합니다.
        </p>
        <label>
          대상 서버
          <select
            aria-label="대상 서버"
            value={server}
            onChange={(e) => setServer(e.target.value)}
          >
            <option value="">서버 선택</option>
            {servers.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          </select>
        </label>
      </section>
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
      {data && host && (
        <>
          <section className="panel">
            <div className="panel-head">
              <h2>{host.name} · SSH IP 차단</h2>
              <span className={"badge " + (applied ? "good" : "warn")}>
                {status}
              </span>
            </div>
            {state?.error && <p role="alert">{state.error}</p>}
            <p>
              마지막 적용 결과: {fmt(state?.reported)} · SSH 포트:{" "}
              {data.policy.ports.join(", ")}
            </p>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                if (
                  confirm(
                    `${host.name}에서 ${ip.trim()}의 SSH 접속을 차단할까요?\n${disconnect ? "기존 SSH 연결의 트래픽도 차단됩니다. 원격 접속을 잃을 수 있습니다." : "기존 연결은 유지하고 새 연결을 차단합니다."}`,
                  )
                )
                  change("/bans", "POST", { ip: ip.trim(), disconnect });
              }}
            >
              <label>
                차단할 IP
                <input
                  required
                  value={ip}
                  onChange={(e) => setIP(e.target.value)}
                  placeholder="203.0.113.10 또는 2001:db8::10"
                />
              </label>
              <label className="check-label">
                <input
                  type="checkbox"
                  checked={disconnect}
                  onChange={(e) => setDisconnect(e.target.checked)}
                />
                기존 SSH 연결도 차단
              </label>
              <small>
                이 옵션은 기존 연결의 패킷도 차단합니다. 서버에서 실행 중인
                프로세스 종료는 세션 종료 기능을 사용하세요.
              </small>
              <button className="danger" disabled={busy}>
                IP 차단
              </button>
            </form>
          </section>
          <section className="panel">
            <h2>차단 목록 ({data.policy.bans.length})</h2>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>IP</th>
                    <th>범위</th>
                    <th>상태</th>
                    <th>관리</th>
                  </tr>
                </thead>
                <tbody>
                  {data.policy.bans.map((b: Row) => (
                    <tr key={b.ip}>
                      <td>{b.ip}</td>
                      <td>{b.disconnect ? "기존 + 새 연결" : "새 연결"}</td>
                      <td>{applied ? "차단됨" : status}</td>
                      <td>
                        <button
                          disabled={busy}
                          onClick={() => {
                            if (
                              confirm(
                                `${host.name}에서 ${b.ip}의 차단을 해제할까요?`,
                              )
                            )
                              change(
                                `/bans/${encodeURIComponent(b.ip)}`,
                                "DELETE",
                              );
                          }}
                        >
                          차단 해제
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!data.policy.bans.length && (
                <p className="empty">등록된 차단 IP가 없습니다.</p>
              )}
            </div>
          </section>
          <section className="panel">
            <h2>SSH 포트 · 보호 IP</h2>
            <p>
              보호 IP는 차단할 수 없습니다. 이미 차단 중인 IP는 먼저 차단 해제한
              뒤 등록하세요.
            </p>
            {superAdmin ? (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  if (
                    confirm(
                      `${host.name}의 SSH 포트와 보호 IP 설정을 저장할까요?`,
                    )
                  )
                    change("/firewall/settings", "PUT", {
                      ports: ports
                        .split(/[\s,]+/)
                        .filter(Boolean)
                        .map(Number),
                      protected: protectedIPs.split(/[\s,]+/).filter(Boolean),
                    });
                }}
              >
                <label>
                  SSH 포트 (쉼표로 구분)
                  <input
                    required
                    value={ports}
                    onChange={(e) => setPorts(e.target.value)}
                  />
                </label>
                <label>
                  보호할 관리 IP (줄바꿈 또는 쉼표로 구분)
                  <textarea
                    value={protectedIPs}
                    onChange={(e) => setProtected(e.target.value)}
                    rows={4}
                  />
                </label>
                <button disabled={busy} className="primary">
                  방화벽 설정 저장
                </button>
              </form>
            ) : (
              <p>
                보호 IP: {data.policy.protected.join(", ") || "없음"} · 설정은
                super admin이 관리합니다.
              </p>
            )}
          </section>
          <section className="panel">
            <h2>차단 · 해제 · 설정 이력</h2>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>시각</th>
                    <th>요청자</th>
                    <th>작업</th>
                    <th>IP</th>
                    <th>결과</th>
                  </tr>
                </thead>
                <tbody>
                  {data.history.slice(0, 50).map((h: Row) => (
                    <tr key={h.id}>
                      <td>{fmt(h.created)}</td>
                      <td>{h.requested_by}</td>
                      <td>
                        {
                          {
                            ban: "차단",
                            unban: "차단 해제",
                            settings: "설정 변경",
                          }[h.action as string]
                        }
                      </td>
                      <td>{h.ip || "—"}</td>
                      <td>
                        {
                          {
                            pending: "적용 대기",
                            succeeded: "적용 완료",
                            failed: "실패",
                            superseded: "후속 정책으로 대체",
                          }[h.status as string]
                        }
                        {h.error && <small>{h.error}</small>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="actions">
              <button disabled={!page} onClick={() => setPage((p) => p - 1)}>
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
          </section>
        </>
      )}
    </div>
  );
}
