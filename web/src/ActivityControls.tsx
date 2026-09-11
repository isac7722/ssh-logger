export type ActivityMode = "important" | "all" | "routine";
export type ActivitySummary = {
  total_count: number;
  routine_count: number;
  visible_count: number;
};
export function ActivityControls({
  mode,
  summary,
  loading,
  onChange,
}: {
  mode: ActivityMode;
  summary: ActivitySummary | null;
  loading: boolean;
  onChange: (mode: ActivityMode) => void;
}) {
  return (
    <div className="activity-controls">
      <div className="activity-toolbar">
        <div className="activity-modes" role="group" aria-label="활동 표시">
          {(
            [
              ["important", "주요 활동"],
              ["all", "전체 기록"],
              ["routine", "보조 실행"],
            ] as const
          ).map(([value, label]) => (
            <button
              key={value}
              type="button"
              aria-pressed={mode === value}
              onClick={() => onChange(value)}
            >
              {label}
            </button>
          ))}
        </div>
        <span className="activity-count" aria-live="polite">
          {loading
            ? "활동을 확인하는 중…"
            : summary
              ? `${summary.visible_count.toLocaleString()}건 표시 대상 / 전체 ${summary.total_count.toLocaleString()}건`
              : ""}
        </span>
      </div>
      {!loading && summary && (
        <p className="activity-summary">
          {mode === "important"
            ? `현재 검색 조건에서 보조 실행 ${summary.routine_count.toLocaleString()}건을 숨겼습니다. 전체 기록에서 다시 확인할 수 있습니다.`
            : mode === "routine"
              ? "환경 확인·문자 처리 등 보조 실행으로 분류된 기록입니다."
              : "보조 실행을 포함한 모든 기록입니다. 행마다 분류 이유를 표시합니다."}
        </p>
      )}
      <details className="activity-rules">
        <summary>분류 기준 보기</summary>
        <p>
          프로그램 경로와 인자가 정해진 패턴에 일치하는 환경 확인(lsb_release
          -a, getconf LONG_BIT, locale), 문자 변환(tr), 문자 추출(cut -c1/-c2-),
          표준 입력 행 수(wc -l) 등을 보조 실행으로 분류합니다.
        </p>
        <p>
          실패했거나 결과·계정이 불명인 실행, 로그인 계정과 실행 계정이 다른
          실행, 접속·인증 기록은 주요 활동에 남깁니다. cat, find, bash 같은
          프로그램을 이름만으로 숨기지 않습니다.
        </p>
        <p>
          직접 입력한 명령인지 판별하는 기능은 아닙니다. 직접 실행한 명령도 같은
          패턴이면 보조 실행으로 분류될 수 있습니다. 표시 방식만 바꾸며 저장된
          기록은 삭제하지 않습니다.
        </p>
      </details>
    </div>
  );
}
export function CommandText({ text }: { text: string }) {
  if (text.length <= 180 && !text.includes("\n")) return <code>{text}</code>;
  const preview = text.split("\n")[0].slice(0, 120);
  return (
    <details className="command-details">
      <summary>
        <code>
          {preview}
          {text.length > preview.length ? "…" : ""}
        </code>
        <span>전체 명령 펼치기</span>
      </summary>
      <pre>
        <code>{text}</code>
      </pre>
    </details>
  );
}
