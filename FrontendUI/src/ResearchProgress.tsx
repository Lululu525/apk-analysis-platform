import { useEffect, useMemo, useState } from "react";

type ResearchClaim = {
  claim_id: string;
  population_id: string;
  unit_count: number;
  apk_count: number;
  metric_name: string;
  metric_label: string;
  metric_value: number;
  evaluation_design: string;
  claim_scope: string;
  boundary: "static_path_only" | "descriptive_ceiling" | "design_informed" | "held_out_internal";
  notes: string;
  source: {
    artifact_path: string;
    artifact_sha256: string;
    json_pointer: string;
  };
};

type ResearchProgressResponse = {
  report_date: string;
  evidence_status: string;
  summary: {
    claim_count: number;
    population_count: number;
    generalization_claim_count: number;
    static_path_claim_count: number;
  };
  populations: Array<{ population_id: string; unit_count: number; apk_count: number }>;
  claims: ResearchClaim[];
  caveats: string[];
};

const API_BASE = "http://127.0.0.1:8000";

const boundaryLabels: Record<ResearchClaim["boundary"], string> = {
  held_out_internal: "Held-out internal",
  design_informed: "Design-informed",
  descriptive_ceiling: "Descriptive ceiling",
  static_path_only: "Static path only",
};

function metricValue(claim: ResearchClaim) {
  if (claim.metric_name.includes("f1")) return claim.metric_value.toFixed(3);
  return new Intl.NumberFormat("en-US").format(claim.metric_value);
}

export default function ResearchProgress() {
  const [data, setData] = useState<ResearchProgressResponse | null>(null);
  const [error, setError] = useState("");
  const [boundary, setBoundary] = useState("all");

  useEffect(() => {
    fetch(`${API_BASE}/v1/research/progress`)
      .then(async (response) => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json() as Promise<ResearchProgressResponse>;
      })
      .then(setData)
      .catch((reason: unknown) => setError(reason instanceof Error ? reason.message : "Unknown error"));
  }, []);

  const visibleClaims = useMemo(
    () => data?.claims.filter((claim) => boundary === "all" || claim.boundary === boundary) ?? [],
    [data, boundary]
  );

  if (error) {
    return <div className="research-state research-state-error">研究進度載入失敗：{error}</div>;
  }
  if (!data) {
    return <div className="research-state">正在載入研究證據…</div>;
  }

  return (
    <div className="research-progress">
      <section className="research-callout">
        <div>
          <span className="research-eyebrow">Evidence status · {data.report_date}</span>
          <h2>結果可追溯，但主張仍有邊界</h2>
          <p>目前沒有登錄為外部獨立測試的泛化結果；每個數值都保留母體、評估設計與原始 JSON 位置。</p>
        </div>
        <span className="research-status-badge">Bounded evidence</span>
      </section>

      <section className="research-summary-grid">
        <article><span>Audited claims</span><strong>{data.summary.claim_count}</strong></article>
        <article><span>Distinct populations</span><strong>{data.summary.population_count}</strong></article>
        <article><span>Static path claims</span><strong>{data.summary.static_path_claim_count}</strong></article>
        <article className="research-summary-warning"><span>Generalization claims</span><strong>{data.summary.generalization_claim_count}</strong></article>
      </section>

      <section className="research-panel">
        <div className="research-panel-heading">
          <div><span className="research-eyebrow">Population registry</span><h3>評估母體不可混算</h3></div>
        </div>
        <div className="population-grid">
          {data.populations.map((population) => (
            <article key={population.population_id}>
              <strong>{population.unit_count.toLocaleString()} units</strong>
              <span>{population.apk_count} APKs</span>
              <code>{population.population_id}</code>
            </article>
          ))}
        </div>
      </section>

      <section className="research-panel">
        <div className="research-panel-heading research-panel-filter">
          <div><span className="research-eyebrow">Registered results</span><h3>主要實驗結果</h3></div>
          <select value={boundary} onChange={(event) => setBoundary(event.target.value)} aria-label="Filter by evidence boundary">
            <option value="all">全部證據邊界</option>
            {Object.entries(boundaryLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
          </select>
        </div>
        <div className="research-claim-list">
          {visibleClaims.map((claim) => (
            <article className="research-claim" key={claim.claim_id}>
              <div className="research-claim-value">
                <strong>{metricValue(claim)}</strong>
                <span>{claim.metric_label}</span>
              </div>
              <div className="research-claim-body">
                <div className="research-tags">
                  <span className={`research-boundary research-boundary-${claim.boundary}`}>{boundaryLabels[claim.boundary]}</span>
                  <span>{claim.evaluation_design.replace(/_/g, " ")}</span>
                  <span>{claim.unit_count} units / {claim.apk_count} APKs</span>
                </div>
                <p>{claim.notes}</p>
                <details>
                  <summary>查看證據來源</summary>
                  <code>{claim.source.artifact_path}{claim.source.json_pointer}</code>
                  <small>SHA-256 {claim.source.artifact_sha256}</small>
                </details>
              </div>
            </article>
          ))}
        </div>
      </section>

      <section className="research-caveats">
        <span className="research-eyebrow">Interpretation guardrails</span>
        <h3>報告時必須保留的限制</h3>
        <ul>{data.caveats.map((caveat) => <li key={caveat}>{caveat}</li>)}</ul>
      </section>
    </div>
  );
}
