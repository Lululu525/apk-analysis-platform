import React, { useEffect, useMemo, useRef, useState } from "react";

type SampleStatus = "received" | "queued" | "running" | "finished" | "failed";

type UploadResponse = {
  sample_id: string;
  sha256: string;
  filename: string;
  status: string;
};

type SampleItem = {
  sample_id: string;
  sha256?: string;
  filename: string;
  uploaded_at: string;
  storage_path?: string;
  status: SampleStatus;
};

type SamplesResponse = {
  items: SampleItem[];
  page: number;
  page_size: number;
  total: number;
  total_pages: number;
  has_next: boolean;
  has_prev: boolean;
  query: string;
};

type RunAnalysisResponse = {
  sample_id: string;
  status: "queued";
  task_id: string;
  message: string;
};

type ResultResponse = {
  sample_id: string;
  status: SampleStatus;
  result_ready: boolean;
  message?: string;
  result?: {
    schema_version?: string;
    job_id?: string;
    status?: string;
    started_at?: string | null;
    finished_at?: string | null;
    summary?: {
      risk_score?: number;
      risk_level?: string;
      counts?: {
        critical?: number;
        high?: number;
        medium?: number;
        low?: number;
        info?: number;
      };
      formula?: string;
      base_score?: number;
      special_bonus?: number;
    };
    findings?: Array<{
      id?: string;
      severity?: string;
      title?: string;
      description?: string;
      remediation?: string;
      evidence?: string;
      score_weight?: number;
    }>;
    artifacts?: {
      pdf_path?: string | null;
      features_path?: string | null;
    };
    errors?: string[];
  };
};

const API_BASE = "http://127.0.0.1:8000";

const statusColorMap: Record<SampleStatus, string> = {
  received: "#94a3b8",
  queued: "#64748b",
  running: "#2563eb",
  finished: "#10b981",
  failed: "#ef4444",
};

const statusBgMap: Record<SampleStatus, string> = {
  received: "#f8fafc",
  queued: "#f8fafc",
  running: "#eff6ff",
  finished: "#ecfdf5",
  failed: "#fef2f2",
};

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, init);

  if (!response.ok) {
    let detail = `HTTP ${response.status}`;
    try {
      const data = await response.json();
      detail = data.detail || JSON.stringify(data);
    } catch {
      try {
        detail = await response.text();
      } catch {
        // ignore
      }
    }
    throw new Error(detail);
  }

  return response.json() as Promise<T>;
}

function formatDate(value?: string) {
  if (!value) return "N/A";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString();
}

function escapeRegExp(text: string) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function HighlightText({
  text,
  keyword,
}: {
  text: string;
  keyword: string;
}) {
  if (!keyword.trim()) {
    return <>{text}</>;
  }

  const regex = new RegExp(`(${escapeRegExp(keyword)})`, "ig");
  const parts = text.split(regex);

  return (
    <>
      {parts.map((part, index) => {
        const isMatch = part.toLowerCase() === keyword.toLowerCase();
        if (isMatch) {
          return (
            <mark
              key={`${part}-${index}`}
              style={{
                background: "#fef08a",
                color: "#111827",
                padding: "0 2px",
                borderRadius: 4,
              }}
            >
              {part}
            </mark>
          );
        }
        return <React.Fragment key={`${part}-${index}`}>{part}</React.Fragment>;
      })}
    </>
  );
}

function StatusBadge({ status }: { status: SampleStatus }) {
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        padding: "6px 10px",
        borderRadius: 999,
        fontSize: 12,
        fontWeight: 700,
        color: statusColorMap[status],
        background: statusBgMap[status],
        border: `1px solid ${statusColorMap[status]}22`,
        textTransform: "lowercase",
      }}
    >
      <span
        style={{
          width: 7,
          height: 7,
          borderRadius: "50%",
          background: statusColorMap[status],
        }}
      />
      {status}
    </span>
  );
}

function SummaryBox({
  title,
  value,
}: {
  title: string;
  value: React.ReactNode;
}) {
  return (
    <div
      style={{
        background: "#ffffff",
        border: "1px solid #e5e7eb",
        borderRadius: 18,
        padding: 18,
        minHeight: 90,
      }}
    >
      <div
        style={{
          color: "#94a3b8",
          fontSize: 12,
          fontWeight: 800,
          textTransform: "uppercase",
          marginBottom: 10,
        }}
      >
        {title}
      </div>
      <div
        style={{
          fontSize: 18,
          fontWeight: 800,
          color: "#111827",
          wordBreak: "break-word",
        }}
      >
        {value}
      </div>
    </div>
  );
}

function CountCard({
  label,
  value,
  color,
  bg,
}: {
  label: string;
  value: number;
  color: string;
  bg: string;
}) {
  return (
    <div
      style={{
        background: bg,
        border: `1px solid ${color}33`,
        borderRadius: 18,
        padding: 18,
        minHeight: 86,
      }}
    >
      <div
        style={{
          color,
          fontWeight: 700,
          fontSize: 12,
          textTransform: "uppercase",
          marginBottom: 10,
        }}
      >
        {label}
      </div>
      <div style={{ color, fontWeight: 800, fontSize: 28 }}>{value}</div>
    </div>
  );
}

function SearchIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
      <path
        d="M21 21L16.65 16.65M18 11C18 14.866 14.866 18 11 18C7.13401 18 4 14.866 4 11C4 7.13401 7.13401 4 11 4C14.866 4 18 7.13401 18 11Z"
        stroke="#94a3b8"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function ClearIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
      <path
        d="M18 6L6 18M6 6L18 18"
        stroke="#94a3b8"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function ReportModal({
  open,
  onClose,
  result,
}: {
  open: boolean;
  onClose: () => void;
  result: ResultResponse | null;
}) {
  if (!open || !result?.result) return null;

  const report = result.result;
  const summary = report.summary || {};
  const counts = summary.counts || {};
  const findings = report.findings || [];
  const errors = report.errors || [];

  return (
    <div
      onClick={onClose}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(15,23,42,0.35)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: 24,
        zIndex: 9999,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: "min(980px, 100%)",
          maxHeight: "88vh",
          overflowY: "auto",
          background: "#f8fafc",
          borderRadius: 28,
          border: "1px solid #e5e7eb",
          boxShadow: "0 24px 80px rgba(15,23,42,0.20)",
        }}
      >
        <div
          style={{
            padding: "22px 24px 18px 24px",
            borderBottom: "1px solid #e5e7eb",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            background: "#ffffff",
            borderTopLeftRadius: 28,
            borderTopRightRadius: 28,
            position: "sticky",
            top: 0,
            zIndex: 1,
          }}
        >
          <div>
            <div
              style={{
                color: "#94a3b8",
                fontSize: 12,
                fontWeight: 700,
                textTransform: "uppercase",
                letterSpacing: 0.4,
              }}
            >
              Analysis Result
            </div>
            <div style={{ fontSize: 20, fontWeight: 800, color: "#111827" }}>
              Report Preview
            </div>
          </div>

          <button
            onClick={onClose}
            style={{
              borderRadius: 14,
              border: "1px solid #cbd5e1",
              background: "#ffffff",
              padding: "10px 16px",
              fontWeight: 700,
              cursor: "pointer",
            }}
          >
            Close
          </button>
        </div>

        <div style={{ padding: 24 }}>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(4, minmax(0, 1fr))",
              gap: 14,
              marginBottom: 18,
            }}
          >
            <SummaryBox title="Sample ID" value={result.sample_id} />
            <SummaryBox title="Report Status" value={report.status || result.status} />
            <SummaryBox title="Risk Score" value={summary.risk_score ?? "N/A"} />
            <SummaryBox title="Risk Level" value={summary.risk_level || "N/A"} />
          </div>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(5, minmax(0, 1fr))",
              gap: 14,
              marginBottom: 22,
            }}
          >
            <CountCard label="Critical" value={counts.critical || 0} color="#ef4444" bg="#fef2f2" />
            <CountCard label="High" value={counts.high || 0} color="#f97316" bg="#fff7ed" />
            <CountCard label="Medium" value={counts.medium || 0} color="#eab308" bg="#fefce8" />
            <CountCard label="Low" value={counts.low || 0} color="#0ea5e9" bg="#f0f9ff" />
            <CountCard label="Info" value={counts.info || 0} color="#64748b" bg="#f8fafc" />
          </div>

          <div
            style={{
              background: "#ffffff",
              border: "1px solid #e5e7eb",
              borderRadius: 22,
              padding: 18,
              marginBottom: 18,
            }}
          >
            <div style={{ fontWeight: 800, fontSize: 16, marginBottom: 14 }}>Findings</div>

            {findings.length === 0 ? (
              <div style={{ color: "#64748b" }}>No findings reported.</div>
            ) : (
              <div style={{ display: "grid", gap: 14 }}>
                {findings.map((finding, index) => {
                  const sev = (finding.severity || "info").toLowerCase();
                  const sevColor =
                    sev === "critical"
                      ? "#ef4444"
                      : sev === "high"
                      ? "#f97316"
                      : sev === "medium"
                      ? "#eab308"
                      : sev === "low"
                      ? "#0ea5e9"
                      : "#64748b";

                  const sevBg =
                    sev === "critical"
                      ? "#fef2f2"
                      : sev === "high"
                      ? "#fff7ed"
                      : sev === "medium"
                      ? "#fefce8"
                      : sev === "low"
                      ? "#f0f9ff"
                      : "#f8fafc";

                  return (
                    <div
                      key={`${finding.id}-${index}`}
                      style={{
                        border: "1px solid #e5e7eb",
                        borderRadius: 18,
                        padding: 16,
                        background: "#ffffff",
                      }}
                    >
                      <div
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: 10,
                          marginBottom: 10,
                          flexWrap: "wrap",
                        }}
                      >
                        <span
                          style={{
                            padding: "6px 10px",
                            borderRadius: 999,
                            background: sevBg,
                            color: sevColor,
                            fontSize: 12,
                            fontWeight: 800,
                            border: `1px solid ${sevColor}33`,
                            textTransform: "uppercase",
                          }}
                        >
                          {sev}
                        </span>
                        <span style={{ fontSize: 16, fontWeight: 700, color: "#111827" }}>
                          {finding.title || "Untitled finding"}
                        </span>
                      </div>

                      <div style={{ color: "#475569", marginBottom: 10 }}>
                        {finding.description || "No description."}
                      </div>

                      {finding.evidence ? (
                        <div
                          style={{
                            padding: 12,
                            borderRadius: 14,
                            background: "#f8fafc",
                            border: "1px solid #e5e7eb",
                            marginBottom: 10,
                            color: "#334155",
                            fontSize: 13,
                          }}
                        >
                          <strong>Evidence</strong>
                          <div style={{ marginTop: 6 }}>{finding.evidence}</div>
                        </div>
                      ) : null}

                      {finding.remediation ? (
                        <div
                          style={{
                            padding: 12,
                            borderRadius: 14,
                            background: "#f8fafc",
                            border: "1px solid #e5e7eb",
                            color: "#475569",
                            fontSize: 13,
                          }}
                        >
                          <strong>Remediation</strong>
                          <div style={{ marginTop: 6 }}>{finding.remediation}</div>
                        </div>
                      ) : null}
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          <div
            style={{
              background: "#ffffff",
              border: "1px solid #e5e7eb",
              borderRadius: 22,
              padding: 18,
              marginBottom: 18,
            }}
          >
            <div style={{ fontWeight: 800, fontSize: 16, marginBottom: 12 }}>Errors</div>
            {errors.length === 0 ? (
              <div style={{ color: "#64748b" }}>No errors reported.</div>
            ) : (
              <div style={{ display: "grid", gap: 8 }}>
                {errors.map((error, index) => (
                  <div
                    key={index}
                    style={{
                      background: "#fef2f2",
                      color: "#b91c1c",
                      border: "1px solid #fecaca",
                      borderRadius: 14,
                      padding: 12,
                    }}
                  >
                    {error}
                  </div>
                ))}
              </div>
            )}
          </div>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(2, minmax(0, 1fr))",
              gap: 14,
            }}
          >
            <SummaryBox title="Started At" value={formatDate(report.started_at || undefined)} />
            <SummaryBox title="Finished At" value={formatDate(report.finished_at || undefined)} />
          </div>
        </div>
      </div>
    </div>
  );
}

function UploadModal({
  open,
  onClose,
  selectedFile,
  onFileChange,
  onUpload,
  isUploading,
}: {
  open: boolean;
  onClose: () => void;
  selectedFile: File | null;
  onFileChange: (file: File | null) => void;
  onUpload: () => void;
  isUploading: boolean;
}) {
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  if (!open) return null;

  return (
    <div
      onClick={onClose}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(15,23,42,0.35)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: 24,
        zIndex: 9999,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: "min(520px, 100%)",
          background: "#ffffff",
          borderRadius: 28,
          border: "1px solid #e5e7eb",
          boxShadow: "0 24px 80px rgba(15,23,42,0.20)",
          overflow: "hidden",
        }}
      >
        <div
          style={{
            padding: "22px 24px 18px 24px",
            borderBottom: "1px solid #e5e7eb",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <div>
            <div
              style={{
                color: "#94a3b8",
                fontSize: 12,
                fontWeight: 700,
                textTransform: "uppercase",
                letterSpacing: 0.4,
              }}
            >
              Upload
            </div>
            <div style={{ fontSize: 20, fontWeight: 800, color: "#111827" }}>
              Upload APK File
            </div>
          </div>

          <button
            onClick={onClose}
            style={{
              borderRadius: 14,
              border: "1px solid #cbd5e1",
              background: "#ffffff",
              padding: "10px 16px",
              fontWeight: 700,
              cursor: "pointer",
            }}
          >
            Close
          </button>
        </div>

        <div style={{ padding: 24 }}>
          <input
            ref={fileInputRef}
            type="file"
            accept=".apk"
            onChange={(e) => onFileChange(e.target.files?.[0] || null)}
            style={{ display: "none" }}
          />

          <div
            style={{
              border: "1px dashed #cbd5e1",
              borderRadius: 20,
              padding: 24,
              background: "#f8fafc",
              textAlign: "center",
            }}
          >
            <div
              style={{
                fontSize: 16,
                fontWeight: 700,
                color: "#0f172a",
                marginBottom: 8,
              }}
            >
              Select an APK to analyze
            </div>
            <div
              style={{
                fontSize: 14,
                color: "#64748b",
                marginBottom: 18,
              }}
            >
              Upload an APK file and start async analysis through the backend queue.
            </div>

            <button
              onClick={() => fileInputRef.current?.click()}
              style={{
                borderRadius: 14,
                border: "1px solid #cbd5e1",
                background: "#ffffff",
                padding: "10px 16px",
                fontWeight: 700,
                cursor: "pointer",
                marginBottom: 14,
              }}
            >
              Choose APK
            </button>

            <div
              style={{
                minHeight: 22,
                color: selectedFile ? "#0f172a" : "#94a3b8",
                fontSize: 14,
                wordBreak: "break-all",
              }}
            >
              {selectedFile ? selectedFile.name : "No file selected"}
            </div>
          </div>

          <div
            style={{
              display: "flex",
              justifyContent: "flex-end",
              gap: 10,
              marginTop: 20,
            }}
          >
            <button
              onClick={onClose}
              style={{
                borderRadius: 14,
                border: "1px solid #cbd5e1",
                background: "#ffffff",
                padding: "10px 16px",
                fontWeight: 700,
                cursor: "pointer",
              }}
            >
              Cancel
            </button>

            <button
              onClick={onUpload}
              disabled={isUploading}
              style={{
                borderRadius: 14,
                border: "1px solid #dbeafe",
                background: isUploading ? "#93c5fd" : "#2563eb",
                color: "#ffffff",
                padding: "10px 18px",
                fontWeight: 800,
                cursor: isUploading ? "not-allowed" : "pointer",
                boxShadow: "0 8px 20px rgba(37,99,235,0.24)",
              }}
            >
              {isUploading ? "Uploading..." : "Upload"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const [samples, setSamples] = useState<SampleItem[]>([]);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(10);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);

  const [queryInput, setQueryInput] = useState("");
  const [query, setQuery] = useState("");

  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isUploading, setIsUploading] = useState(false);

  const [banner, setBanner] = useState("");
  const [bannerType, setBannerType] = useState<"error" | "success" | "info">("info");

  const [modalOpen, setModalOpen] = useState(false);
  const [modalResult, setModalResult] = useState<ResultResponse | null>(null);

  const [uploadModalOpen, setUploadModalOpen] = useState(false);

  const pollingRef = useRef<Record<string, boolean>>({});

  async function fetchSamples(targetPage = page, targetQuery = query) {
    try {
      const data = await apiFetch<SamplesResponse>(
        `/v1/samples?page=${targetPage}&page_size=${pageSize}&query=${encodeURIComponent(
          targetQuery
        )}`
      );
      setSamples(data.items);
      setPage(data.page);
      setTotal(data.total);
      setTotalPages(data.total_pages);
    } catch (error) {
      console.error(error);
      setBannerType("error");
      setBanner("Failed to load sample list.");
    }
  }

  useEffect(() => {
    fetchSamples(1, query);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query]);

  useEffect(() => {
    const handler = setTimeout(() => {
      setPage(1);
      setQuery(queryInput.trim());
    }, 250);

    return () => clearTimeout(handler);
  }, [queryInput]);

  async function pollSampleUntilDone(sampleId: string) {
    if (pollingRef.current[sampleId]) return;
    pollingRef.current[sampleId] = true;

    try {
      while (true) {
        const statusData = await apiFetch<{ sample_id: string; status: SampleStatus }>(
          `/v1/samples/${sampleId}/status`
        );

        setSamples((prev) =>
          prev.map((item) =>
            item.sample_id === sampleId ? { ...item, status: statusData.status } : item
          )
        );

        if (statusData.status === "finished") {
          setBannerType("success");
          setBanner(`Analysis finished for sample ${sampleId}.`);
          await fetchSamples(page, query);
          break;
        }

        if (statusData.status === "failed") {
          setBannerType("error");
          setBanner(`Analysis failed for sample ${sampleId}.`);
          await fetchSamples(page, query);
          break;
        }

        await sleep(2000);
      }
    } catch (error) {
      console.error(error);
      setBannerType("error");
      setBanner(`Polling failed for sample ${sampleId}.`);
    } finally {
      delete pollingRef.current[sampleId];
    }
  }

  async function startAnalysis(sampleId: string) {
    try {
      const data = await apiFetch<RunAnalysisResponse>(`/v1/samples/${sampleId}/run-analysis`, {
        method: "POST",
      });

      setBannerType("info");
      setBanner(`Analysis queued. Task ID: ${data.task_id}`);

      setSamples((prev) =>
        prev.map((item) =>
          item.sample_id === sampleId ? { ...item, status: "queued" } : item
        )
      );

      pollSampleUntilDone(sampleId);
    } catch (error) {
      console.error(error);
      setBannerType("error");
      setBanner("Upload or analysis failed. Please check your backend API.");
      throw error;
    }
  }

  async function handleUpload() {
    if (!selectedFile) {
      setBannerType("error");
      setBanner("Please choose an APK file first.");
      return;
    }

    const formData = new FormData();
    formData.append("file", selectedFile);

    setIsUploading(true);

    try {
      const response = await fetch(`${API_BASE}/v1/samples/upload`, {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        const text = await response.text();
        throw new Error(text || "Upload failed");
      }

      const uploadData = (await response.json()) as UploadResponse;

      setBannerType("info");
      setBanner(`Upload succeeded. Starting analysis for ${uploadData.filename}...`);

      await fetchSamples(1, query);
      await startAnalysis(uploadData.sample_id);

      setSelectedFile(null);
      setUploadModalOpen(false);
    } catch (error) {
      console.error(error);
      setBannerType("error");
      setBanner("Upload or analysis failed. Please check your backend API.");
    } finally {
      setIsUploading(false);
    }
  }

  async function openResult(sampleId: string) {
    try {
      const data = await apiFetch<ResultResponse>(`/v1/samples/${sampleId}/result`);
      setModalResult(data);
      setModalOpen(true);
    } catch (error) {
      console.error(error);
      setBannerType("error");
      setBanner("Failed to load report result.");
    }
  }

  function openPdf(sampleId: string) {
    window.open(`${API_BASE}/v1/samples/${sampleId}/report.pdf`, "_blank");
  }

  const filteredVisibleSamples = useMemo(() => {
    return samples;
  }, [samples]);

  function bannerStyle(type: "error" | "success" | "info") {
    if (type === "error") {
      return {
        background: "#fef2f2",
        color: "#dc2626",
        border: "1px solid #fecaca",
      };
    }
    if (type === "success") {
      return {
        background: "#ecfdf5",
        color: "#059669",
        border: "1px solid #a7f3d0",
      };
    }
    return {
      background: "#eff6ff",
      color: "#2563eb",
      border: "1px solid #bfdbfe",
    };
  }

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "#f3f6fb",
        padding: "24px 20px",
        fontFamily:
          'Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
        color: "#0f172a",
      }}
    >
      <div
        style={{
          width: "min(1100px, 100%)",
          margin: "0 auto",
        }}
      >
        <div
          style={{
            background: "#ffffff",
            borderRadius: 28,
            border: "1px solid #e5e7eb",
            boxShadow: "0 18px 50px rgba(15,23,42,0.06)",
            overflow: "hidden",
          }}
        >
          <div
            style={{
              padding: 28,
              borderBottom: "1px solid #eef2f7",
              background:
                "linear-gradient(180deg, rgba(255,255,255,1) 0%, rgba(248,250,252,1) 100%)",
            }}
          >
            <div
              style={{
                color: "#94a3b8",
                fontSize: 13,
                fontWeight: 800,
                textTransform: "uppercase",
                letterSpacing: 0.8,
                marginBottom: 10,
              }}
            >
              APK Analysis Platform
            </div>

            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                gap: 18,
                alignItems: "flex-start",
                flexWrap: "wrap",
              }}
            >
              <div>
                <div style={{ fontSize: 34, fontWeight: 900, marginBottom: 8, lineHeight: 1.1 }}>
                  Analysis Dashboard
                </div>
                <div style={{ color: "#64748b", fontSize: 16 }}>
                  Upload APK files, track async analysis progress, and review generated reports.
                </div>
              </div>

              <button
                onClick={() => setUploadModalOpen(true)}
                style={{
                  borderRadius: 16,
                  border: "1px solid #dbeafe",
                  background: "#2563eb",
                  color: "#ffffff",
                  padding: "12px 22px",
                  fontWeight: 800,
                  fontSize: 17,
                  cursor: "pointer",
                  boxShadow: "0 10px 24px rgba(37,99,235,0.28)",
                }}
              >
                Upload
              </button>
            </div>
          </div>

          <div style={{ padding: 24 }}>
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                gap: 12,
                flexWrap: "wrap",
                marginBottom: 16,
              }}
            >
              <div style={{ color: "#64748b", fontSize: 14, fontWeight: 600 }}>
                Total Samples: <strong style={{ color: "#0f172a" }}>{total}</strong>
              </div>

              <div
                style={{
                  position: "relative",
                  width: 360,
                  maxWidth: "100%",
                }}
              >
                <div
                  style={{
                    position: "absolute",
                    left: 14,
                    top: "50%",
                    transform: "translateY(-50%)",
                    pointerEvents: "none",
                  }}
                >
                  <SearchIcon />
                </div>

                <input
                  value={queryInput}
                  onChange={(e) => setQueryInput(e.target.value)}
                  placeholder="Search filename or sample id"
                  style={{
                    width: "100%",
                    borderRadius: 16,
                    border: "1px solid #dbe2ea",
                    padding: "12px 42px 12px 42px",
                    outline: "none",
                    background: "#ffffff",
                    fontSize: 15,
                    boxSizing: "border-box",
                  }}
                />

                {queryInput ? (
                  <button
                    onClick={() => setQueryInput("")}
                    style={{
                      position: "absolute",
                      right: 12,
                      top: "50%",
                      transform: "translateY(-50%)",
                      border: "none",
                      background: "transparent",
                      padding: 4,
                      cursor: "pointer",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                    }}
                    aria-label="Clear search"
                  >
                    <ClearIcon />
                  </button>
                ) : null}
              </div>
            </div>

            {banner ? (
              <div
                style={{
                  ...bannerStyle(bannerType),
                  borderRadius: 16,
                  padding: "12px 14px",
                  fontWeight: 600,
                  marginBottom: 18,
                }}
              >
                {banner}
              </div>
            ) : null}

            <div
              style={{
                border: "1px solid #e5e7eb",
                borderRadius: 24,
                overflow: "hidden",
                background: "#ffffff",
              }}
            >
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "3fr 1.2fr 1.6fr 1.4fr",
                  gap: 12,
                  padding: "14px 16px",
                  background: "#f8fafc",
                  borderBottom: "1px solid #e5e7eb",
                  fontSize: 12,
                  fontWeight: 800,
                  textTransform: "uppercase",
                  color: "#64748b",
                  letterSpacing: 0.4,
                }}
              >
                <div>Filename</div>
                <div>Status</div>
                <div>Uploaded</div>
                <div>Report</div>
              </div>

              {filteredVisibleSamples.length === 0 ? (
                <div style={{ padding: 24, color: "#64748b" }}>No samples found.</div>
              ) : (
                filteredVisibleSamples.map((sample) => (
                  <div
                    key={sample.sample_id}
                    style={{
                      display: "grid",
                      gridTemplateColumns: "3fr 1.2fr 1.6fr 1.4fr",
                      gap: 12,
                      padding: "16px",
                      borderBottom: "1px solid #eef2f7",
                      alignItems: "center",
                    }}
                  >
                    <div style={{ minWidth: 0 }}>
                      <div
                        style={{
                          fontWeight: 700,
                          color: "#0f172a",
                          marginBottom: 6,
                          wordBreak: "break-all",
                          fontSize: 16,
                        }}
                      >
                        <HighlightText text={sample.filename} keyword={query} />
                      </div>
                      <div
                        style={{
                          color: "#94a3b8",
                          fontSize: 12,
                          wordBreak: "break-all",
                        }}
                      >
                        <HighlightText text={sample.sample_id} keyword={query} />
                      </div>
                    </div>

                    <div>
                      <StatusBadge status={sample.status} />
                    </div>

                    <div style={{ color: "#475569", fontSize: 14 }}>
                      {formatDate(sample.uploaded_at)}
                    </div>

                    <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                      <button
                        onClick={() => openResult(sample.sample_id)}
                        disabled={sample.status !== "finished"}
                        style={{
                          borderRadius: 12,
                          border: "1px solid #cbd5e1",
                          background: sample.status === "finished" ? "#ffffff" : "#f8fafc",
                          padding: "8px 12px",
                          fontWeight: 700,
                          cursor: sample.status === "finished" ? "pointer" : "not-allowed",
                        }}
                      >
                        Result
                      </button>

                      <button
                        onClick={() => openPdf(sample.sample_id)}
                        disabled={sample.status !== "finished"}
                        style={{
                          borderRadius: 12,
                          border: "1px solid #cbd5e1",
                          background: sample.status === "finished" ? "#ffffff" : "#f8fafc",
                          padding: "8px 12px",
                          fontWeight: 700,
                          cursor: sample.status === "finished" ? "pointer" : "not-allowed",
                        }}
                      >
                        PDF
                      </button>

                      {(sample.status === "received" || sample.status === "failed") && (
                        <button
                          onClick={() => startAnalysis(sample.sample_id)}
                          style={{
                            borderRadius: 12,
                            border: "1px solid #dbeafe",
                            background: "#eff6ff",
                            color: "#2563eb",
                            padding: "8px 12px",
                            fontWeight: 700,
                            cursor: "pointer",
                          }}
                        >
                          Retry
                        </button>
                      )}
                    </div>
                  </div>
                ))
              )}
            </div>

            <div
              style={{
                marginTop: 16,
                display: "flex",
                justifyContent: "center",
                alignItems: "center",
                gap: 8,
                flexWrap: "wrap",
              }}
            >
              <button
                disabled={page <= 1}
                onClick={() => {
                  const nextPage = page - 1;
                  setPage(nextPage);
                  fetchSamples(nextPage, query);
                }}
                style={{
                  borderRadius: 12,
                  border: "1px solid #cbd5e1",
                  background: page <= 1 ? "#f8fafc" : "#ffffff",
                  padding: "8px 12px",
                  fontWeight: 700,
                  cursor: page <= 1 ? "not-allowed" : "pointer",
                }}
              >
                Prev
              </button>

              {Array.from({ length: totalPages }, (_, i) => i + 1)
                .slice(Math.max(0, page - 3), Math.min(totalPages, page + 2))
                .map((pageNumber) => (
                  <button
                    key={pageNumber}
                    onClick={() => {
                      setPage(pageNumber);
                      fetchSamples(pageNumber, query);
                    }}
                    style={{
                      width: 36,
                      height: 36,
                      borderRadius: 12,
                      border: pageNumber === page ? "1px solid #111827" : "1px solid #cbd5e1",
                      background: pageNumber === page ? "#111827" : "#ffffff",
                      color: pageNumber === page ? "#ffffff" : "#111827",
                      fontWeight: 800,
                      cursor: "pointer",
                    }}
                  >
                    {pageNumber}
                  </button>
                ))}

              <button
                disabled={page >= totalPages}
                onClick={() => {
                  const nextPage = page + 1;
                  setPage(nextPage);
                  fetchSamples(nextPage, query);
                }}
                style={{
                  borderRadius: 12,
                  border: "1px solid #cbd5e1",
                  background: page >= totalPages ? "#f8fafc" : "#ffffff",
                  padding: "8px 12px",
                  fontWeight: 700,
                  cursor: page >= totalPages ? "not-allowed" : "pointer",
                }}
              >
                Next
              </button>
            </div>
          </div>
        </div>
      </div>

      <ReportModal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        result={modalResult}
      />

      <UploadModal
        open={uploadModalOpen}
        onClose={() => setUploadModalOpen(false)}
        selectedFile={selectedFile}
        onFileChange={setSelectedFile}
        onUpload={handleUpload}
        isUploading={isUploading}
      />
    </div>
  );
}