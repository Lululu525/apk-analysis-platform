import React, { useEffect, useMemo, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  Download,
  FileCode2,
  Loader2,
  RefreshCw,
  Search,
  Shield,
  Upload,
  X,
} from "lucide-react";
import jsPDF from "jspdf";

const API_BASE = "http://127.0.0.1:8000";
const SELECTED_SAMPLE_KEY = "apk-dashboard:selected-sample-id";

const statusToProgress: Record<string, number> = {
  received: 10,
  queued: 25,
  running: 70,
  finished: 100,
  failed: 100,
};

type SampleItem = {
  sample_id: string;
  filename?: string;
  uploaded_at?: string;
  status?: string;
};

type Finding = {
  id?: string;
  finding_id?: string;
  severity?: string;
  title?: string;
  description?: string;
  remediation?: string;
};

type ResultPayload = {
  sample_id: string;
  status: string;
  result_ready: boolean;
  result?: {
    summary?: {
      risk_score?: number;
      counts?: Record<string, number>;
    };
    findings?: Finding[];
    started_at?: string;
    finished_at?: string;
  };
  message?: string;
};

function severityFromScore(score: number) {
  if (score >= 80) return "Critical";
  if (score >= 60) return "High";
  if (score >= 30) return "Medium";
  if (score > 0) return "Low";
  return "Info";
}

function humanReadableStatus(status: string) {
  switch (status) {
    case "received":
      return "APK received";
    case "queued":
      return "Queued for analysis";
    case "running":
      return "Analysis in progress";
    case "finished":
      return "Analysis completed";
    case "failed":
      return "Analysis failed";
    default:
      return status;
  }
}

function statusBadgeStyle(status: string): React.CSSProperties {
  switch (status) {
    case "finished":
      return { background: "#dcfce7", color: "#15803d" };
    case "running":
      return { background: "#dbeafe", color: "#1d4ed8" };
    case "failed":
      return { background: "#fee2e2", color: "#b91c1c" };
    case "received":
    case "queued":
      return { background: "#fef3c7", color: "#b45309" };
    default:
      return { background: "#e2e8f0", color: "#475569" };
  }
}

function riskBadgeStyle(severity: string): React.CSSProperties {
  switch ((severity || "info").toLowerCase()) {
    case "critical":
      return { background: "#fee2e2", color: "#b91c1c" };
    case "high":
      return { background: "#ffedd5", color: "#c2410c" };
    case "medium":
      return { background: "#fef3c7", color: "#b45309" };
    case "low":
      return { background: "#dbeafe", color: "#1d4ed8" };
    default:
      return { background: "#e2e8f0", color: "#475569" };
  }
}

async function apiGet<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`);
  if (!res.ok) {
    throw new Error(`GET ${path} failed: ${res.status}`);
  }
  return res.json();
}

async function apiPost<T>(path: string, body?: BodyInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    body,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`POST ${path} failed: ${res.status} ${text}`);
  }
  return res.json();
}

export default function App() {
  const [samples, setSamples] = useState<SampleItem[]>([]);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [selectedSampleId, setSelectedSampleId] = useState<string | null>(null);
  const [result, setResult] = useState<ResultPayload | null>(null);
  const [status, setStatus] = useState("");
  const [search, setSearch] = useState("");
  const [isUploading, setIsUploading] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState("");
  const [showProgressModal, setShowProgressModal] = useState(false);
  const [showCompleteModal, setShowCompleteModal] = useState(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const resultSectionRef = useRef<HTMLDivElement | null>(null);

  const selectedSample = useMemo(
    () => samples.find((s) => s.sample_id === selectedSampleId) ?? null,
    [samples, selectedSampleId]
  );

  const filteredSamples = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return samples;
    return samples.filter((s) =>
      [s.filename, s.sample_id, s.status].some((v) =>
        String(v ?? "").toLowerCase().includes(q)
      )
    );
  }, [samples, search]);

  const stats = useMemo(() => {
    return {
      total: samples.length,
      finished: samples.filter((s) => s.status === "finished").length,
      running: samples.filter((s) => s.status === "running").length,
      failed: samples.filter((s) => s.status === "failed").length,
    };
  }, [samples]);

  const effectiveStatus = result?.status || status || selectedSample?.status || "";
  const progress =
    statusToProgress[effectiveStatus] ?? statusToProgress[status] ?? 0;
  const riskScore = result?.result?.summary?.risk_score ?? 0;
  const riskLevel = severityFromScore(riskScore);
  const findings = result?.result?.findings ?? [];

  async function loadSamples() {
    const data = await apiGet<SampleItem[]>("/v1/samples");
    setSamples(data);
  }

  async function loadResult(sampleId: string) {
    const data = await apiGet<ResultPayload>(`/v1/samples/${sampleId}/result`);
    setResult(data);
    setStatus(data.status);
    setSelectedSampleId(sampleId);
    return data;
  }

  function hardRefresh() {
    window.location.reload();
  }

  function openUploadPicker() {
    fileInputRef.current?.click();
  }

  function saveSelectedSampleToSession(sampleId: string) {
    sessionStorage.setItem(SELECTED_SAMPLE_KEY, sampleId);
  }

  function clearSelectedSampleFromSession() {
    sessionStorage.removeItem(SELECTED_SAMPLE_KEY);
  }

  async function handleFileSelected(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0] ?? null;
    setSelectedFile(file);
    if (!file) return;
    await uploadAndAnalyze(file);
    e.target.value = "";
  }

  async function uploadAndAnalyze(file: File) {
    try {
      setError("");
      setResult(null);
      setStatus("received");
      setShowProgressModal(true);
      setShowCompleteModal(false);
      setIsUploading(true);

      const formData = new FormData();
      formData.append("file", file);

      const uploadRes = await apiPost<{ sample_id: string; status: string }>(
        "/v1/samples/upload",
        formData
      );
      setSelectedSampleId(uploadRes.sample_id);
      setStatus(uploadRes.status ?? "received");
      await loadSamples();

      setIsUploading(false);
      setIsAnalyzing(true);
      setStatus("running");

      await apiPost(`/v1/samples/${uploadRes.sample_id}/run-analysis`);
      const finalResult = await loadResult(uploadRes.sample_id);
      await loadSamples();
      setIsAnalyzing(false);

      if (finalResult.result_ready) {
        saveSelectedSampleToSession(uploadRes.sample_id);
        setShowProgressModal(false);
        setShowCompleteModal(true);
      }
    } catch (e) {
      setIsUploading(false);
      setIsAnalyzing(false);
      setStatus("failed");
      setError(e instanceof Error ? e.message : "Unknown error");
    }
  }

  async function viewResult(sampleId: string) {
    try {
      setError("");
      setSelectedSampleId(sampleId);
      saveSelectedSampleToSession(sampleId);

      const sampleMeta = samples.find((s) => s.sample_id === sampleId);
      if (sampleMeta?.status) {
        setStatus(sampleMeta.status);
      }

      const data = await loadResult(sampleId);

      setTimeout(() => {
        resultSectionRef.current?.scrollIntoView({
          behavior: "smooth",
          block: "start",
        });
      }, 100);

      return data;
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error");
      return null;
    }
  }

  function goToResultAfterReload() {
    setShowCompleteModal(false);
    hardRefresh();
  }

  function downloadPdfReport() {
    if (!selectedSampleId || !result) return;

    const pdf = new jsPDF();
    let y = 20;

    pdf.setFontSize(18);
    pdf.text("APK Security Analysis Report", 14, y);
    y += 12;

    pdf.setFontSize(11);
    pdf.text(`Sample ID: ${selectedSampleId}`, 14, y);
    y += 7;
    pdf.text(
      `Filename: ${selectedSample?.filename ?? selectedFile?.name ?? "-"}`,
      14,
      y
    );
    y += 7;
    pdf.text(`Status: ${result.status}`, 14, y);
    y += 7;
    pdf.text(`Risk Score: ${riskScore}`, 14, y);
    y += 7;
    pdf.text(`Risk Level: ${riskLevel}`, 14, y);
    y += 10;

    pdf.setFontSize(14);
    pdf.text("Findings", 14, y);
    y += 8;

    if (findings.length === 0) {
      pdf.setFontSize(11);
      pdf.text("No findings in current prototype ruleset.", 14, y);
    } else {
      findings.forEach((finding, index) => {
        const title = `${index + 1}. ${finding.title ?? "Untitled Finding"}`;
        const severity = `Severity: ${(finding.severity ?? "info").toUpperCase()}`;
        const description = finding.description ?? "No description available.";
        const remediation = finding.remediation
          ? `Remediation: ${finding.remediation}`
          : "";

        if (y > 250) {
          pdf.addPage();
          y = 20;
        }

        pdf.setFontSize(12);
        pdf.text(title, 14, y);
        y += 6;

        pdf.setFontSize(10);
        pdf.text(severity, 14, y);
        y += 6;

        const descLines = pdf.splitTextToSize(description, 180);
        pdf.text(descLines, 14, y);
        y += descLines.length * 5 + 3;

        if (remediation) {
          const remediationLines = pdf.splitTextToSize(remediation, 180);
          pdf.text(remediationLines, 14, y);
          y += remediationLines.length * 5 + 5;
        }
      });
    }

    pdf.save(`${selectedSampleId}-analysis-report.pdf`);
  }

  useEffect(() => {
    loadSamples().catch((e) =>
      setError(e instanceof Error ? e.message : "Failed to load samples")
    );

    const rememberedSampleId = sessionStorage.getItem(SELECTED_SAMPLE_KEY);
    if (rememberedSampleId) {
      loadResult(rememberedSampleId)
        .then((data) => {
          setSelectedSampleId(rememberedSampleId);
          if (data?.status) {
            setStatus(data.status);
          }

          setTimeout(() => {
            resultSectionRef.current?.scrollIntoView({
              behavior: "smooth",
              block: "start",
            });
          }, 200);
        })
        .catch(() => {
          clearSelectedSampleFromSession();
        });
    }
  }, []);

  useEffect(() => {
    if (!selectedSampleId || !showProgressModal || (!isAnalyzing && !isUploading)) return;

    const timer = setInterval(async () => {
      try {
        const statusRes = await apiGet<{ status: string }>(
          `/v1/samples/${selectedSampleId}/status`
        );
        setStatus(statusRes.status);

        if (statusRes.status === "finished" || statusRes.status === "failed") {
          clearInterval(timer);
          const resultRes = await loadResult(selectedSampleId);
          await loadSamples();
          setIsAnalyzing(false);
          setIsUploading(false);

          if (resultRes.result_ready) {
            saveSelectedSampleToSession(selectedSampleId);
            setShowProgressModal(false);
            setShowCompleteModal(true);
          }
        }
      } catch (e) {
        console.error(e);
      }
    }, 1500);

    return () => clearInterval(timer);
  }, [selectedSampleId, isAnalyzing, isUploading, showProgressModal]);

  return (
    <div style={{ minHeight: "100vh", background: "#f8fafc", padding: 24 }}>
      <input
        ref={fileInputRef}
        type="file"
        accept=".apk"
        hidden
        onChange={handleFileSelected}
      />

      <div style={{ maxWidth: 1280, margin: "0 auto" }}>
        <motion.div
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          style={{
            display: "flex",
            justifyContent: "space-between",
            gap: 16,
            alignItems: "center",
            flexWrap: "wrap",
            marginBottom: 24,
          }}
        >
          <button onClick={hardRefresh} style={titleButton}>
            <div
              style={{
                borderRadius: 24,
                background: "#0f172a",
                padding: 12,
                color: "white",
              }}
            >
              <Shield size={24} />
            </div>
            <div style={{ textAlign: "left" }}>
              <h1 style={{ margin: 0, fontSize: 32, fontWeight: 700 }}>
                APK Security Dashboard
              </h1>
              <p style={{ margin: "6px 0 0", color: "#475569", fontSize: 14 }}>
                使用者版 APK 分析平台，專注於分析結果與風險摘要。
              </p>
            </div>
          </button>

          <div style={{ display: "flex", gap: 12 }}>
            <button onClick={hardRefresh} style={buttonOutline}>
              <RefreshCw size={16} />
              <span>Refresh</span>
            </button>
            <button onClick={openUploadPicker} style={buttonPrimary}>
              <Upload size={16} />
              <span>Upload APK</span>
            </button>
          </div>
        </motion.div>

        {error && (
          <div
            style={{
              border: "1px solid #fecaca",
              background: "#fef2f2",
              color: "#b91c1c",
              borderRadius: 24,
              padding: 16,
              marginBottom: 20,
            }}
          >
            <div style={{ fontWeight: 700 }}>Analysis Error</div>
            <div style={{ marginTop: 6, fontSize: 14 }}>{error}</div>
          </div>
        )}

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
            gap: 16,
            marginBottom: 24,
          }}
        >
          <StatCard title="Total Analyses" value={stats.total} icon={<FileCode2 size={20} />} />
          <StatCard title="Finished" value={stats.finished} icon={<CheckCircle2 size={20} />} />
          <StatCard title="Running" value={stats.running} icon={<Loader2 size={20} />} />
          <StatCard title="Failed" value={stats.failed} icon={<AlertTriangle size={20} />} />
        </div>

        <section style={panelStyle}>
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              gap: 16,
              flexWrap: "wrap",
              marginBottom: 18,
            }}
          >
            <div>
              <h2 style={{ margin: 0, fontSize: 22, fontWeight: 700 }}>
                Recent Analyses
              </h2>
              <p style={{ margin: "6px 0 0", color: "#64748b", fontSize: 14 }}>
                最近分析紀錄與目前狀態。
              </p>
            </div>
            <div style={{ position: "relative", width: 320, maxWidth: "100%" }}>
              <Search
                size={16}
                style={{
                  position: "absolute",
                  left: 12,
                  top: "50%",
                  transform: "translateY(-50%)",
                  color: "#94a3b8",
                }}
              />
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search"
                style={{
                  width: "100%",
                  borderRadius: 16,
                  border: "1px solid #e2e8f0",
                  background: "#f8fafc",
                  padding: "10px 12px 10px 36px",
                }}
              />
            </div>
          </div>

          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr
                  style={{
                    borderBottom: "1px solid #e2e8f0",
                    color: "#64748b",
                    fontSize: 14,
                  }}
                >
                  <th style={thStyle}>Filename</th>
                  <th style={thStyle}>Status</th>
                  <th style={thStyle}>Uploaded</th>
                  <th style={{ ...thStyle, textAlign: "right" }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredSamples.length === 0 ? (
                  <tr>
                    <td
                      colSpan={4}
                      style={{ padding: 28, textAlign: "center", color: "#64748b" }}
                    >
                      No analysis records yet.
                    </td>
                  </tr>
                ) : (
                  filteredSamples.map((sample) => (
                    <tr
                      key={sample.sample_id}
                      style={{ borderBottom: "1px solid #f1f5f9" }}
                    >
                      <td style={tdStyle}>{sample.filename ?? sample.sample_id}</td>
                      <td style={tdStyle}>
                        <span
                          style={{
                            ...badgeStyle,
                            ...statusBadgeStyle(sample.status ?? "unknown"),
                          }}
                        >
                          {sample.status ?? "unknown"}
                        </span>
                      </td>
                      <td style={{ ...tdStyle, color: "#64748b", fontSize: 14 }}>
                        {sample.uploaded_at
                          ? new Date(sample.uploaded_at).toLocaleString()
                          : "-"}
                      </td>
                      <td style={{ ...tdStyle, textAlign: "right" }}>
                        <button
                          onClick={() => viewResult(sample.sample_id)}
                          style={ghostButton}
                        >
                          <span>View</span>
                          <ChevronRight size={16} />
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>

        <div ref={resultSectionRef} style={{ marginTop: 24 }}>
          {selectedSampleId && !result?.result_ready && (
            <section style={panelStyle}>
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  gap: 12,
                  flexWrap: "wrap",
                  alignItems: "center",
                }}
              >
                <div>
                  <h2 style={{ margin: 0, fontSize: 22, fontWeight: 700 }}>
                    Analysis Status
                  </h2>
                  <p style={{ margin: "6px 0 0", color: "#64748b", fontSize: 14 }}>
                    顯示目前選取紀錄的狀態與基本資訊。所有 View 都可以開啟這裡。
                  </p>
                </div>

                <span
                  style={{
                    ...badgeStyle,
                    ...statusBadgeStyle(effectiveStatus || "unknown"),
                  }}
                >
                  {effectiveStatus || "unknown"}
                </span>
              </div>

              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))",
                  gap: 16,
                  marginTop: 24,
                }}
              >
                <InfoCard
                  label="Filename"
                  value={selectedSample?.filename ?? selectedFile?.name ?? "-"}
                />
                <InfoCard label="Sample ID" value={selectedSampleId} />
                <InfoCard
                  label="Uploaded"
                  value={
                    selectedSample?.uploaded_at
                      ? new Date(selectedSample.uploaded_at).toLocaleString()
                      : "-"
                  }
                />
                <InfoCard
                  label="Current Status"
                  value={humanReadableStatus(effectiveStatus || "unknown")}
                />
              </div>

              <div
                style={{
                  marginTop: 24,
                  borderRadius: 24,
                  border: "1px solid #e2e8f0",
                  background: "#f8fafc",
                  padding: 24,
                }}
              >
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    gap: 16,
                    alignItems: "center",
                    flexWrap: "wrap",
                    marginBottom: 16,
                  }}
                >
                  <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
                    {effectiveStatus === "finished" ? (
                      <CheckCircle2 size={24} color="#059669" />
                    ) : effectiveStatus === "failed" ? (
                      <AlertTriangle size={24} color="#dc2626" />
                    ) : (
                      <Loader2 size={24} color="#2563eb" />
                    )}

                    <div>
                      <div style={{ fontWeight: 700 }}>
                        {humanReadableStatus(effectiveStatus || "unknown")}
                      </div>
                      <div style={{ fontSize: 14, color: "#64748b" }}>
                        {effectiveStatus === "failed"
                          ? "This analysis did not generate a report result."
                          : effectiveStatus === "received"
                          ? "This sample has been uploaded and is waiting for analysis."
                          : effectiveStatus === "running"
                          ? "This sample is currently being analyzed."
                          : effectiveStatus === "queued"
                          ? "This sample is queued and waiting to run."
                          : "This sample is available for review."}
                      </div>
                    </div>
                  </div>
                </div>

                <div
                  style={{
                    height: 14,
                    width: "100%",
                    overflow: "hidden",
                    borderRadius: 9999,
                    background: "#e2e8f0",
                  }}
                >
                  <div
                    style={{
                      height: "100%",
                      width: `${progress}%`,
                      borderRadius: 9999,
                      background: "#0f172a",
                      transition: "width 0.5s ease",
                    }}
                  />
                </div>

                <div
                  style={{
                    marginTop: 10,
                    display: "flex",
                    justifyContent: "space-between",
                    fontSize: 12,
                    color: "#64748b",
                  }}
                >
                  <span>Upload</span>
                  <span>Queue</span>
                  <span>Analysis</span>
                  <span>Finish</span>
                </div>
              </div>
            </section>
          )}

          {result?.result_ready && (
            <>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
                  gap: 16,
                  marginBottom: 24,
                }}
              >
                <StatCard title="Risk Score" value={riskScore} icon={<Shield size={20} />} />
                <StatCard title="Risk Level" value={riskLevel} icon={<AlertTriangle size={20} />} />
                <StatCard title="Findings" value={findings.length} icon={<FileCode2 size={20} />} />
                <StatCard title="Status" value={result?.status ?? effectiveStatus ?? "-"} icon={<CheckCircle2 size={20} />} />
              </div>

              <section style={panelStyle}>
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    gap: 12,
                    flexWrap: "wrap",
                    alignItems: "center",
                  }}
                >
                  <div>
                    <h2 style={{ margin: 0, fontSize: 22, fontWeight: 700 }}>
                      Analysis Summary
                    </h2>
                    <p style={{ margin: "6px 0 0", color: "#64748b", fontSize: 14 }}>
                      顯示目前選取分析紀錄的摘要結果與 findings。
                    </p>
                  </div>
                  <button onClick={downloadPdfReport} style={buttonPrimary}>
                    <Download size={16} />
                    <span>Download PDF</span>
                  </button>
                </div>

                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))",
                    gap: 16,
                    marginTop: 24,
                  }}
                >
                  <InfoCard
                    label="Filename"
                    value={selectedSample?.filename ?? selectedFile?.name ?? "-"}
                  />
                  <InfoCard label="Sample ID" value={selectedSampleId ?? "-"} />
                  <InfoCard
                    label="Started"
                    value={
                      result?.result?.started_at
                        ? new Date(result.result.started_at).toLocaleString()
                        : "-"
                    }
                  />
                  <InfoCard
                    label="Finished"
                    value={
                      result?.result?.finished_at
                        ? new Date(result.result.finished_at).toLocaleString()
                        : "-"
                    }
                  />
                </div>
              </section>

              <section style={{ ...panelStyle, marginTop: 24 }}>
                <h2 style={{ margin: 0, fontSize: 22, fontWeight: 700 }}>
                  Findings
                </h2>
                <p style={{ margin: "6px 0 0", color: "#64748b", fontSize: 14 }}>
                  偵測到的安全風險與建議處置。
                </p>

                <div
                  style={{
                    marginTop: 24,
                    display: "flex",
                    flexDirection: "column",
                    gap: 16,
                  }}
                >
                  {findings.length === 0 ? (
                    <div
                      style={{
                        borderRadius: 16,
                        border: "1px solid #e2e8f0",
                        background: "#f8fafc",
                        padding: 32,
                        textAlign: "center",
                        color: "#64748b",
                      }}
                    >
                      No findings. This sample currently shows no flagged issues.
                    </div>
                  ) : (
                    findings.map((finding, index) => (
                      <div
                        key={`${finding.id ?? finding.finding_id ?? "finding"}-${index}`}
                        style={{
                          borderRadius: 24,
                          border: "1px solid #e2e8f0",
                          background: "white",
                          padding: 20,
                        }}
                      >
                        <div
                          style={{
                            display: "flex",
                            justifyContent: "space-between",
                            gap: 12,
                            alignItems: "center",
                            flexWrap: "wrap",
                            marginBottom: 12,
                          }}
                        >
                          <div style={{ fontSize: 18, fontWeight: 700 }}>
                            {finding.title ?? "Untitled Finding"}
                          </div>
                          <span
                            style={{
                              ...badgeStyle,
                              ...riskBadgeStyle(finding.severity ?? "info"),
                            }}
                          >
                            {(finding.severity ?? "info").toUpperCase()}
                          </span>
                        </div>

                        <p
                          style={{
                            margin: 0,
                            fontSize: 14,
                            lineHeight: 1.7,
                            color: "#475569",
                          }}
                        >
                          {finding.description ?? "No description available."}
                        </p>

                        {finding.remediation && (
                          <div
                            style={{
                              marginTop: 16,
                              borderRadius: 16,
                              background: "#f8fafc",
                              padding: 16,
                            }}
                          >
                            <div
                              style={{
                                marginBottom: 6,
                                fontSize: 14,
                                fontWeight: 700,
                              }}
                            >
                              Suggested remediation
                            </div>
                            <div style={{ fontSize: 14, color: "#475569" }}>
                              {finding.remediation}
                            </div>
                          </div>
                        )}
                      </div>
                    ))
                  )}
                </div>
              </section>
            </>
          )}
        </div>
      </div>

      <AnimatePresence>
        {showProgressModal && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            style={overlayStyle}
          >
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              style={modalStyle}
            >
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  marginBottom: 16,
                }}
              >
                <div>
                  <h2 style={{ margin: 0, fontSize: 24, fontWeight: 700 }}>
                    Analysis Progress
                  </h2>
                  <p style={{ margin: "6px 0 0", color: "#64748b", fontSize: 14 }}>
                    分析進行中，完成後會自動帶到結果區塊。
                  </p>
                </div>
                <button
                  onClick={() => setShowProgressModal(false)}
                  style={iconButtonStyle}
                >
                  <X size={18} />
                </button>
              </div>

              <div
                style={{
                  display: "grid",
                  gap: 16,
                  gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
                }}
              >
                <InfoCard label="Sample ID" value={selectedSampleId ?? "-"} />
                <InfoCard
                  label="Filename"
                  value={selectedSample?.filename ?? selectedFile?.name ?? "-"}
                />
              </div>

              <div
                style={{
                  marginTop: 20,
                  borderRadius: 24,
                  border: "1px solid #e2e8f0",
                  background: "#f8fafc",
                  padding: 24,
                }}
              >
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    gap: 16,
                    alignItems: "center",
                    flexWrap: "wrap",
                    marginBottom: 16,
                  }}
                >
                  <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
                    {effectiveStatus === "finished" ? (
                      <CheckCircle2 size={24} color="#059669" />
                    ) : effectiveStatus === "failed" ? (
                      <AlertTriangle size={24} color="#dc2626" />
                    ) : (
                      <Loader2 size={24} color="#2563eb" />
                    )}
                    <div>
                      <div style={{ fontWeight: 700 }}>
                        {humanReadableStatus(effectiveStatus || "received")}
                      </div>
                      <div style={{ fontSize: 14, color: "#64748b" }}>
                        Current analysis status
                      </div>
                    </div>
                  </div>
                  <span
                    style={{
                      ...badgeStyle,
                      ...statusBadgeStyle(effectiveStatus || "received"),
                    }}
                  >
                    {effectiveStatus || "received"}
                  </span>
                </div>

                <div
                  style={{
                    height: 14,
                    width: "100%",
                    overflow: "hidden",
                    borderRadius: 9999,
                    background: "#e2e8f0",
                  }}
                >
                  <div
                    style={{
                      height: "100%",
                      width: `${progress}%`,
                      borderRadius: 9999,
                      background: "#0f172a",
                      transition: "width 0.5s ease",
                    }}
                  />
                </div>

                <div
                  style={{
                    marginTop: 10,
                    display: "flex",
                    justifyContent: "space-between",
                    fontSize: 12,
                    color: "#64748b",
                  }}
                >
                  <span>Upload</span>
                  <span>Queue</span>
                  <span>Analysis</span>
                  <span>Finish</span>
                </div>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      <AnimatePresence>
        {showCompleteModal && result?.result_ready && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            style={overlayStyle}
          >
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              style={{ ...modalStyle, maxWidth: 560 }}
            >
              <div style={{ textAlign: "center" }}>
                <div
                  style={{
                    display: "inline-flex",
                    borderRadius: 9999,
                    background: "#dcfce7",
                    padding: 16,
                    color: "#15803d",
                    marginBottom: 16,
                  }}
                >
                  <CheckCircle2 size={28} />
                </div>
                <h2 style={{ margin: 0, fontSize: 24, fontWeight: 700 }}>
                  Analysis Completed
                </h2>
                <p style={{ margin: "10px 0 0", color: "#64748b", fontSize: 14 }}>
                  分析完成，重整後會自動跳到結果區塊。你也可以直接下載 PDF。
                </p>
              </div>

              <div
                style={{
                  marginTop: 24,
                  display: "grid",
                  gap: 16,
                  gridTemplateColumns: "repeat(2, minmax(0, 1fr))",
                }}
              >
                <InfoCard label="Risk Score" value={riskScore} />
                <InfoCard label="Risk Level" value={riskLevel} />
              </div>

              <div
                style={{
                  marginTop: 24,
                  display: "flex",
                  justifyContent: "center",
                  gap: 12,
                  flexWrap: "wrap",
                }}
              >
                <button
                  onClick={() => setShowCompleteModal(false)}
                  style={buttonOutline}
                >
                  Close
                </button>
                <button onClick={goToResultAfterReload} style={buttonPrimary}>
                  Reload to Result
                </button>
                <button onClick={downloadPdfReport} style={buttonPrimary}>
                  <Download size={16} />
                  <span>Download PDF</span>
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

function StatCard({
  title,
  value,
  icon,
}: {
  title: string;
  value: React.ReactNode;
  icon: React.ReactNode;
}) {
  return (
    <div style={panelStyle}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <div style={{ fontSize: 14, color: "#64748b" }}>{title}</div>
          <div style={{ marginTop: 8, fontSize: 32, fontWeight: 700 }}>{value}</div>
        </div>
        <div style={{ borderRadius: 16, background: "#f1f5f9", padding: 12, color: "#334155" }}>
          {icon}
        </div>
      </div>
    </div>
  );
}

function InfoCard({
  label,
  value,
}: {
  label: string;
  value: React.ReactNode;
}) {
  return (
    <div
      style={{
        borderRadius: 16,
        border: "1px solid #e2e8f0",
        background: "#f8fafc",
        padding: 16,
      }}
    >
      <div
        style={{
          fontSize: 11,
          letterSpacing: 1,
          textTransform: "uppercase",
          color: "#64748b",
        }}
      >
        {label}
      </div>
      <div
        style={{
          marginTop: 8,
          wordBreak: "break-all",
          fontSize: 14,
          fontWeight: 600,
        }}
      >
        {value}
      </div>
    </div>
  );
}

const panelStyle: React.CSSProperties = {
  borderRadius: 24,
  background: "white",
  padding: 24,
  boxShadow: "0 1px 3px rgba(15,23,42,0.08)",
};

const buttonPrimary: React.CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  gap: 8,
  borderRadius: 16,
  background: "#0f172a",
  color: "white",
  border: "none",
  padding: "10px 16px",
  fontWeight: 600,
  cursor: "pointer",
};

const buttonOutline: React.CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  gap: 8,
  borderRadius: 16,
  background: "white",
  color: "#334155",
  border: "1px solid #e2e8f0",
  padding: "10px 16px",
  fontWeight: 600,
  cursor: "pointer",
};

const ghostButton: React.CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  gap: 8,
  borderRadius: 16,
  background: "transparent",
  color: "#334155",
  border: "none",
  padding: "8px 12px",
  fontWeight: 600,
  cursor: "pointer",
};

const titleButton: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: 16,
  background: "transparent",
  border: "none",
  padding: 0,
  cursor: "pointer",
};

const badgeStyle: React.CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  borderRadius: 9999,
  padding: "6px 12px",
  fontSize: 12,
  fontWeight: 700,
};

const thStyle: React.CSSProperties = {
  paddingBottom: 12,
  fontWeight: 600,
};

const tdStyle: React.CSSProperties = {
  padding: "16px 0",
};

const overlayStyle: React.CSSProperties = {
  position: "fixed",
  inset: 0,
  background: "rgba(15, 23, 42, 0.45)",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  padding: 24,
  zIndex: 999,
};

const modalStyle: React.CSSProperties = {
  width: "100%",
  maxWidth: 760,
  borderRadius: 28,
  background: "white",
  padding: 24,
  boxShadow: "0 20px 50px rgba(15,23,42,0.18)",
};

const iconButtonStyle: React.CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  justifyContent: "center",
  width: 40,
  height: 40,
  borderRadius: 9999,
  border: "1px solid #e2e8f0",
  background: "white",
  cursor: "pointer",
};