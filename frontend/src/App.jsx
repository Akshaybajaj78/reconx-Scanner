import React, { useState } from "react";
const API_BASE = (import.meta.env.VITE_API_BASE || "").replace(/\/+$/, "");

function normalizeTarget(raw) {
  const value = raw.trim();
  if (!value) {
    return "http://127.0.0.1:3000";
  }
  if (value.startsWith("http://") || value.startsWith("https://")) {
    return value;
  }
  return `http://${value}`;
}

function resolveLoginUrl(rawTarget) {
  const normalized = normalizeTarget(rawTarget);
  if (/login|signin/i.test(normalized)) {
    return normalized;
  }

  if (normalized.includes("#/")) {
    return normalized.replace(/#\/?.*$/, "#/login");
  }

  const isJuiceShop = /juice/i.test(normalized) || /:3000/.test(normalized);
  if (isJuiceShop) {
    return `${normalized.replace(/\/+$/, "")}/#/login`;
  }

  return `${normalized.replace(/\/+$/, "")}/login`;
}

function App() {
  const [target, setTarget] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [inputWarn, setInputWarn] = useState(false);

  const [portsMeta, setPortsMeta] = useState("To Be Scanned");
  const [subMeta, setSubMeta] = useState("To Be Scanned");
  const [pathsMeta, setPathsMeta] = useState("To Be Scanned");
  const [vulnMeta, setVulnMeta] = useState("To Be Scanned");

  const [ports, setPorts] = useState(["Top 1000 TCP ports", "Open port discovery"]);
  const [subdomains, setSubdomains] = useState(["Common subdomains", "HTTP/HTTPS validation"]);
  const [paths, setPaths] = useState(["Directories from wordlist", "Valid path discovery"]);
  const [vulns, setVulns] = useState([
    "Missing security headers",
    "CORS configuration",
    "Basic XSS reflection",
  ]);

  const [reports, setReports] = useState([
    { value: `${API_BASE}/reports/reconx_report.pdf`, label: "reconx_report.pdf" },
    { value: `${API_BASE}/reports/reconx_report_2.pdf`, label: "reconx_report_2.pdf" },
  ]);
  const [selectedReport, setSelectedReport] = useState(`${API_BASE}/reports/reconx_report.pdf`);

  function setAllMeta(meta) {
    setPortsMeta(meta);
    setSubMeta(meta);
    setPathsMeta(meta);
    setVulnMeta(meta);
  }

  function setAllLists(itemText) {
    setPorts([itemText]);
    setSubdomains([itemText]);
    setPaths([itemText]);
    setVulns([itemText]);
  }

  async function runScan() {
    if (!target.trim()) {
      setInputWarn(true);
      window.setTimeout(() => setInputWarn(false), 800);
      return;
    }

    setIsScanning(true);
    setAllMeta("Scanning...");
    setAllLists("Queued: awaiting results...");

    try {
      const res = await fetch(`${API_BASE}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: normalizeTarget(target) }),
      });

      if (!res.ok) {
        throw new Error("Scan failed");
      }

      const data = await res.json();

      setPortsMeta("Open Ports");
      setSubMeta("Discovered Subdomains");
      setPathsMeta("Discovered Paths");
      setVulnMeta("Vulnerabilities");

      setPorts(data.open_ports?.length ? data.open_ports : ["No open ports found."]);
      setSubdomains(data.subdomains?.length ? data.subdomains : ["No subdomains found."]);
      setPaths(data.discovered_paths?.length ? data.discovered_paths : ["No paths found."]);
      setVulns(data.vulnerabilities?.length ? data.vulnerabilities : ["No vulnerabilities detected."]);

      if (data.report) {
        const reportUrl = /^https?:\/\//i.test(data.report)
          ? data.report
          : `${API_BASE}${data.report}`;
        const label = reportUrl.split("/").pop();
        setReports((prev) => {
          const filtered = prev.filter((r) => r.value !== reportUrl);
          return [{ value: reportUrl, label }, ...filtered];
        });
        setSelectedReport(reportUrl);
      }
    } catch (_error) {
      setAllMeta("Scan Failed");
      setAllLists("Check backend and try again.");
    } finally {
      setIsScanning(false);
    }
  }

  function openTechStack() {
    const base = normalizeTarget(target).replace(/\/+$/, "");
    window.open(base, "_blank", "noopener");
  }

  function openLogin() {
    window.open(resolveLoginUrl(target), "_blank", "noopener");
  }

  function exportReport() {
    if (!selectedReport) {
      return;
    }
    window.open(selectedReport, "_blank", "noopener");
  }

  return (
    <>
      <video className="bg-video" autoPlay muted loop playsInline>
        <source src="/assets/meri.mp4" type="video/mp4" />
      </video>
      <div className="bg-grid"></div>
      <div className="bg-glow"></div>
      <div className="bg-live"></div>

      <header className="topbar">
        <div className="logo">
          <span className="logo-mark">RECON</span>
          <span className="logo-x">X</span>
        </div>
        <div className="tagline">Automated Reconnaissance &amp; Vulnerability Scanner</div>
        <div className="crazy-text">CYBER-TRIAGE / SIGNAL ACTIVE / VECTOR GRID ONLINE</div>
        <div className="credit-line">Developed by Akshay Bajaj and Deepanshi Malhotra</div>
      </header>

      <main className="container">
        <section className="instructions">
          <details>
            <summary>How to Use This Site</summary>
            <div className="instructions-body">
              <ol className="instructions-list">
                <li>Enter a target URL or domain in the Target URL box.</li>
                <li>Click Start Scan to begin the scan flow.</li>
                <li>Click Tech Stack Detected to open the target home page.</li>
                <li>Click Login Page Detected to open the target login page.</li>
                <li>Use Export Report to open the latest report PDF.</li>
              </ol>
            </div>
          </details>
        </section>

        <section className="scan-bar">
          <div className="scan-shell">
            <label className="scan-label" htmlFor="target">
              Target URL
            </label>
            <input
              id="target"
              className={`scan-input ${inputWarn ? "input-warn" : ""}`}
              placeholder={inputWarn ? "Please enter a target URL..." : "Type here..."}
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            />
          </div>
          <button className={`btn-primary ${isScanning ? "pulse" : ""}`} id="startScan" onClick={runScan}>
            {isScanning ? "Scanning..." : "Start Scan"}
          </button>
        </section>

        <section className="cards">
          <article className="card card-red">
            <header className="card-title">
              <span className="card-icon">◉</span>
              <h3>Open Ports</h3>
            </header>
            <div className="card-meta" id="portsMeta">
              {portsMeta}
            </div>
            <ul className="list" id="portsList">
              {ports.map((item, idx) => (
                <li key={`ports-${idx}-${item}`}>{item}</li>
              ))}
            </ul>
          </article>

          <article className="card card-blue">
            <header className="card-title">
              <span className="card-icon">◎</span>
              <h3>Subdomains</h3>
            </header>
            <div className="card-meta" id="subdomainsMeta">
              {subMeta}
            </div>
            <ul className="list" id="subdomainsList">
              {subdomains.map((item, idx) => (
                <li key={`sub-${idx}-${item}`}>{item}</li>
              ))}
            </ul>
          </article>

          <article className="card card-green">
            <header className="card-title">
              <span className="card-icon">⬢</span>
              <h3>Discovered Paths</h3>
            </header>
            <div className="card-meta" id="pathsMeta">
              {pathsMeta}
            </div>
            <ul className="list" id="pathsList">
              {paths.map((item, idx) => (
                <li key={`paths-${idx}-${item}`}>{item}</li>
              ))}
            </ul>
          </article>

          <article className="card card-orange">
            <header className="card-title">
              <span className="card-icon">✦</span>
              <h3>Vulnerabilities</h3>
            </header>
            <div className="card-meta" id="vulnsMeta">
              {vulnMeta}
            </div>
            <ul className="list" id="vulnsList">
              {vulns.map((item, idx) => (
                <li key={`vuln-${idx}-${item}`}>{item}</li>
              ))}
            </ul>
          </article>
        </section>

        <section className="status-row">
          <button className="status-pill link" id="techStackLink" onClick={openTechStack}>
            Tech Stack Detected: Apache | PHP
          </button>
          <button className="status-pill good link" id="loginLink" onClick={openLogin}>
            Login Page Detected
          </button>
        </section>

        <section className="export-row">
          <div className="export-left">
            <span className="label">Scan Summary</span>
            <select
              className="select"
              id="reportSelect"
              value={selectedReport}
              onChange={(e) => setSelectedReport(e.target.value)}
            >
              {reports.map((report) => (
                <option key={report.value} value={report.value}>
                  {report.label}
                </option>
              ))}
            </select>
          </div>
          <button className="btn-secondary" id="exportBtn" onClick={exportReport}>
            Export Report
          </button>
        </section>
      </main>
      <footer className="footer">© 2026 ReconX. All rights reserved.</footer>
    </>
  );
}

export default App;
