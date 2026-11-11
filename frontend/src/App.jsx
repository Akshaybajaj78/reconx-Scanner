import React, { useState } from "react";

function normalizeTarget(raw) {
  const value = raw.trim();
  if (!value) {
    return "http://127.0.0.1:5000";
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

const SCAN_TYPES = [
  { value: "quick", label: "Quick (top 100 ports)" },
  { value: "standard", label: "Standard (top 1000 + service detection)" },
  { value: "comprehensive", label: "Comprehensive (top 1000 + OS + NSE scripts)" },
  { value: "udp", label: "UDP (top 100)" },
  { value: "custom", label: "Custom ports" },
];

function App() {
  const [target, setTarget] = useState("");
  const [scanType, setScanType] = useState("standard");
  const [customPorts, setCustomPorts] = useState("");
  const [enableOs, setEnableOs] = useState(false);
  const [enableScripts, setEnableScripts] = useState(false);
  const [subdomainUseCtsh, setSubdomainUseCtsh] = useState(true);
  const [subdomainUseDns, setSubdomainUseDns] = useState(true);
  const [subdomainProbeLive, setSubdomainProbeLive] = useState(true);
  const [pathUseApiDocs, setPathUseApiDocs] = useState(true);
  const [pathAggressive, setPathAggressive] = useState(false);
  const [pathMethods, setPathMethods] = useState("GET,HEAD,OPTIONS");
  const [isScanning, setIsScanning] = useState(false);
  const [inputWarn, setInputWarn] = useState(false);

  const [portsMeta, setPortsMeta] = useState("To Be Scanned");
  const [subMeta, setSubMeta] = useState("To Be Scanned");
  const [pathsMeta, setPathsMeta] = useState("To Be Scanned");
  const [vulnMeta, setVulnMeta] = useState("To Be Scanned");

  const [ports, setPorts] = useState(["Top 1000 TCP ports", "Open port discovery"]);
  const [subdomains, setSubdomains] = useState([
    "Certificate Transparency (crt.sh)",
    "DNS brute-force + live probing",
  ]);
  const [paths, setPaths] = useState(["Directories from wordlist", "Valid path discovery"]);
  const [apiEndpoints, setApiEndpoints] = useState([]);
  const [apiDocs, setApiDocs] = useState([]);
  const [vulns, setVulns] = useState([
    "Missing security headers",
    "CORS configuration",
    "Basic XSS reflection",
  ]);

  const [reports, setReports] = useState([
    { value: "/reports/reconx_report.pdf", label: "reconx_report.pdf" },
    { value: "/reports/reconx_report_2.pdf", label: "reconx_report_2.pdf" },
  ]);
  const [selectedReport, setSelectedReport] = useState("/reports/reconx_report.pdf");
  const [portScanSummary, setPortScanSummary] = useState(null);
  const [osMatches, setOsMatches] = useState([]);
  const [subdomainSummary, setSubdomainSummary] = useState(null);
  const [pathScanSummary, setPathScanSummary] = useState(null);
  const [vulnSummary, setVulnSummary] = useState(null);
  const [vulnFindings, setVulnFindings] = useState([]);
  const [techStack, setTechStack] = useState([]);
  const [techSummary, setTechSummary] = useState(null);

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
    setPortScanSummary(null);
    setOsMatches([]);
    setSubdomainSummary(null);
    setPathScanSummary(null);
    setApiEndpoints([]);
    setApiDocs([]);
    setVulnSummary(null);
    setVulnFindings([]);
    setTechStack([]);
    setTechSummary(null);

    try {
      const body = {
        target: normalizeTarget(target),
        scan_type: scanType,
        ports: scanType === "custom" ? customPorts : undefined,
        enable_os: enableOs,
        enable_scripts: enableScripts,
        subdomain_use_ctsh: subdomainUseCtsh,
        subdomain_use_dns: subdomainUseDns,
        subdomain_probe_live: subdomainProbeLive,
        path_use_api_docs: pathUseApiDocs,
        path_aggressive: pathAggressive,
        path_methods: pathMethods,
      };

      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });

      if (!res.ok) {
        throw new Error("Scan failed");
      }

      const data = await res.json();

      setPortsMeta("Open Ports");
      setSubMeta("Discovered Subdomains");
      setPathsMeta("Discovered Paths");
      setVulnMeta("Vulnerabilities");

      // Ports
      if (data.open_ports_detail && data.open_ports_detail.length) {
        setPorts(
          data.open_ports_detail.map((p) => {
            const svc = [p.service, p.product, p.version].filter(Boolean).join(" ") || "unknown";
            return `${p.port}/${p.protocol} — ${svc}${p.extrainfo ? ` (${p.extrainfo})` : ""}${
              p.banner ? ` | banner: ${p.banner}` : ""
            }`;
          })
        );
      } else if (data.open_ports?.length) {
        setPorts(data.open_ports);
      } else {
        setPorts(["No open ports found."]);
      }

      setPortScanSummary(data.port_scan_summary || null);
      setOsMatches(data.os_matches || []);

      // Subdomains
      if (data.subdomains && data.subdomains.length) {
        setSubdomains(
          data.subdomains.map((s) => {
            const ip = s.ip || "—";
            const method = s.method || "—";
            const status = s.status_code !== undefined ? s.status_code : "—";
            const title = s.title || "";
            return `${s.subdomain} | ${ip} | ${method} | status=${status} | ${title}`;
          })
        );
        setSubdomainSummary(data.subdomain_summary || null);
      } else {
        setSubdomains(["No subdomains found."]);
        setSubdomainSummary(null);
      }

      // Paths / API endpoints
      if (data.discovered_paths && data.discovered_paths.length) {
        setPaths(
          data.discovered_paths.map((p) => {
            const typeTag = [];
            if (p.is_api_doc) typeTag.push("API-DOC");
            if (p.is_api) typeTag.push("API");
            const tag = typeTag.length ? ` [${typeTag.join("/")}]` : "";
            return `${p.method} ${p.path} (${p.status_code}) ${p.content_type || "—"}${tag}`;
          })
        );
        setApiEndpoints(
          (data.api_endpoints || []).map((p) => ({
            method: p.method,
            path: p.path,
            status: p.status_code,
            contentType: p.content_type || "—",
            size: p.content_length || "—",
          }))
        );
        setApiDocs(
          (data.api_docs || []).map((p) => ({
            method: p.method,
            path: p.path,
            status: p.status_code,
          }))
        );
        setPathScanSummary(data.path_scan_summary || null);
      } else {
        setPaths(["No paths found."]);
        setApiEndpoints([]);
        setApiDocs([]);
        setPathScanSummary(null);
      }

      // Vulnerabilities — render rich finding objects.
      if (data.vulnerabilities && Array.isArray(data.vulnerabilities) && data.vulnerabilities.length) {
        setVulnFindings(data.vulnerabilities);
        setVulnSummary(data.vuln_summary || null);
        setVulns(
          data.vulnerabilities.map((v) => {
            const sev = v.severity || "info";
            return `[${sev.toUpperCase()}] ${v.title} — ${v.description} [${v.category}]`;
          })
        );
      } else {
        setVulns(["No vulnerabilities detected."]);
        setVulnFindings([]);
        setVulnSummary(null);
      }

      // Technology stack — render rich technology objects with descriptions.
      if (data.tech_stack && Array.isArray(data.tech_stack) && data.tech_stack.length) {
        setTechStack(data.tech_stack);
        setTechSummary(data.tech_summary || null);
      } else {
        setTechStack([]);
        setTechSummary(null);
      }

      if (data.report) {
        const label = data.report.split("/").pop();
        setReports((prev) => {
          const filtered = prev.filter((r) => r.value !== data.report);
          return [{ value: data.report, label }, ...filtered];
        });
        setSelectedReport(data.report);
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
                <li>Choose a scan type (Quick / Standard / Comprehensive / UDP / Custom).</li>
                <li>Toggle subdomain options (CT.sh, DNS brute-force, live probe) as needed.</li>
                <li>Toggle path options (API docs, aggressive scan, HTTP methods) to discover endpoints.</li>
                <li>Click Start Scan to detect ports, subdomains, paths, tech stack, and vulnerabilities.</li>
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
              placeholder={inputWarn ? "Please enter a target URL..." : "e.g. google.com"}
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            />
          </div>

          <div className="scan-controls">
            <label className="scan-label">Scan Type</label>
            <select
              className="select"
              id="scanType"
              value={scanType}
              onChange={(e) => setScanType(e.target.value)}
            >
              {SCAN_TYPES.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>

            {scanType === "custom" && (
              <div className="custom-ports">
                <label className="scan-label">Ports (comma-separated)</label>
                <input
                  className="scan-input"
                  id="customPorts"
                  placeholder="e.g. 22,80,443,8080"
                  value={customPorts}
                  onChange={(e) => setCustomPorts(e.target.value)}
                />
              </div>
            )}

            <div className="scan-toggles">
              <label className="toggle-label">
                <input
                  type="checkbox"
                  checked={enableOs}
                  onChange={(e) => setEnableOs(e.target.checked)}
                />
                OS fingerprinting
              </label>
              <label className="toggle-label">
                <input
                  type="checkbox"
                  checked={enableScripts}
                  onChange={(e) => setEnableScripts(e.target.checked)}
                />
                NSE scripts
              </label>
            </div>

            <div className="scan-toggles">
              <label className="toggle-label">
                <input
                  type="checkbox"
                  checked={subdomainUseCtsh}
                  onChange={(e) => setSubdomainUseCtsh(e.target.checked)}
                />
                Subdomain CT.sh
              </label>
              <label className="toggle-label">
                <input
                  type="checkbox"
                  checked={subdomainUseDns}
                  onChange={(e) => setSubdomainUseDns(e.target.checked)}
                />
                Subdomain DNS brute
              </label>
              <label className="toggle-label">
                <input
                  type="checkbox"
                  checked={subdomainProbeLive}
                  onChange={(e) => setSubdomainProbeLive(e.target.checked)}
                />
                Probe live
              </label>
            </div>

            <div className="scan-toggles">
              <label className="toggle-label">
                <input
                  type="checkbox"
                  checked={pathUseApiDocs}
                  onChange={(e) => setPathUseApiDocs(e.target.checked)}
                />
                Path API docs
              </label>
              <label className="toggle-label">
                <input
                  type="checkbox"
                  checked={pathAggressive}
                  onChange={(e) => setPathAggressive(e.target.checked)}
                />
                Path aggressive
              </label>
              <label className="toggle-label">
                <input
                  className="methods-input"
                  type="text"
                  placeholder="GET,HEAD,OPTIONS"
                  value={pathMethods}
                  onChange={(e) => setPathMethods(e.target.value)}
                />
                Methods
              </label>
            </div>
          </div>

          <button
            className={`btn-primary ${isScanning ? "pulse" : ""}`}
            id="startScan"
            onClick={runScan}
          >
            {isScanning ? "Scanning..." : "Start Scan"}
          </button>
        </section>

        {/* Port scan summary strip */}
        {portScanSummary && (
          <section className="summary-strip">
            <span className="summary-label">Port scan</span>
            <span className="summary-value">
              {portScanSummary.open} open of {portScanSummary.scanned} scanned
            </span>
            <span className="summary-type">({portScanSummary.scan_type})</span>
          </section>
        )}

        {/* Subdomain scan summary strip */}
        {subdomainSummary && (
          <section className="summary-strip">
            <span className="summary-label">Subdomains</span>
            <span className="summary-value">
              {subdomainSummary.total} found
            </span>
            <span className="summary-type">
              {Object.entries(subdomainSummary.methods || {})
                .map(([k, v]) => `${k}=${v}`)
                .join(", ")}
            </span>
          </section>
        )}

        {/* Path scan summary strip */}
        {pathScanSummary && (
          <section className="summary-strip">
            <span className="summary-label">Paths</span>
            <span className="summary-value">
              {pathScanSummary.total} found
            </span>
            <span className="summary-type">
              {pathScanSummary.api_count} API • {pathScanSummary.docs_count} Docs
            </span>
          </section>
        )}

        {/* Vulnerability summary strip */}
        {vulnSummary && (
          <section className="summary-strip">
            <span className="summary-label">Vulnerabilities</span>
            <span className="summary-value">
              {vulnSummary.total} found
            </span>
            <span className="summary-type">
              high={vulnSummary.by_severity.high} • medium={vulnSummary.by_severity.medium} • low={vulnSummary.by_severity.low} • info={vulnSummary.by_severity.info}
            </span>
          </section>
        )}

        {/* Technology stack summary strip */}
        {techSummary && (
          <section className="summary-strip">
            <span className="summary-label">Tech Stack</span>
            <span className="summary-value">
              {techSummary.total} detected
            </span>
            <span className="summary-type">
              {techSummary.categories} categories
            </span>
          </section>
        )}

        {/* API documentation endpoints */}
        {apiDocs.length > 0 && (
          <section className="api-docs-section">
            <h4>API Documentation Endpoints</h4>
            <ul className="list">
              {apiDocs.map((doc, i) => (
                <li key={i}>{doc.method} {doc.path} (status {doc.status})</li>
              ))}
            </ul>
          </section>
        )}

        {/* OS fingerprint matches */}
        {osMatches.length > 0 && (
          <section className="os-matches">
            <h4>OS Fingerprint Matches</h4>
            <ul className="list">
              {osMatches.map((om, i) => (
                <li key={i}>{om.name} (accuracy: {om.accuracy}%)</li>
              ))}
            </ul>
          </section>
        )}

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
              {subdomains.map((item, idx) => {
                const displayItem =
                  typeof item === "object" && item !== null
                    ? `${item.subdomain || item} | ${item.ip || "—"} | ${item.method || "—"} | status=${item.status_code !== undefined ? item.status_code : "—"} | ${item.title || ""}`
                    : item;
                return <li key={`sub-${idx}-${displayItem}`}>{displayItem}</li>;
              })}
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
              {paths.map((item, idx) => {
                const displayItem =
                  typeof item === "object" && item !== null
                    ? `${item.method || item} ${item.path || ""} (${item.status || "—"}) ${item.contentType || "—"}`
                    : item;
                return <li key={`paths-${idx}-${displayItem}`}>{displayItem}</li>;
              })}
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
              {vulns.map((item, idx) => {
                const isObj = typeof item === "object" && item !== null;
                const sev = isObj ? (item.severity || "info") : "info";
                const sevClass = `vuln-${sev}`;
                const displayItem = isObj
                  ? `[${sev.toUpperCase()}] ${item.title} — ${item.category}`
                  : item;
                return (
                  <li key={`vuln-${idx}-${displayItem}`} className={sevClass}>
                    {displayItem}
                  </li>
                );
              })}
            </ul>
          </article>

          <article className="card card-purple">
            <header className="card-title">
              <span className="card-icon">⚙️</span>
              <h3>Technology Stack</h3>
            </header>
            <div className="card-meta" id="techStackMeta">
              {techSummary ? `${techSummary.total} technologies • ${techSummary.categories} categories` : "To Be Scanned"}
            </div>
            <ul className="list" id="techStackList">
              {techStack.length > 0 ? techStack.map((t, idx) => (
                <li key={`tech-${idx}-${t.name}`}>
                  <span className={`tech-badge tech-${t.category}`}>{t.category}</span>
                  <strong>{t.name}</strong>
                  <span className="tech-confidence">[{t.confidence}]</span>
                  <p className="tech-desc">{t.description}</p>
                </li>
              )) : [<li key="tech-none">No technologies detected.</li>]}
            </ul>
          </article>
        </section>

        <section className="status-row">
          <button className="status-pill link" id="techStackLink" onClick={openTechStack}>
            {techStack.length > 0
              ? `Tech Stack: ${techStack.map(t => t.name).join(" | ")}`
              : "Tech Stack: To Be Scanned"}
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
