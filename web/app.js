const startBtn = document.getElementById("startScan");
const targetInput = document.getElementById("target");
const techStackLink = document.getElementById("techStackLink");
const loginLink = document.getElementById("loginLink");
const exportBtn = document.getElementById("exportBtn");
const reportSelect = document.getElementById("reportSelect");
const cards = document.querySelectorAll(".card");
const portsMeta = document.getElementById("portsMeta");
const subdomainsMeta = document.getElementById("subdomainsMeta");
const pathsMeta = document.getElementById("pathsMeta");
const vulnsMeta = document.getElementById("vulnsMeta");
const portsList = document.getElementById("portsList");
const subdomainsList = document.getElementById("subdomainsList");
const pathsList = document.getElementById("pathsList");
const vulnsList = document.getElementById("vulnsList");

startBtn.addEventListener("click", () => {
  const raw = targetInput.value.trim();
  if (!raw) {
    targetInput.classList.add("input-warn");
    targetInput.placeholder = "Please enter a target URL...";
    setTimeout(() => targetInput.classList.remove("input-warn"), 800);
    return;
  }

  startBtn.classList.add("pulse");
  startBtn.textContent = "Scanning...";

  setCardState("Scanning...", "Queued: awaiting results...");
  runScan();
});

function normalizeTarget() {
  const raw = targetInput.value.trim();
  if (!raw) {
    return "http://127.0.0.1:3000";
  }
  if (raw.startsWith("http://") || raw.startsWith("https://")) {
    return raw;
  }
  return `http://${raw}`;
}

function openLoginPage() {
  const normalized = normalizeTarget();
  let loginUrl = normalized;

  if (!/login|signin/i.test(normalized)) {
    const isJuiceShop = /juice/i.test(normalized) || /:3000/.test(normalized);
    if (normalized.includes("#/")) {
      loginUrl = normalized.replace(/#\/?.*$/, "#/login");
    } else if (isJuiceShop) {
      loginUrl = normalized.replace(/\/+$/, "") + "/#/login";
    } else {
      loginUrl = normalized.replace(/\/+$/, "") + "/login";
    }
  }

  window.open(loginUrl, "_blank");
}

function openTechStackPage() {
  const base = normalizeTarget().replace(/\/+$/, "");
  window.open(base, "_blank");
}

techStackLink.addEventListener("click", openTechStackPage);
loginLink.addEventListener("click", openLoginPage);

exportBtn.addEventListener("click", () => {
  const reportUrl = reportSelect.value;
  const link = document.createElement("a");
  link.href = reportUrl;
  link.target = "_blank";
  link.rel = "noopener";
  link.click();
});

function setCardState(metaText, itemText) {
  cards.forEach((card) => {
    const meta = card.querySelector(".card-meta");
    const list = card.querySelector(".list");
    if (meta) {
      meta.textContent = metaText;
    }
    if (list) {
      list.innerHTML = "";
      const li = document.createElement("li");
      li.textContent = itemText;
      list.appendChild(li);
    }
  });
}

function renderList(listEl, items, emptyText) {
  listEl.innerHTML = "";
  if (!items || items.length === 0) {
    const li = document.createElement("li");
    li.textContent = emptyText;
    listEl.appendChild(li);
    return;
  }
  items.forEach((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    listEl.appendChild(li);
  });
}

async function runScan() {
  const target = normalizeTarget();
  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target }),
    });

    if (!res.ok) {
      throw new Error("Scan failed");
    }

    const data = await res.json();

    portsMeta.textContent = "Open Ports";
    subdomainsMeta.textContent = "Discovered Subdomains";
    pathsMeta.textContent = "Discovered Paths";
    vulnsMeta.textContent = "Vulnerabilities";

    renderList(portsList, data.open_ports, "No open ports found.");
    renderList(subdomainsList, data.subdomains, "No subdomains found.");
    renderList(pathsList, data.discovered_paths, "No paths found.");
    renderList(vulnsList, data.vulnerabilities, "No vulnerabilities detected.");

    if (data.report) {
      const option = document.createElement("option");
      option.value = data.report;
      option.textContent = data.report.split("/").pop();
      reportSelect.insertBefore(option, reportSelect.firstChild);
      reportSelect.value = option.value;
    }
  } catch (err) {
    setCardState("Scan Failed", "Check backend and try again.");
  } finally {
    startBtn.classList.remove("pulse");
    startBtn.textContent = "Start Scan";
  }
}
