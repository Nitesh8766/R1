// Malware Static Analysis Workbench -- frontend logic.
// STATIC ANALYSIS ONLY: this script never executes, opens, or navigates to
// anything extracted from an analyzed sample (URLs/paths/strings are only
// ever displayed as text).

(() => {
  const state = {
    selectedFile: null,
    result: null,
    historyId: null,
    stringPage: 0,
    stringPageSize: 40,
    findingsFilter: { search: "", category: "", severity: "", sort: "score_desc" },
  };

  const $ = (id) => document.getElementById(id);

  // ---------------------------------------------------------------------
  // Upload / dropzone
  // ---------------------------------------------------------------------
  const dropzone = $("dropzone");
  const fileInput = $("file-input");
  const analyzeBtn = $("analyze-btn");
  const clearBtn = $("clear-btn");
  const statusLine = $("status-line");

  dropzone.addEventListener("click", () => fileInput.click());
  dropzone.addEventListener("dragover", (e) => { e.preventDefault(); dropzone.classList.add("dragover"); });
  dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));
  dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("dragover");
    if (e.dataTransfer.files.length) selectFile(e.dataTransfer.files[0]);
  });
  fileInput.addEventListener("change", () => {
    if (fileInput.files.length) selectFile(fileInput.files[0]);
  });

  function selectFile(file) {
    state.selectedFile = file;
    $("selected-filename").textContent = `${file.name} (${file.size.toLocaleString()} bytes)`;
    analyzeBtn.disabled = false;
    clearBtn.disabled = false;
    setStatus("", false);
  }

  clearBtn.addEventListener("click", () => {
    state.selectedFile = null;
    fileInput.value = "";
    $("selected-filename").textContent = "";
    analyzeBtn.disabled = true;
    clearBtn.disabled = true;
    setStatus("", false);
    $("results").classList.add("hidden");
  });

  function setStatus(msg, isError) {
    statusLine.textContent = msg;
    statusLine.classList.toggle("error", !!isError);
  }

  analyzeBtn.addEventListener("click", async () => {
    if (!state.selectedFile) return;
    analyzeBtn.disabled = true;
    setStatus("Analyzing sample statically (the file is never executed)...", false);

    const formData = new FormData();
    formData.append("file", state.selectedFile);

    try {
      const resp = await fetch("/api/analyze", { method: "POST", body: formData });
      const data = await resp.json();
      if (!resp.ok) {
        setStatus(`Error: ${data.error || "analysis failed"}`, true);
        analyzeBtn.disabled = false;
        return;
      }
      if (data.error || !data.risk || data.risk.verdict === null) {
        setStatus(`Error: ${data.error || "analysis did not produce a result"}`, true);
        analyzeBtn.disabled = false;
        return;
      }
      state.historyId = data.history_id || null;
      renderResult(data);
      setStatus("Analysis complete.", false);
      loadHistory();
    } catch (err) {
      setStatus(`Request failed: ${err}`, true);
    } finally {
      analyzeBtn.disabled = false;
    }
  });

  // ---------------------------------------------------------------------
  // Render: main dispatch
  // ---------------------------------------------------------------------
  function renderResult(result) {
    state.result = result;
    state.stringPage = 0;
    state.findingsFilter = { search: "", category: "", severity: "", sort: "score_desc" };
    $("findings-search").value = "";
    $("string-search").value = "";

    $("results").classList.remove("hidden");
    renderRiskOverview(result);
    renderFileInfo(result);
    renderCategoryBars(result);
    populateCategoryFilter(result);
    renderFindings();
    renderPEInfo(result);
    renderEntropyBars(result);
    renderImports(result);
    renderStrings();
    renderIOCs(result);
    renderMitre(result);
  }

  // ---------------------------------------------------------------------
  // Risk overview
  // ---------------------------------------------------------------------
  function renderRiskOverview(result) {
    const { raw_score, normalized_score, verdict } = result.risk;
    const gauge = $("risk-gauge");
    const color = verdict === "HIGH" ? "#ff4d4f" : verdict === "MEDIUM" ? "#ffa940" : "#52c41a";
    const pct = Math.max(0, Math.min(100, normalized_score));
    const deg = (pct / 100) * 360;
    gauge.style.background = `conic-gradient(${color} ${deg}deg, #21262d ${deg}deg)`;
    $("risk-score-num").textContent = normalized_score;

    const verdictEl = $("verdict-label");
    verdictEl.textContent = emojiFor(verdict) + " " + verdict + " RISK";
    verdictEl.className = "verdict-label " + verdict;

    $("finding-count").textContent = `${result.findings.length} suspicious indicator(s)`;
    $("category-count").textContent = `${Object.keys(result.categories).length} detection categor${Object.keys(result.categories).length === 1 ? "y" : "ies"}`;
  }

  function emojiFor(verdict) {
    return verdict === "HIGH" ? "🔴" : verdict === "MEDIUM" ? "🟡" : "🟢";
  }

  // ---------------------------------------------------------------------
  // File info
  // ---------------------------------------------------------------------
  function renderFileInfo(result) {
    const rows = [
      ["Filename", result.file.name],
      ["Size", `${result.file.size.toLocaleString()} bytes`],
      ["SHA-256", result.file.sha256],
      ["File type", result.pe.is_pe ? "Windows PE" : "Non-PE / unrecognized"],
      ["Analyzed at", result.meta.analyzed_at],
    ];
    if (result.pe.is_pe) {
      rows.push(
        ["Machine", result.pe.machine],
        ["Subsystem", result.pe.subsystem],
        ["Sections", result.pe.sections],
        ["Imports", result.pe.num_imports],
        ["Signed", result.pe.is_signed === true ? "Yes" : result.pe.is_signed === false ? "No" : "Unknown"],
      );
    }
    $("file-info-table").innerHTML = rows.map(([k, v]) => `<tr><td>${escapeHtml(k)}</td><td>${escapeHtml(String(v))}</td></tr>`).join("");
  }

  $("copy-hash-btn").addEventListener("click", () => {
    if (!state.result) return;
    navigator.clipboard.writeText(state.result.file.sha256).then(() => {
      setStatus("SHA-256 copied to clipboard.", false);
    });
  });

  $("report-btn").addEventListener("click", () => {
    if (!state.historyId) {
      setStatus("Report is available after the analysis is saved to history.", true);
      return;
    }
    window.open(`/api/report/${state.historyId}`, "_blank");
  });

  // ---------------------------------------------------------------------
  // Category breakdown
  // ---------------------------------------------------------------------
  function renderCategoryBars(result) {
    const entries = Object.entries(result.categories).sort((a, b) => b[1] - a[1]);
    const max = entries.length ? entries[0][1] : 1;
    $("category-bars").innerHTML = entries.length
      ? entries.map(([cat, pts]) => barRow(cat, pts, max)).join("")
      : `<p class="muted">No categorized findings.</p>`;
  }

  function barRow(label, value, max) {
    const pct = Math.round((value / max) * 100);
    const cls = pct > 66 ? "hot" : pct > 33 ? "warm" : "";
    return `<div class="bar-row">
      <span>${escapeHtml(label)}</span>
      <div class="bar-track"><div class="bar-fill ${cls}" style="width:${pct}%"></div></div>
      <span>${value}</span>
    </div>`;
  }

  // ---------------------------------------------------------------------
  // Findings panel
  // ---------------------------------------------------------------------
  function populateCategoryFilter(result) {
    const sel = $("findings-category-filter");
    const cats = [...new Set(result.findings.map((f) => f.category))].sort();
    sel.innerHTML = `<option value="">All categories</option>` +
      cats.map((c) => `<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`).join("");
  }

  ["findings-search"].forEach((id) => {
    $(id).addEventListener("input", (e) => { state.findingsFilter.search = e.target.value.toLowerCase(); renderFindings(); });
  });
  $("findings-category-filter").addEventListener("change", (e) => { state.findingsFilter.category = e.target.value; renderFindings(); });
  $("findings-severity-filter").addEventListener("change", (e) => { state.findingsFilter.severity = e.target.value; renderFindings(); });
  $("findings-sort").addEventListener("change", (e) => { state.findingsFilter.sort = e.target.value; renderFindings(); });

  function renderFindings() {
    if (!state.result) return;
    const { search, category, severity, sort } = state.findingsFilter;
    let items = state.result.findings.filter((f) => {
      if (category && f.category !== category) return false;
      if (severity && f.severity !== severity) return false;
      if (search) {
        const hay = `${f.indicator} ${f.message} ${f.explanation} ${f.evidence}`.toLowerCase();
        if (!hay.includes(search)) return false;
      }
      return true;
    });
    items.sort((a, b) => sort === "score_asc" ? a.score - b.score : b.score - a.score);

    $("findings-list").innerHTML = items.length
      ? items.map(findingCard).join("")
      : `<p class="muted">No findings match the current filters.</p>`;

    document.querySelectorAll(".finding-item").forEach((el) => {
      el.addEventListener("click", () => el.classList.toggle("expanded"));
    });
  }

  function findingCard(f) {
    const mitre = (f.mitre || []).map((m) => `${m.technique_id} ${m.technique_name}`).join(", ");
    return `<div class="finding-item">
      <div class="finding-head">
        <span class="finding-title"><span class="sev-pill sev-${f.severity}">${f.severity.toUpperCase()}</span> ${escapeHtml(f.indicator)}</span>
        <span class="finding-score">+${f.score}</span>
      </div>
      <div class="finding-meta">${escapeHtml(f.category)}${mitre ? " · " + escapeHtml(mitre) : ""}</div>
      <div class="finding-body">
        <p><strong>Why suspicious:</strong> ${escapeHtml(f.explanation)}</p>
        <p><strong>Evidence:</strong> ${escapeHtml(f.evidence)}</p>
      </div>
    </div>`;
  }

  // ---------------------------------------------------------------------
  // PE analysis
  // ---------------------------------------------------------------------
  function renderPEInfo(result) {
    const pe = result.pe;
    if (!pe.is_pe) {
      $("pe-info-table").innerHTML = `<tr><td>Status</td><td>Not a valid PE file (whole-file entropy: ${pe.whole_file_entropy ?? "n/a"}/8.0)</td></tr>`;
      document.querySelector("#section-table tbody").innerHTML = `<tr><td colspan="5">No sections (not a PE file)</td></tr>`;
      return;
    }
    const rows = [
      ["Machine", pe.machine], ["Subsystem", pe.subsystem], ["Entry Point", pe.entry_point],
      ["Image Base", pe.image_base], ["Timestamp", pe.timestamp], ["Sections", pe.sections],
      ["Imports", pe.num_imports], ["Signed", pe.is_signed], ["TLS Callbacks", pe.has_tls_callbacks],
    ];
    $("pe-info-table").innerHTML = rows.map(([k, v]) => `<tr><td>${escapeHtml(k)}</td><td>${escapeHtml(String(v))}</td></tr>`).join("");

    const tbody = document.querySelector("#section-table tbody");
    tbody.innerHTML = (result.sections || []).map((s) => {
      const rowClass = s.status === "Suspicious" ? "row-suspicious" : s.status === "Watch" ? "row-watch" : "";
      return `<tr class="${rowClass}">
        <td>${escapeHtml(s.name)}</td><td>${s.raw_size.toLocaleString()}</td>
        <td>${s.entropy.toFixed(2)}</td><td>${escapeHtml(s.permissions)}</td>
        <td>${escapeHtml(s.status)}</td>
      </tr>`;
    }).join("") || `<tr><td colspan="5">No sections</td></tr>`;
  }

  function renderEntropyBars(result) {
    const sections = result.sections || [];
    if (!sections.length) {
      $("entropy-bars").innerHTML = `<p class="muted">No section data (not a PE file).</p>`;
      return;
    }
    $("entropy-bars").innerHTML = sections.map((s) => {
      const pct = Math.round((s.entropy / 8) * 100);
      const cls = s.entropy > 7.2 ? "hot" : s.entropy > 6.8 ? "warm" : "";
      return `<div class="bar-row">
        <span>${escapeHtml(s.name)}</span>
        <div class="bar-track"><div class="bar-fill ${cls}" style="width:${pct}%"></div></div>
        <span>${s.entropy.toFixed(2)}</span>
      </div>`;
    }).join("");
  }

  // ---------------------------------------------------------------------
  // Imports
  // ---------------------------------------------------------------------
  function renderImports(result) {
    const imp = result.imports || {};
    $("import-summary").textContent =
      `Total imports: ${imp.total_imports || 0}   |   Suspicious imports: ${imp.suspicious_imports || 0}`;

    const byCat = imp.by_category || {};
    const cats = Object.keys(byCat);
    $("import-groups").innerHTML = cats.length
      ? cats.map((cat) => `
        <div style="margin-bottom:0.6rem;">
          <strong>${escapeHtml(cat)}</strong>
          <div class="muted small">${byCat[cat].map(escapeHtml).join(", ")}</div>
        </div>`).join("")
      : `<p class="muted">No suspicious imports detected.</p>`;
  }

  // ---------------------------------------------------------------------
  // Strings (paginated + searchable)
  // ---------------------------------------------------------------------
  $("string-search").addEventListener("input", () => { state.stringPage = 0; renderStrings(); });
  $("string-prev").addEventListener("click", () => { if (state.stringPage > 0) { state.stringPage--; renderStrings(); } });
  $("string-next").addEventListener("click", () => { state.stringPage++; renderStrings(); });

  function renderStrings() {
    if (!state.result) return;
    const summary = state.result.strings || {};
    const query = $("string-search").value.toLowerCase();

    $("string-summary").textContent =
      `Extracted ${summary.total_extracted || 0} strings (showing first ${summary.sample ? summary.sample.length : 0}). ` +
      (Object.keys(summary.suspicious_categories || {}).length
        ? `Suspicious categories: ${Object.keys(summary.suspicious_categories).join(", ")}`
        : "No suspicious string patterns matched.");

    let items = (summary.sample || []);
    if (query) items = items.filter((s) => s.toLowerCase().includes(query));

    const start = state.stringPage * state.stringPageSize;
    const pageItems = items.slice(start, start + state.stringPageSize);

    $("string-list").innerHTML = pageItems.length
      ? pageItems.map((s) => `<div>${escapeHtml(s)}</div>`).join("")
      : `<div class="muted">No strings match.</div>`;

    const totalPages = Math.max(1, Math.ceil(items.length / state.stringPageSize));
    $("string-page-label").textContent = `Page ${state.stringPage + 1} of ${totalPages}`;
    $("string-prev").disabled = state.stringPage <= 0;
    $("string-next").disabled = state.stringPage >= totalPages - 1;
  }

  // ---------------------------------------------------------------------
  // IOCs -- displayed as plain text only, never linked/clickable/executed
  // ---------------------------------------------------------------------
  function renderIOCs(result) {
    const iocs = result.iocs || {};
    const labels = Object.keys(iocs);
    $("ioc-panel").innerHTML = labels.length
      ? labels.map((label) => `
        <div class="ioc-group">
          <h4>${escapeHtml(label.replace(/_/g, " ").toUpperCase())}</h4>
          <ul>${iocs[label].map((v) => `<li>${escapeHtml(v)}</li>`).join("")}</ul>
        </div>`).join("")
      : `<p class="muted">No static IOCs extracted from this file.</p>`;
  }

  // ---------------------------------------------------------------------
  // MITRE mapping
  // ---------------------------------------------------------------------
  function renderMitre(result) {
    const seen = new Map();
    (result.findings || []).forEach((f) => {
      (f.mitre || []).forEach((m) => {
        if (!seen.has(m.technique_id)) seen.set(m.technique_id, { name: m.technique_name, based_on: new Set() });
        seen.get(m.technique_id).based_on.add(f.indicator);
      });
    });
    const tbody = document.querySelector("#mitre-table tbody");
    if (seen.size === 0) {
      tbody.innerHTML = `<tr><td colspan="3">No techniques mapped for this file.</td></tr>`;
      return;
    }
    tbody.innerHTML = [...seen.entries()].map(([tid, info]) =>
      `<tr><td>${escapeHtml(tid)}</td><td>${escapeHtml(info.name)}</td><td class="muted">${[...info.based_on].map(escapeHtml).join(", ")}</td></tr>`
    ).join("");
  }

  // ---------------------------------------------------------------------
  // History
  // ---------------------------------------------------------------------
  async function loadHistory() {
    try {
      const resp = await fetch("/api/history?limit=20");
      const rows = await resp.json();
      const tbody = document.querySelector("#history-table tbody");
      tbody.innerHTML = rows.length
        ? rows.map((r) => `
          <tr data-id="${r.id}">
            <td>${escapeHtml(r.filename)}</td>
            <td class="muted small">${escapeHtml(r.timestamp)}</td>
            <td>${r.normalized_score}</td>
            <td>${emojiFor(r.verdict)} ${escapeHtml(r.verdict)}</td>
            <td>${r.finding_count}</td>
          </tr>`).join("")
        : `<tr><td colspan="5" class="muted">No analyses yet.</td></tr>`;

      tbody.querySelectorAll("tr[data-id]").forEach((row) => {
        row.addEventListener("click", async () => {
          const id = row.getAttribute("data-id");
          const r = await fetch(`/api/history/${id}`).then((res) => res.json());
          if (r.error) return;
          state.historyId = parseInt(id, 10);
          renderResult(r.result);
          setStatus(`Loaded analysis #${id} from history.`, false);
          window.scrollTo({ top: 0, behavior: "smooth" });
        });
      });
    } catch (err) {
      // History is a convenience feature -- fail silently in the UI.
    }
  }

  // ---------------------------------------------------------------------
  // Utils
  // ---------------------------------------------------------------------
  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  loadHistory();
})();
