(() => {
  // --- 1. Tab Switching ---
  const tabButtons = document.querySelectorAll('.nav-tab');
  const tabPanels = document.querySelectorAll('.tab-panel');

  tabButtons.forEach((btn) => {
    btn.addEventListener('click', () => {
      const targetTab = btn.getAttribute('data-tab');

      tabButtons.forEach((b) => {
        b.classList.remove('active');
        b.setAttribute('aria-selected', 'false');
      });
      tabPanels.forEach((p) => {
        p.classList.remove('active');
        p.hidden = true;
      });

      btn.classList.add('active');
      btn.setAttribute('aria-selected', 'true');

      const panel = document.getElementById(`panel-${targetTab}`);
      if (panel) {
        panel.classList.add('active');
        panel.hidden = false;
      }
    });
  });

  // --- Helper: Format URL ---
  function sanitizeInputUrl(val) {
    let trimmed = val.trim();
    if (!trimmed) return null;
    if (!/^https?:\/\//i.test(trimmed)) {
      trimmed = `https://${trimmed}`;
    }
    try {
      const parsed = new URL(trimmed);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return null;
      }
      return parsed.toString();
    } catch {
      return null;
    }
  }

  // --- 2. Proxy Tab ---
  const proxyForm = document.getElementById('proxyForm');
  const proxyInput = document.getElementById('proxyUrl');
  const proxyError = document.getElementById('proxyError');

  proxyForm.addEventListener('submit', (e) => {
    e.preventDefault();
    proxyError.hidden = true;

    const validated = sanitizeInputUrl(proxyInput.value);
    if (!validated) {
      proxyError.textContent = 'Please enter a valid HTTP or HTTPS destination URL.';
      proxyError.hidden = false;
      return;
    }

    window.location.href = `/proxy?url=${encodeURIComponent(validated)}`;
  });

  // --- 3. Diagnostics Tab ---
  const diagForm = document.getElementById('diagForm');
  const diagInput = document.getElementById('diagUrl');
  const diagError = document.getElementById('diagError');
  const diagLoading = document.getElementById('diagLoading');
  const diagResults = document.getElementById('diagResults');
  const diagTargetText = document.getElementById('diagTargetText');
  const diagRatingBadge = document.getElementById('diagRatingBadge');
  const diagSummaryText = document.getElementById('diagSummaryText');
  const diagProbeRows = document.getElementById('diagProbeRows');
  const diagRecsSection = document.getElementById('diagRecsSection');
  const diagRecsList = document.getElementById('diagRecsList');

  diagForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    diagError.hidden = true;
    diagResults.hidden = true;

    const targetUrl = sanitizeInputUrl(diagInput.value);
    if (!targetUrl) {
      diagError.textContent = 'Please enter a valid HTTP or HTTPS target for diagnostics.';
      diagError.hidden = false;
      return;
    }

    diagLoading.hidden = false;

    try {
      const res = await fetch(`/diagnostics?url=${encodeURIComponent(targetUrl)}`);
      const data = await res.json();

      if (!res.ok || data.ok === false) {
        throw new Error(data.error || `HTTP ${res.status}: Diagnostics probe failed.`);
      }

      diagTargetText.textContent = data.target || targetUrl;

      // Compatibility Badge
      const rating = data.compatibility || 'Limited';
      diagRatingBadge.textContent = rating;
      diagRatingBadge.className = `rating-badge rating-${rating.toLowerCase()}`;
      diagSummaryText.textContent = data.summary || '';

      // Probe Table
      diagProbeRows.innerHTML = '';
      if (Array.isArray(data.probes)) {
        data.probes.forEach((probe) => {
          const tr = document.createElement('tr');

          const tdCat = document.createElement('td');
          tdCat.className = 'mono';
          tdCat.textContent = probe.name;

          const tdStatus = document.createElement('td');
          const pill = document.createElement('span');
          pill.className = `probe-status-pill probe-status-${probe.status || 'warn'}`;
          pill.textContent = (probe.status || 'warn').toUpperCase();
          tdStatus.appendChild(pill);

          const tdObs = document.createElement('td');
          tdObs.textContent = probe.message || '';

          tr.appendChild(tdCat);
          tr.appendChild(tdStatus);
          tr.appendChild(tdObs);
          diagProbeRows.appendChild(tr);
        });
      }

      // Recommendations
      if (Array.isArray(data.recommendations) && data.recommendations.length > 0) {
        diagRecsList.innerHTML = '';
        data.recommendations.forEach((rec) => {
          const li = document.createElement('li');
          li.textContent = rec;
          diagRecsList.appendChild(li);
        });
        diagRecsSection.hidden = false;
      } else {
        diagRecsSection.hidden = true;
      }

      diagResults.hidden = false;
    } catch (err) {
      diagError.textContent = err.message || 'Error executing diagnostics.';
      diagError.hidden = false;
    } finally {
      diagLoading.hidden = true;
    }
  });

  // --- 4. Browser Lab Tab (Daytona Sandboxes) ---
  const browserForm = document.getElementById('browserForm');
  const browserInput = document.getElementById('browserUrl');
  const browserToolSelect = document.getElementById('browserToolSelect');
  const browserViewportSelect = document.getElementById('browserViewportSelect');
  const browserError = document.getElementById('browserError');
  const browserLoading = document.getElementById('browserLoading');
  const browserResults = document.getElementById('browserResults');
  const browserDuration = document.getElementById('browserDuration');
  const browserReqCount = document.getElementById('browserReqCount');
  const browserViewportActive = document.getElementById('browserViewportActive');
  const browserOutputArea = document.getElementById('browserOutputArea');
  const browserConsoleSection = document.getElementById('browserConsoleSection');
  const browserConsoleLogs = document.getElementById('browserConsoleLogs');

  browserForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    browserError.hidden = true;
    browserResults.hidden = true;

    const targetUrl = sanitizeInputUrl(browserInput.value);
    if (!targetUrl) {
      browserError.textContent = 'Please enter a valid HTTP or HTTPS URL.';
      browserError.hidden = false;
      return;
    }

    const tool = browserToolSelect.value;
    const viewport = browserViewportSelect.value;
    browserLoading.hidden = false;

    try {
      const res = await fetch(`/api/tools/${encodeURIComponent(tool)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl, viewport }),
      });

      const data = await res.json();

      if (!res.ok || data.ok === false) {
        throw new Error(data.error || `HTTP ${res.status}: Daytona operation error.`);
      }

      browserDuration.textContent = `${data.durationMs || 0} ms`;
      browserReqCount.textContent = data.networkRequests ?? 'N/A';
      browserViewportActive.textContent = (data.viewport || viewport).toUpperCase();

      browserOutputArea.innerHTML = '';

      if (tool === 'screenshot' && data.screenshotBase64) {
        const img = document.createElement('img');
        img.className = 'browser-preview-img';
        img.src = `data:image/png;base64,${data.screenshotBase64}`;
        img.alt = `Screenshot of ${targetUrl}`;
        browserOutputArea.appendChild(img);
      } else if (tool === 'pdf' && data.pdfBase64) {
        const wrap = document.createElement('div');
        const dlBtn = document.createElement('a');
        dlBtn.className = 'btn-primary';
        dlBtn.textContent = 'Download Vector PDF';
        dlBtn.href = `data:application/pdf;base64,${data.pdfBase64}`;
        dlBtn.download = `routex-${Date.now()}.pdf`;
        wrap.appendChild(dlBtn);
        browserOutputArea.appendChild(wrap);
      } else if (tool === 'render' && data.renderedHtml) {
        const pre = document.createElement('pre');
        pre.className = 'code-view';
        pre.textContent = data.renderedHtml.slice(0, 50000);
        browserOutputArea.appendChild(pre);
      }

      // Console Logs
      if (Array.isArray(data.consoleLogs) && data.consoleLogs.length > 0) {
        browserConsoleLogs.innerHTML = '';
        data.consoleLogs.forEach((log) => {
          const row = document.createElement('div');
          row.className = `console-entry ${log.type === 'error' ? 'error' : log.type === 'warn' ? 'warn' : ''}`;
          row.textContent = `[${(log.type || 'info').toUpperCase()}] ${log.text}`;
          browserConsoleLogs.appendChild(row);
        });
        browserConsoleSection.hidden = false;
      } else {
        browserConsoleSection.hidden = true;
      }

      browserResults.hidden = false;
    } catch (err) {
      browserError.textContent = err.message || 'Error executing Daytona tool.';
      browserError.hidden = false;
    } finally {
      browserLoading.hidden = true;
    }
  });

  // --- 5. Inspector Tab ---
  const inspectorForm = document.getElementById('inspectorForm');
  const inspectorInput = document.getElementById('inspectorUrl');
  const inspectorToolSelect = document.getElementById('inspectorToolSelect');
  const inspectorError = document.getElementById('inspectorError');
  const inspectorLoading = document.getElementById('inspectorLoading');
  const inspectorResults = document.getElementById('inspectorResults');
  const inspectorMetaEndpoint = document.getElementById('inspectorMetaEndpoint');
  const inspectorCodeOutput = document.getElementById('inspectorCodeOutput');
  const inspectorCopyBtn = document.getElementById('inspectorCopyBtn');

  inspectorForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    inspectorError.hidden = true;
    inspectorResults.hidden = true;

    const targetUrl = sanitizeInputUrl(inspectorInput.value);
    if (!targetUrl) {
      inspectorError.textContent = 'Please enter a valid HTTP or HTTPS URL to inspect.';
      inspectorError.hidden = false;
      return;
    }

    const tool = inspectorToolSelect.value;
    const endpoint = `/api/tools/${encodeURIComponent(tool)}?url=${encodeURIComponent(targetUrl)}`;
    inspectorMetaEndpoint.textContent = `GET ${endpoint}`;
    inspectorLoading.hidden = false;

    try {
      const res = await fetch(endpoint);
      const text = await res.text();

      let formatted = text;
      try {
        const json = JSON.parse(text);
        formatted = JSON.stringify(json, null, 2);
      } catch {
        // Keep raw text for robots.txt, sitemaps, etc.
      }

      inspectorCodeOutput.textContent = formatted;
      inspectorResults.hidden = false;
    } catch (err) {
      inspectorError.textContent = err.message || 'Error querying inspector tool.';
      inspectorError.hidden = false;
    } finally {
      inspectorLoading.hidden = true;
    }
  });

  inspectorCopyBtn.addEventListener('click', () => {
    if (inspectorCodeOutput.textContent) {
      navigator.clipboard.writeText(inspectorCodeOutput.textContent);
      const originalText = inspectorCopyBtn.textContent;
      inspectorCopyBtn.textContent = 'Copied!';
      setTimeout(() => {
        inspectorCopyBtn.textContent = originalText;
      }, 1800);
    }
  });
})();
