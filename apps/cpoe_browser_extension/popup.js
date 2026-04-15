/**
 * CPoE Browser Extension — Popup Script
 */

const elements = {
  modeBadge: document.getElementById("mode-badge"),
  connectionBadge: document.getElementById("connection-badge"),
  welcome: document.getElementById("welcome"),
  welcomeDismiss: document.getElementById("welcome-dismiss"),
  standaloneNotice: document.getElementById("standalone-notice"),
  desktopNotice: document.getElementById("desktop-notice"),
  btnExport: document.getElementById("btn-export"),
  noSession: document.getElementById("no-session"),
  activeSession: document.getElementById("active-session"),
  sessionSummary: document.getElementById("session-summary"),
  summaryCheckpoints: document.getElementById("summary-checkpoints"),
  summaryDuration: document.getElementById("summary-duration"),
  summaryEvidenceNote: document.getElementById("summary-evidence-note"),
  sessionTitle: document.getElementById("session-title"),
  checkpointCount: document.getElementById("checkpoint-count"),
  charCount: document.getElementById("char-count"),
  btnStart: document.getElementById("btn-start"),
  btnStop: document.getElementById("btn-stop"),
  totalFiles: document.getElementById("total-files"),
  totalCheckpoints: document.getElementById("total-checkpoints"),
  errorBanner: document.getElementById("error-banner"),
  errorMessage: document.getElementById("error-message"),
  errorDismiss: document.getElementById("error-dismiss"),
  openOptions: document.getElementById("open-options"),
};

let currentMode = "detecting";
let sessionStartTime = null;
let lastCheckpointCount = 0;

function updateUI(state) {
  const isStandalone = state.mode === "standalone";
  currentMode = state.mode || currentMode;

  // Mode and connection badges
  if (isStandalone) {
    elements.modeBadge.textContent = "Standalone";
    elements.modeBadge.className = "badge standalone";
    elements.connectionBadge.textContent = "Browser-only";
    elements.connectionBadge.className = "badge standalone";
  } else if (state.connected) {
    elements.modeBadge.textContent = "Desktop";
    elements.modeBadge.className = "badge connected";
    elements.connectionBadge.textContent = "Connected";
    elements.connectionBadge.className = "badge connected";
  } else if (currentMode === "detecting") {
    elements.modeBadge.textContent = "";
    elements.connectionBadge.textContent = "Detecting...";
    elements.connectionBadge.className = "badge";
  } else {
    elements.modeBadge.textContent = "";
    elements.connectionBadge.textContent = "Disconnected";
    elements.connectionBadge.className = "badge disconnected";
  }

  // Mode-specific notices
  elements.standaloneNotice.hidden = !isStandalone;
  elements.desktopNotice.hidden = !(state.connected && !isStandalone && currentMode !== "detecting");

  // Export button: standalone mode with an active or recent session
  elements.btnExport.hidden = !isStandalone || (!state.activeSession && !state.hasExportableSession);

  if (state.activeSession) {
    elements.noSession.hidden = true;
    elements.activeSession.hidden = false;
    elements.sessionSummary.hidden = true;
    elements.welcome.hidden = true;
    elements.btnStart.hidden = true;
    elements.btnStop.hidden = false;
    elements.sessionTitle.textContent =
      state.documentTitle || "Untitled document";
    elements.checkpointCount.textContent = state.checkpointCount || "0";
    elements.charCount.textContent = formatNumber(state.charCount || 0);
    lastCheckpointCount = state.checkpointCount || 0;
    if (!sessionStartTime) {
      chrome.storage.local.get("_sessionStartTime", (r) => {
        sessionStartTime = r._sessionStartTime || Date.now();
      });
    }
    // Mark first session seen
    chrome.storage.local.set({ _hasUsedExtension: true });
  } else {
    elements.activeSession.hidden = true;
    elements.btnStart.hidden = false;
    elements.btnStop.hidden = true;

    // Show summary if we just stopped a session
    if (state.showSummary && lastCheckpointCount > 0) {
      elements.noSession.hidden = true;
      elements.sessionSummary.hidden = false;
      elements.summaryCheckpoints.textContent =
        lastCheckpointCount + (lastCheckpointCount === 1 ? " checkpoint" : " checkpoints");
      const durationMin = sessionStartTime
        ? Math.max(1, Math.round((Date.now() - sessionStartTime) / 60000))
        : 0;
      elements.summaryDuration.textContent = durationMin + " min";
      elements.summaryEvidenceNote.textContent = isStandalone
        ? "Evidence stored in browser. Export JSON or install the desktop app for stronger proof."
        : "Evidence anchored with hardware attestation and VDF time-proofs.";
      sessionStartTime = null;
      lastCheckpointCount = 0;
    } else if (!state.showSummary) {
      elements.noSession.hidden = false;
      elements.sessionSummary.hidden = true;
    }
  }

  if (state.trackedFiles !== undefined) {
    elements.totalFiles.textContent = state.trackedFiles;
  }
  if (state.totalCheckpoints !== undefined) {
    elements.totalCheckpoints.textContent = formatNumber(
      state.totalCheckpoints
    );
  }
}

function showError(message) {
  let safe = typeof message === "string" ? message : "Unknown error";
  safe = safe.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, "");
  if (safe.length > 200) {
    safe = safe.slice(0, 200) + "\u2026";
  }
  elements.errorMessage.textContent = safe || "Unknown error";
  elements.errorBanner.hidden = false;
}

function hideError() {
  elements.errorBanner.hidden = true;
}

function formatNumber(n) {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + "M";
  if (n >= 1_000) return (n / 1_000).toFixed(1) + "K";
  return String(n);
}

elements.btnStart.addEventListener("click", async () => {
  try {
    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true,
    });
    if (!tab?.id) return;

    const response = await chrome.tabs.sendMessage(tab.id, { action: "start" });
    if (response?.ok) {
      sessionStartTime = Date.now();
      updateUI({
        connected: true,
        activeSession: true,
        documentTitle: tab.title,
        mode: currentMode,
      });
    } else {
      showError(response?.error || "Failed to start witnessing");
    }
  } catch (err) {
    showError("Could not start witnessing. Is this a supported page?");
  }
});

elements.btnStop.addEventListener("click", async () => {
  try {
    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true,
    });
    if (tab?.id) {
      const response = await chrome.tabs.sendMessage(tab.id, { action: "stop_witnessing" });
      if (response && !response.ok) {
        // Non-fatal; content script may have been unloaded
      }
    }
  } catch (err) {
    // Content script not reachable; proceed with background stop
  }
  chrome.runtime.sendMessage({ action: "stop_witnessing" });
  updateUI({
    connected: true,
    activeSession: false,
    mode: currentMode,
    showSummary: true,
    hasExportableSession: currentMode === "standalone",
  });
});

elements.btnExport.addEventListener("click", async () => {
  const resp = await chrome.runtime.sendMessage({ action: "export_evidence" });
  if (resp?.ok && resp.evidence) {
    const blob = new Blob([JSON.stringify(resp.evidence, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `writersproof-evidence-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  } else {
    showError(resp?.error || "Export failed");
  }
});

elements.errorDismiss.addEventListener("click", hideError);

elements.welcomeDismiss.addEventListener("click", () => {
  elements.welcome.hidden = true;
  chrome.storage.local.set({ _hasUsedExtension: true });
});

elements.openOptions.addEventListener("click", (e) => {
  e.preventDefault();
  chrome.runtime.openOptionsPage();
});

chrome.runtime.onMessage.addListener((message) => {
  switch (message.type) {
    case "status_update":
      updateUI({
        connected: true,
        activeSession: message.active_session,
        documentTitle: message.document_title,
        documentUrl: message.document_url,
        checkpointCount: message.checkpoint_count,
        trackedFiles: message.tracked_files,
        totalCheckpoints: message.total_checkpoints,
        mode: message.mode,
      });
      break;

    case "session_update":
      if (message.active === false) {
        updateUI({ connected: true, activeSession: false, mode: message.mode });
      } else {
        updateUI({
          connected: true,
          activeSession: true,
          documentTitle: message.document_title,
          checkpointCount: message.checkpoint_count,
          mode: message.mode,
        });
      }
      break;

    case "checkpoint_update":
      elements.checkpointCount.textContent = message.checkpoint_count || "0";
      lastCheckpointCount = message.checkpoint_count || 0;
      break;

    case "error":
      showError(message.message);
      break;
  }
});

async function init() {
  let response = await chrome.runtime.sendMessage({ action: "popup_connect" });

  // Retry once if background is still initializing
  if (!response || response.mode === "detecting") {
    await new Promise((r) => setTimeout(r, 300));
    response = await chrome.runtime.sendMessage({ action: "popup_connect" });
  }

  currentMode = response?.mode || "detecting";

  updateUI({
    connected: response?.connected || false,
    activeSession: false,
    mode: currentMode,
  });

  // Show welcome card on first use
  const { _hasUsedExtension } = await chrome.storage.local.get("_hasUsedExtension");
  if (!_hasUsedExtension) {
    elements.welcome.hidden = false;
  }

  try {
    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true,
    });
    if (tab?.id) {
      const pageInfo = await chrome.tabs.sendMessage(tab.id, {
        action: "get_page_info",
      });
      if (pageInfo?.ok && pageInfo.isWitnessing) {
        elements.welcome.hidden = true;
        updateUI({
          connected: response?.connected || false,
          activeSession: true,
          documentTitle: pageInfo.title,
          charCount: pageInfo.charCount,
          mode: currentMode,
        });
      }

      if (!pageInfo?.ok || !pageInfo.site) {
        elements.btnStart.disabled = true;
        elements.btnStart.title = "Navigate to a supported document editor";
      }
    }
  } catch {
    elements.btnStart.disabled = true;
    elements.btnStart.title = "Navigate to a supported document editor";
  }
}

const versionEl = document.getElementById("ext-version");
if (versionEl) {
  versionEl.textContent = `v${chrome.runtime.getManifest().version}`;
}

init();
