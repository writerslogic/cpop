/**
 * Witnessd Browser Extension — Popup Script
 */

const elements = {
  connectionBadge: document.getElementById("connection-badge"),
  noSession: document.getElementById("no-session"),
  activeSession: document.getElementById("active-session"),
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

// ── State Management ──────────────────────────────────────────────────────

function updateUI(state) {
  // Connection badge
  if (state.connected) {
    elements.connectionBadge.textContent = "Connected";
    elements.connectionBadge.className = "badge connected";
  } else {
    elements.connectionBadge.textContent = "Disconnected";
    elements.connectionBadge.className = "badge disconnected";
  }

  // Session state
  if (state.activeSession) {
    elements.noSession.hidden = true;
    elements.activeSession.hidden = false;
    elements.btnStart.hidden = true;
    elements.btnStop.hidden = false;
    elements.sessionTitle.textContent =
      state.documentTitle || "Untitled document";
    elements.checkpointCount.textContent = state.checkpointCount || "0";
    elements.charCount.textContent = formatNumber(state.charCount || 0);
  } else {
    elements.noSession.hidden = false;
    elements.activeSession.hidden = true;
    elements.btnStart.hidden = false;
    elements.btnStop.hidden = true;
  }

  // System stats
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
  elements.errorMessage.textContent = message;
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

// ── Event Handlers ──────────────────────────────────────────────────────

elements.btnStart.addEventListener("click", async () => {
  try {
    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true,
    });
    if (!tab?.id) return;

    // Ask content script to start
    const response = await chrome.tabs.sendMessage(tab.id, { action: "start" });
    if (response?.ok) {
      updateUI({ connected: true, activeSession: true, documentTitle: tab.title });
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
        console.warn("Content script reported error stopping:", response.error);
      }
    }
  } catch (err) {
    console.warn("Could not notify content script to stop:", err);
  }
  chrome.runtime.sendMessage({ action: "stop_witnessing" });
  updateUI({ connected: true, activeSession: false });
});

elements.errorDismiss.addEventListener("click", hideError);

elements.openOptions.addEventListener("click", (e) => {
  e.preventDefault();
  chrome.runtime.openOptionsPage();
});

// ── Background Messages ─────────────────────────────────────────────────

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
      });
      break;

    case "session_update":
      if (message.active === false) {
        updateUI({ connected: true, activeSession: false });
      } else {
        updateUI({
          connected: true,
          activeSession: true,
          documentTitle: message.document_title,
          checkpointCount: message.checkpoint_count,
        });
      }
      break;

    case "checkpoint_update":
      elements.checkpointCount.textContent = message.checkpoint_count || "0";
      break;

    case "error":
      showError(message.message);
      break;
  }
});

// ── Initialize ──────────────────────────────────────────────────────────

async function init() {
  // Ask background for current status
  const response = await chrome.runtime.sendMessage({ action: "popup_connect" });

  updateUI({
    connected: response?.connected || false,
    activeSession: false,
  });

  // Also ask the active tab for page info
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
        updateUI({
          connected: response?.connected || false,
          activeSession: true,
          documentTitle: pageInfo.title,
          charCount: pageInfo.charCount,
        });
      }

      // Disable start button if not on a supported site
      if (!pageInfo?.ok || !pageInfo.site) {
        elements.btnStart.disabled = true;
        elements.btnStart.title = "Navigate to a supported document editor";
      }
    }
  } catch {
    // Content script not loaded on this page
    elements.btnStart.disabled = true;
    elements.btnStart.title = "Navigate to a supported document editor";
  }
}

init();
