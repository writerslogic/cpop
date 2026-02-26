/**
 * Witnessd Browser Extension — Background Service Worker
 *
 * Manages the native messaging connection to witnessd-native-messaging-host
 * and coordinates between content scripts and the native host.
 */

const NATIVE_HOST_NAME = "com.writerslogic.witnessd";
const CHECKPOINT_INTERVAL_MS = 30_000; // 30 seconds default

let nativePort = null;
let isConnected = false;
let activeTabId = null;
let checkpointTimer = null;
let pendingCallbacks = new Map();
let callbackId = 0;

// ── Native Messaging Connection ─────────────────────────────────────────────

function connectToNativeHost() {
  if (nativePort) {
    return;
  }

  try {
    nativePort = chrome.runtime.connectNative(NATIVE_HOST_NAME);

    nativePort.onMessage.addListener((message) => {
      handleNativeMessage(message);
    });

    nativePort.onDisconnect.addListener(() => {
      const error = chrome.runtime.lastError;
      console.warn("Native host disconnected:", error?.message || "unknown");
      nativePort = null;
      isConnected = false;
      updateBadge("!", "#e74c3c");
    });

    isConnected = true;
    updateBadge("", "#2ecc71");

    // Send ping to verify connection
    sendNativeMessage({ type: "ping" });
  } catch (err) {
    console.error("Failed to connect to native host:", err);
    isConnected = false;
    updateBadge("!", "#e74c3c");
  }
}

function disconnectFromNativeHost() {
  if (nativePort) {
    nativePort.disconnect();
    nativePort = null;
  }
  isConnected = false;
  updateBadge("", "#95a5a6");
}

function sendNativeMessage(message) {
  if (!nativePort) {
    connectToNativeHost();
  }

  if (!nativePort) {
    console.error("Cannot send message: not connected to native host");
    return;
  }

  nativePort.postMessage(message);
}

// ── Message Handlers ────────────────────────────────────────────────────────

function handleNativeMessage(message) {
  switch (message.type) {
    case "pong":
      console.log(`Native host connected: v${message.version}`);
      isConnected = true;
      updateBadge("", "#2ecc71");
      break;

    case "session_started":
      console.log(`Session started: ${message.session_id}`);
      updateBadge("\u2713", "#2ecc71");
      // Notify popup if open
      broadcastToPopup({ type: "session_update", ...message });
      break;

    case "checkpoint_created":
      console.log(
        `Checkpoint #${message.checkpoint_count}: ${message.hash?.slice(0, 12)}...`
      );
      // Brief flash on badge
      updateBadge(String(message.checkpoint_count), "#2ecc71");
      broadcastToPopup({ type: "checkpoint_update", ...message });
      break;

    case "session_stopped":
      console.log("Session stopped:", message.message);
      updateBadge("", "#95a5a6");
      stopCheckpointTimer();
      broadcastToPopup({ type: "session_update", active: false });
      break;

    case "status":
      broadcastToPopup({ type: "status_update", ...message });
      break;

    case "jitter_received":
      // Acknowledged
      break;

    case "error":
      console.error(`Native host error [${message.code}]: ${message.message}`);
      broadcastToPopup({
        type: "error",
        message: message.message,
        code: message.code,
      });
      break;

    default:
      console.warn("Unknown native message type:", message.type);
  }
}

// ── Content Script Communication ────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.action) {
    case "start_witnessing":
      connectToNativeHost();
      sendNativeMessage({
        type: "start_session",
        document_url: message.url,
        document_title: message.title,
        timer_resolution_ms: message.timerResolution,
      });
      activeTabId = sender.tab?.id;
      startCheckpointTimer();
      sendResponse({ ok: true });
      break;

    case "stop_witnessing":
      sendNativeMessage({ type: "stop_session" });
      activeTabId = null;
      stopCheckpointTimer();
      sendResponse({ ok: true });
      break;

    case "content_changed":
      sendNativeMessage({
        type: "checkpoint",
        content_hash: message.contentHash,
        char_count: message.charCount,
        delta: message.delta,
      });
      sendResponse({ ok: true });
      break;

    case "keystroke_jitter":
      sendNativeMessage({
        type: "inject_jitter",
        intervals: message.intervals,
      });
      sendResponse({ ok: true });
      break;

    case "get_status":
      sendNativeMessage({ type: "get_status" });
      sendResponse({ ok: true, connected: isConnected });
      break;

    case "popup_connect":
      // Popup opened — send current state
      sendNativeMessage({ type: "get_status" });
      sendResponse({ ok: true, connected: isConnected });
      break;

    default:
      sendResponse({ ok: false, error: "Unknown action" });
  }

  return true; // Keep channel open for async response
});

// ── Checkpoint Timer ────────────────────────────────────────────────────────

function startCheckpointTimer() {
  stopCheckpointTimer();
  checkpointTimer = setInterval(() => {
    if (activeTabId) {
      // Ask content script to capture current state
      chrome.tabs.sendMessage(activeTabId, { action: "capture_state" }).catch(() => {
        // Tab may have been closed
        stopCheckpointTimer();
      });
    }
  }, CHECKPOINT_INTERVAL_MS);
}

function stopCheckpointTimer() {
  if (checkpointTimer) {
    clearInterval(checkpointTimer);
    checkpointTimer = null;
  }
}

// ── Badge Updates ───────────────────────────────────────────────────────────

function updateBadge(text, color) {
  chrome.action.setBadgeText({ text });
  chrome.action.setBadgeBackgroundColor({ color });
}

function broadcastToPopup(message) {
  chrome.runtime.sendMessage(message).catch(() => {
    // Popup not open, ignore
  });
}

// ── Lifecycle ───────────────────────────────────────────────────────────────

// Auto-connect on install
chrome.runtime.onInstalled.addListener(() => {
  console.log("Witnessd extension installed");
  updateBadge("", "#95a5a6");
});

// Clean up on tab close
chrome.tabs.onRemoved.addListener((tabId) => {
  if (tabId === activeTabId) {
    sendNativeMessage({ type: "stop_session" });
    activeTabId = null;
    stopCheckpointTimer();
    updateBadge("", "#95a5a6");
  }
});
