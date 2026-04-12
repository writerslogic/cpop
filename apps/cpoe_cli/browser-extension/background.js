/**
 * CPoE Browser Extension — Background Service Worker
 *
 * Manages the native messaging connection to writerslogic-native-messaging-host
 * and coordinates between content scripts and the native host.
 */

const NATIVE_HOST_NAME = "com.writerslogic.witnessd";
const CHECKPOINT_INTERVAL_MS = 30_000; // 30 seconds default
const MAX_PENDING_CALLBACKS = 256;
const GENESIS_COMMITMENT_PREFIX = "CPoE-Genesis-v1";
const COMMITMENT_CHAIN_INITIAL_ORDINAL = 2; // Ordinal 1 = session start

// M-118: Shared action names used in message validation
const CONTENT_ACTIONS = [
  "start_witnessing", "stop_witnessing", "content_changed", "keystroke_jitter"
];
const VALID_ACTIONS = [
  ...CONTENT_ACTIONS, "get_status", "popup_connect"
];

/**
 * Global mutable state. Service worker restarts will reset these to defaults.
 * (H-105) Chrome MV3 service workers can be terminated and restarted at any time.
 * Critical session state (sessionNonce, prevCommitment, checkpointOrdinal) is
 * ephemeral by design — a service worker restart forces a new session handshake
 * with the native host, which re-initializes the commitment chain.
 */
let nativePort = null;
let isConnected = false;
let isConnecting = false;
let activeTabId = null;
let checkpointTimer = null;
let pendingCallbacks = new Map();
let callbackId = 0;

// Anti-forgery commitment chain state
let sessionNonce = null;
let prevCommitment = null;
let checkpointOrdinal = COMMITMENT_CHAIN_INITIAL_ORDINAL;

function connectToNativeHost() {
  if (nativePort || isConnecting) {
    return;
  }

  isConnecting = true;
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
      isConnecting = false;
      updateBadge("!", "#e74c3c");
    });

    isConnected = true;
    updateBadge("", "#2ecc71");

    sendNativeMessage({ type: "ping" });
  } catch (err) {
    console.error("Failed to connect to native host:", err);
    isConnected = false;
    updateBadge("!", "#e74c3c");
  } finally {
    isConnecting = false;
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

  // H-106: Enforce max pending callbacks to prevent unbounded growth
  if (pendingCallbacks.size >= MAX_PENDING_CALLBACKS) {
    console.warn("Pending callbacks limit reached, dropping oldest");
    const oldest = pendingCallbacks.keys().next().value;
    pendingCallbacks.delete(oldest);
  }

  nativePort.postMessage(message);
}

/**
 * Handle messages from the native messaging host.
 * (M-052) Acknowledged: this handler is ~60 lines of switch/case which is
 * acceptable for a flat message dispatch; extracting sub-handlers would add
 * indirection without meaningful benefit.
 */
function handleNativeMessage(message) {
  // SYS-019: Validate native message structure before dispatch
  if (!message || typeof message !== "object" || typeof message.type !== "string") {
    console.warn("Ignoring malformed native message:", message);
    return;
  }

  switch (message.type) {
    case "pong":
      console.log(`Native host connected: v${message.version}`);
      isConnected = true;
      updateBadge("", "#2ecc71");
      break;

    case "session_started":
      console.log(`Session started: ${message.session_id}`);
      // Initialize commitment chain from session nonce
      if (message.session_nonce) {
        sessionNonce = message.session_nonce;
        checkpointOrdinal = COMMITMENT_CHAIN_INITIAL_ORDINAL;
        // Derive deterministic genesis commitment so the first checkpoint
        // has a valid prev_commitment instead of null.
        computeGenesisCommitment(message.session_nonce)
          .then((genesis) => { prevCommitment = genesis; })
          .catch((err) => {
            console.error("Failed to compute genesis commitment:", err);
            prevCommitment = null;
          });
      }
      updateBadge("\u2713", "#2ecc71");
      broadcastToPopup({ type: "session_update", ...message });
      break;

    case "checkpoint_created":
      console.log(
        `Checkpoint #${message.checkpoint_count}: ${message.hash?.slice(0, 12)}...`
      );
      // Update commitment chain with server's confirmed commitment
      if (message.commitment) {
        prevCommitment = message.commitment;
      }
      // Ordinal is already incremented at send time (see content_changed handler)
      updateBadge(String(message.checkpoint_count), "#2ecc71");
      broadcastToPopup({ type: "checkpoint_update", ...message });
      break;

    case "session_stopped":
      console.log("Session stopped:", message.message);
      // Clear commitment chain state
      sessionNonce = null;
      prevCommitment = null;
      checkpointOrdinal = COMMITMENT_CHAIN_INITIAL_ORDINAL;
      updateBadge("", "#95a5a6");
      stopCheckpointTimer();
      broadcastToPopup({ type: "session_update", active: false });
      break;

    case "status":
      broadcastToPopup({ type: "status_update", ...message });
      break;

    case "jitter_received":
      break;

    case "error":
      console.error(`Native host error [${message.code}]: ${message.message}`);
      broadcastToPopup({
        type: "error",
        message: sanitizeErrorMessage(message.message),
        code: message.code,
      });
      break;

    default:
      console.warn("Unknown native message type:", message.type);
  }
}

// Allowed URL patterns for content script messages (must match manifest.json)
const ALLOWED_ORIGINS = [
  /^https:\/\/docs\.google\.com\//,
  /^https:\/\/(www\.)?overleaf\.com\//,
  /^https:\/\/medium\.com\//,
  /^https:\/\/(www\.)?notion\.so\//,
];

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // SYS-019: Validate message structure
  if (!message || typeof message !== "object" || typeof message.action !== "string") {
    sendResponse({ ok: false, error: "Malformed message" });
    return true;
  }

  // SYS-019: Reject unknown actions early
  if (!VALID_ACTIONS.includes(message.action)) {
    sendResponse({ ok: false, error: "Unknown action" });
    return true;
  }

  // Block messages from other extensions
  if (sender.id !== chrome.runtime.id) {
    sendResponse({ ok: false, error: "Unauthorized sender" });
    return true;
  }

  // Content script actions require a valid tab with an allowed URL
  // M-098: TOCTOU note — the URL check and subsequent use are in the same
  // synchronous event-loop turn, so no interleaving is possible in JS.
  if (CONTENT_ACTIONS.includes(message.action)) {
    const tabUrl = sender.tab?.url || sender.url || "";
    if (!sender.tab || !ALLOWED_ORIGINS.some((re) => re.test(tabUrl))) {
      sendResponse({ ok: false, error: "Unauthorized origin" });
      return true;
    }
  }

  switch (message.action) {
    case "start_witnessing":
      {
        // M-080: Validate URL before forwarding to native host
        const url = message.url;
        if (typeof url !== "string" || !ALLOWED_ORIGINS.some((re) => re.test(url))) {
          sendResponse({ ok: false, error: "Invalid document URL" });
          break;
        }
        connectToNativeHost();
        sendNativeMessage({
          type: "start_session",
          document_url: url,
          document_title: message.title,
          timer_resolution_ms: message.timerResolution,
        });
        activeTabId = sender.tab?.id;
        startCheckpointTimer();
        sendResponse({ ok: true });
      }
      break;

    case "stop_witnessing":
      sendNativeMessage({ type: "stop_session" });
      activeTabId = null;
      stopCheckpointTimer();
      sendResponse({ ok: true });
      break;

    case "content_changed":
      {
        // M-132: Return true (below) to keep the message channel open for the
        // async commitment computation, then call sendResponse when done.
        const ordinal = checkpointOrdinal;
        const checkpointMsg = {
          type: "checkpoint",
          content_hash: message.contentHash,
          char_count: message.charCount,
          delta: message.delta,
          ordinal,
        };
        // Increment ordinal at send time, not on server response
        checkpointOrdinal++;
        // Compute commitment if we have the chain state
        if (prevCommitment && sessionNonce) {
          computeCommitment(prevCommitment, message.contentHash, ordinal, sessionNonce)
            .then((commitment) => {
              checkpointMsg.commitment = commitment;
              sendNativeMessage(checkpointMsg);
              sendResponse({ ok: true });
            })
            .catch((err) => {
              // Do NOT send checkpoint without a valid commitment — skip it
              console.error("Commitment computation failed, skipping checkpoint:", err);
              sendResponse({ ok: false, error: "Commitment failed" });
            });
        } else {
          sendNativeMessage(checkpointMsg);
          sendResponse({ ok: true });
        }
      }
      // M-132/M-070: return true keeps the channel open for async sendResponse
      return true;

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
      sendNativeMessage({ type: "get_status" });
      sendResponse({ ok: true, connected: isConnected });
      break;

    default:
      sendResponse({ ok: false, error: "Unknown action" });
  }

  return true;
});

function startCheckpointTimer() {
  stopCheckpointTimer();
  checkpointTimer = setInterval(() => {
    if (activeTabId) {
      chrome.tabs.sendMessage(activeTabId, { action: "capture_state" }).catch(() => {
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

function updateBadge(text, color) {
  chrome.action.setBadgeText({ text });
  chrome.action.setBadgeBackgroundColor({ color });
}

function broadcastToPopup(message) {
  chrome.runtime.sendMessage(message).catch(() => {});
}

/**
 * Sanitize error messages from native host before displaying in popup.
 * Caps length to prevent UI flooding and strips control characters.
 */
function sanitizeErrorMessage(raw) {
  if (typeof raw !== "string") return "Unknown error";
  // Strip control characters (except newline/tab) that could spoof UI
  const cleaned = raw.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, "");
  // Cap length to prevent oversized messages
  if (cleaned.length > 200) {
    return cleaned.slice(0, 200) + "\u2026";
  }
  return cleaned || "Unknown error";
}

/**
 * Derive a deterministic genesis commitment from the session nonce.
 * SHA-256("CPoE-Genesis-v1" || session_nonce).
 * This ensures the first checkpoint has a valid prev_commitment.
 *
 * M-090: The commitment chain is stored entirely in memory (prevCommitment is
 * a single hash, not a growing list). Storage I/O only occurs for the session
 * nonce read at startup. Chain length does not affect storage I/O.
 */
async function computeGenesisCommitment(sessionNonceHex) {
  const prefix = new TextEncoder().encode(GENESIS_COMMITMENT_PREFIX);
  const nonce = hexToBytes(sessionNonceHex);
  const combined = new Uint8Array(prefix.length + nonce.length);
  combined.set(prefix, 0);
  combined.set(nonce, prefix.length);
  const hashBuf = await crypto.subtle.digest("SHA-256", combined);
  return bytesToHex(new Uint8Array(hashBuf));
}

/**
 * Compute commitment hash: SHA-256(prev_commitment || content_hash || ordinal_le || session_nonce).
 * Must match the server-side computation in native_messaging_host.rs.
 */
async function computeCommitment(prevCommitmentHex, contentHash, ordinal, sessionNonceHex) {
  const prev = hexToBytes(prevCommitmentHex);
  const nonce = hexToBytes(sessionNonceHex);
  const contentBytes = new TextEncoder().encode(contentHash);

  // ordinal as 8-byte little-endian
  const ordinalBuf = new ArrayBuffer(8);
  const ordinalView = new DataView(ordinalBuf);
  ordinalView.setUint32(0, ordinal & 0xffffffff, true);
  ordinalView.setUint32(4, Math.floor(ordinal / 0x100000000), true);
  const ordinalBytes = new Uint8Array(ordinalBuf);

  // Concatenate: prev(32) + contentHash(utf8) + ordinal(8) + nonce(16)
  const combined = new Uint8Array(prev.length + contentBytes.length + 8 + nonce.length);
  let offset = 0;
  combined.set(prev, offset); offset += prev.length;
  combined.set(contentBytes, offset); offset += contentBytes.length;
  combined.set(ordinalBytes, offset); offset += 8;
  combined.set(nonce, offset);

  const hashBuf = await crypto.subtle.digest("SHA-256", combined);
  return bytesToHex(new Uint8Array(hashBuf));
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

chrome.runtime.onInstalled.addListener(() => {
  console.log("CPoE extension installed");
  updateBadge("", "#95a5a6");
});

chrome.tabs.onRemoved.addListener((tabId) => {
  if (tabId === activeTabId) {
    sendNativeMessage({ type: "stop_session" });
    activeTabId = null;
    sessionNonce = null;
    prevCommitment = null;
    checkpointOrdinal = COMMITMENT_CHAIN_INITIAL_ORDINAL;
    stopCheckpointTimer();
    updateBadge("", "#95a5a6");
  }
});
