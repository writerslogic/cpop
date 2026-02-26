/**
 * Witnessd Browser Extension — Content Script
 *
 * Monitors document editing in supported web applications:
 * - Google Docs: Watches the editor iframe and contenteditable elements
 * - Overleaf: Watches the CodeMirror editor
 * - Medium: Watches the contenteditable post editor
 * - Notion: Watches the page content blocks
 *
 * Captures:
 * - Content changes via MutationObserver (character count, delta)
 * - Keystroke timing (inter-key intervals for SWF jitter binding)
 */

(() => {
  "use strict";

  // ── State ───────────────────────────────────────────────────────────────

  let isWitnessing = false;
  let lastCharCount = 0;
  let lastContentHash = "";
  let keystrokeTimestamps = [];
  let timerResolution = 0;
  const JITTER_BATCH_SIZE = 50;
  const MIN_CHANGE_THRESHOLD = 5; // chars before sending checkpoint

  // ── Site Detection ──────────────────────────────────────────────────────

  function detectSite() {
    const hostname = window.location.hostname;
    const pathname = window.location.pathname;

    if (hostname === "docs.google.com" && pathname.startsWith("/document/")) {
      return "google-docs";
    }
    if (hostname === "www.overleaf.com" && pathname.startsWith("/project/")) {
      return "overleaf";
    }
    if (hostname === "medium.com") {
      return "medium";
    }
    if (hostname.includes("notion.so")) {
      return "notion";
    }

    return null;
  }

  // ── Environment Calibration ──────────────────────────────────────────

  /**
   * Measures the resolution of performance.now().
   * Browsers often jitter/clamp this (e.g. to 5ms) to prevent side-channels.
   * Native host needs to know this to properly weigh jitter entropy.
   */
  function calibrateTimer() {
    const samples = [];
    let last = performance.now();
    // Take 10 samples of the smallest detectable increment
    for (let i = 0; i < 10; i++) {
      let current = performance.now();
      while (current === last) {
        current = performance.now();
      }
      samples.push(current - last);
      last = current;
    }
    // Median/min resolution
    timerResolution = Math.min(...samples);
    console.log(`[Witnessd] Timer resolution detected: ${timerResolution.toFixed(4)}ms`);
  }

  // ── Content Extraction ────────────────────────────────────────────────

  function getEditorElement() {
    const site = detectSite();

    switch (site) {
      case "google-docs": {
        // Google Docs uses an iframe with class "docs-texteventtarget-iframe"
        // and contenteditable divs with class "kix-page"
        const pages = document.querySelectorAll(".kix-page");
        if (pages.length > 0) return pages;
        // Fallback: try the editor content wrapper
        return document.querySelectorAll(
          '.kix-appview-editor [contenteditable="true"]'
        );
      }

      case "overleaf": {
        // Overleaf uses CodeMirror — look for .cm-content
        return document.querySelectorAll(".cm-content");
      }

      case "medium": {
        // Medium uses contenteditable sections
        return document.querySelectorAll(
          'article [contenteditable="true"], .postArticle [contenteditable="true"], [role="textbox"]'
        );
      }

      case "notion": {
        // Notion uses contenteditable blocks
        return document.querySelectorAll(
          '.notion-page-content [contenteditable="true"]'
        );
      }

      default:
        return document.querySelectorAll('[contenteditable="true"]');
    }
  }

  function getDocumentText() {
    const elements = getEditorElement();
    if (!elements || elements.length === 0) return "";

    let text = "";
    elements.forEach((el) => {
      text += el.textContent || "";
    });
    return text;
  }

  function getDocumentTitle() {
    const site = detectSite();

    switch (site) {
      case "google-docs": {
        const titleEl = document.querySelector(".docs-title-input input");
        return titleEl?.value || document.title.replace(" - Google Docs", "");
      }
      case "overleaf":
        return document.title.replace(" - Overleaf, Online LaTeX Editor", "");
      case "medium":
        return (
          document.querySelector("h3.graf--title")?.textContent ||
          document.title
        );
      case "notion":
        return (
          document.querySelector(".notion-page-block .notranslate")
            ?.textContent || document.title
        );
      default:
        return document.title;
    }
  }

  // ── SHA-256 Hash ──────────────────────────────────────────────────────

  async function sha256(text) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = new Uint8Array(hashBuffer);
    
    // Fast hex conversion for large documents
    let hashHex = "";
    for (let i = 0; i < hashArray.length; i++) {
      hashHex += hashArray[i].toString(16).padStart(2, "0");
    }
    return hashHex;
  }

  // ── Content Change Detection ──────────────────────────────────────────

  let changeDebounceTimer = null;

  async function handleContentChange() {
    if (!isWitnessing) return;

    // Debounce rapid changes (e.g. typing)
    clearTimeout(changeDebounceTimer);
    changeDebounceTimer = setTimeout(async () => {
      const text = getDocumentText();
      const charCount = text.length;
      const delta = charCount - lastCharCount;

      // Only send checkpoint if meaningful change occurred
      if (Math.abs(delta) < MIN_CHANGE_THRESHOLD) return;

      const contentHash = await sha256(text);
      if (contentHash === lastContentHash) return;

      lastContentHash = contentHash;
      const previousCount = lastCharCount;
      lastCharCount = charCount;

      chrome.runtime.sendMessage({
        action: "content_changed",
        contentHash,
        charCount,
        delta: charCount - previousCount,
      });
    }, 2000); // 2 second debounce
  }

  // ── Mutation Observer ─────────────────────────────────────────────────

  let observer = null;

  function startObserving() {
    if (observer) return;

    const elements = getEditorElement();
    if (!elements || elements.length === 0) {
      // Editor not loaded yet, retry
      setTimeout(startObserving, 1000);
      return;
    }

    observer = new MutationObserver(() => {
      handleContentChange();
    });

    elements.forEach((el) => {
      observer.observe(el, {
        characterData: true,
        childList: true,
        subtree: true,
      });
    });

    // Capture initial state
    const text = getDocumentText();
    lastCharCount = text.length;
    sha256(text).then((hash) => {
      lastContentHash = hash;
    });
  }

  function stopObserving() {
    if (observer) {
      observer.disconnect();
      observer = null;
    }
  }

  // ── Keystroke Timing ──────────────────────────────────────────────────

  function handleKeyDown(event) {
    if (!isWitnessing) return;

    const now = performance.now();
    keystrokeTimestamps.push(now);

    // When we have enough samples, compute intervals and send
    if (keystrokeTimestamps.length >= JITTER_BATCH_SIZE) {
      const intervals = [];
      for (let i = 1; i < keystrokeTimestamps.length; i++) {
        // Convert to microseconds (browser gives millisecond precision ~5ms)
        intervals.push(
          Math.round((keystrokeTimestamps[i] - keystrokeTimestamps[i - 1]) * 1000)
        );
      }
      keystrokeTimestamps = [keystrokeTimestamps[keystrokeTimestamps.length - 1]];

      chrome.runtime.sendMessage({
        action: "keystroke_jitter",
        intervals,
      });
    }
  }

  // ── Witnessing Control ────────────────────────────────────────────────

  function startWitnessing() {
    if (isWitnessing) return;
    
    calibrateTimer();
    isWitnessing = true;

    // Persist state for this URL
    chrome.storage.local.set({ [`witnessing_${window.location.href}`]: true });

    startObserving();
    document.addEventListener("keydown", handleKeyDown, { passive: true });

    chrome.runtime.sendMessage({
      action: "start_witnessing",
      url: window.location.href,
      title: getDocumentTitle(),
      timerResolution: timerResolution,
    });
  }

  function stopWitnessing() {
    if (!isWitnessing) return;
    isWitnessing = false;

    // Remove persisted state for this URL
    chrome.storage.local.remove([`witnessing_${window.location.href}`]);

    stopObserving();
    document.removeEventListener("keydown", handleKeyDown);
    keystrokeTimestamps = [];

    chrome.runtime.sendMessage({ action: "stop_witnessing" });
  }

  // ── Message Handling ──────────────────────────────────────────────────

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    switch (message.action) {
      case "capture_state":
        // Triggered by background.js checkpoint timer
        handleContentChange();
        sendResponse({ ok: true });
        break;

      case "start":
        startWitnessing();
        sendResponse({ ok: true });
        break;

      case "stop":
      case "stop_witnessing":
        stopWitnessing();
        sendResponse({ ok: true });
        break;

      case "get_page_info":
        sendResponse({
          ok: true,
          site: detectSite(),
          title: getDocumentTitle(),
          charCount: getDocumentText().length,
          isWitnessing,
        });
        break;

      default:
        sendResponse({ ok: false, error: "Unknown action" });
    }
    return true;
  });

  // ── Initialization ────────────────────────────────────────────────────

  // Restore witnessing state if it was active before reload
  chrome.storage.local.get([`witnessing_${window.location.href}`, "autoWitness"], (result) => {
    if (result[`witnessing_${window.location.href}`] || (result.autoWitness && detectSite())) {
      // Wait for editor to load
      setTimeout(() => {
        startWitnessing();
      }, 3000);
    }
  });
})();
