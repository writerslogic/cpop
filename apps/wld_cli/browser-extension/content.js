/**
 * WritersLogic Browser Extension — Content Script
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

  // M-115: Named constants for site detection
  const SITE_GOOGLE_DOCS = "google-docs";
  const SITE_OVERLEAF = "overleaf";
  const SITE_MEDIUM = "medium";
  const SITE_NOTION = "notion";

  // M-135: Valid actions accepted from the background script
  const VALID_CONTENT_ACTIONS = [
    "capture_state", "start", "stop", "stop_witnessing", "get_page_info"
  ];

  let isWitnessing = false;
  let lastCharCount = 0;
  let lastContentHash = "";
  let keystrokeTimestamps = [];
  let timerResolution = 0;
  let observerRetries = 0;
  const JITTER_BATCH_SIZE = 50;
  const MIN_CHANGE_THRESHOLD = 5;
  const MAX_OBSERVER_RETRIES = 20;
  const MAX_DOCUMENT_SIZE = 10 * 1024 * 1024; // 10 MB — stop traversal beyond this

  // M-091: Cached editor element references, invalidated on stop/start
  let cachedEditorElements = null;
  let cachedSite = null;

  function storageKey() {
    return `witnessing_${window.location.origin}${window.location.pathname}`;
  }

  function detectSite() {
    const hostname = window.location.hostname;
    const pathname = window.location.pathname;

    if (hostname === "docs.google.com" && pathname.startsWith("/document/")) {
      return SITE_GOOGLE_DOCS;
    }
    if (hostname === "www.overleaf.com" && pathname.startsWith("/project/")) {
      return SITE_OVERLEAF;
    }
    if (hostname === "medium.com") {
      return SITE_MEDIUM;
    }
    if (hostname.includes("notion.so")) {
      return SITE_NOTION;
    }

    return null;
  }

  /** Invalidate cached editor elements (call on start/stop witnessing). */
  function invalidateEditorCache() {
    cachedEditorElements = null;
    cachedSite = null;
  }

  /**
   * Measures the resolution of performance.now().
   * Browsers often jitter/clamp this (e.g. to 5ms) to prevent side-channels.
   * Native host needs to know this to properly weigh jitter entropy.
   */
  function calibrateTimer() {
    const samples = [];
    let last = performance.now();
    for (let i = 0; i < 10; i++) {
      let current = performance.now();
      while (current === last) {
        current = performance.now();
      }
      samples.push(current - last);
      last = current;
    }
    timerResolution = Math.min(...samples);
    console.log(`[WritersLogic] Timer resolution detected: ${timerResolution.toFixed(4)}ms`);
  }

  /**
   * M-091: Returns cached editor element references when available.
   * Cache is invalidated on start/stop witnessing and when elements are
   * detached from the DOM.
   */
  function getEditorElement() {
    // Return cache if elements are still attached to the DOM
    if (cachedEditorElements && cachedEditorElements.length > 0) {
      if (cachedEditorElements[0].isConnected) {
        return cachedEditorElements;
      }
      cachedEditorElements = null;
    }

    const site = detectSite();
    let elements;

    switch (site) {
      case SITE_GOOGLE_DOCS: {
        const pages = document.querySelectorAll(".kix-page");
        elements = pages.length > 0
          ? pages
          : document.querySelectorAll(
              '.kix-appview-editor [contenteditable="true"]'
            );
        break;
      }

      case SITE_OVERLEAF:
        elements = document.querySelectorAll(".cm-content");
        break;

      case SITE_MEDIUM:
        elements = document.querySelectorAll(
          'article [contenteditable="true"], .postArticle [contenteditable="true"], [role="textbox"]'
        );
        break;

      case SITE_NOTION:
        elements = document.querySelectorAll(
          '.notion-page-content [contenteditable="true"]'
        );
        break;

      default:
        elements = document.querySelectorAll('[contenteditable="true"]');
    }

    if (elements && elements.length > 0) {
      cachedEditorElements = elements;
      cachedSite = site;
    }
    return elements;
  }

  /**
   * Collects text from editor elements with bounded memory.
   * Walks the DOM incrementally and stops once MAX_DOCUMENT_SIZE is reached,
   * preventing OOM on malicious pages with huge content.
   */
  function getDocumentText() {
    const elements = getEditorElement();
    if (!elements || elements.length === 0) return "";

    const chunks = [];
    let totalLength = 0;

    for (const el of elements) {
      if (totalLength >= MAX_DOCUMENT_SIZE) break;

      const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
      let node;
      while ((node = walker.nextNode())) {
        const value = node.nodeValue;
        if (!value) continue;

        const remaining = MAX_DOCUMENT_SIZE - totalLength;
        if (remaining <= 0) break;

        if (value.length <= remaining) {
          chunks.push(value);
          totalLength += value.length;
        } else {
          chunks.push(value.slice(0, remaining));
          totalLength += remaining;
          break;
        }
      }
    }

    return chunks.join("");
  }

  /** Returns only the character count without building a full string. */
  function getDocumentCharCount() {
    const elements = getEditorElement();
    if (!elements || elements.length === 0) return 0;

    let total = 0;
    for (const el of elements) {
      if (total >= MAX_DOCUMENT_SIZE) break;

      const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
      let node;
      while ((node = walker.nextNode())) {
        const value = node.nodeValue;
        if (!value) continue;
        total += value.length;
        if (total >= MAX_DOCUMENT_SIZE) {
          return MAX_DOCUMENT_SIZE;
        }
      }
    }
    return total;
  }

  function getDocumentTitle() {
    const site = detectSite();

    switch (site) {
      case SITE_GOOGLE_DOCS: {
        const titleEl = document.querySelector(".docs-title-input input");
        return titleEl?.value || document.title.replace(" - Google Docs", "");
      }
      case SITE_OVERLEAF:
        return document.title.replace(" - Overleaf, Online LaTeX Editor", "");
      case SITE_MEDIUM:
        return (
          document.querySelector("h3.graf--title")?.textContent ||
          document.title
        );
      case SITE_NOTION:
        return (
          document.querySelector(".notion-page-block .notranslate")
            ?.textContent || document.title
        );
      default:
        return document.title;
    }
  }

  async function sha256(text) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = new Uint8Array(hashBuffer);
    
    let hashHex = "";
    for (let i = 0; i < hashArray.length; i++) {
      hashHex += hashArray[i].toString(16).padStart(2, "0");
    }
    return hashHex;
  }

  let changeDebounceTimer = null;

  async function handleContentChange() {
    if (!isWitnessing) return;

    clearTimeout(changeDebounceTimer);
    changeDebounceTimer = setTimeout(async () => {
      const text = getDocumentText();
      const charCount = text.length;
      const delta = charCount - lastCharCount;

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
    }, 2000);
  }

  let observer = null;

  function startObserving() {
    if (observer) return;

    const elements = getEditorElement();
    if (!elements || elements.length === 0) {
      if (++observerRetries < MAX_OBSERVER_RETRIES) {
        setTimeout(startObserving, 1000);
      }
      return;
    }
    observerRetries = 0;

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

  function handleKeyDown(event) {
    if (!isWitnessing) return;

    const now = performance.now();
    keystrokeTimestamps.push(now);

    if (keystrokeTimestamps.length >= JITTER_BATCH_SIZE) {
      const intervals = [];
      for (let i = 1; i < keystrokeTimestamps.length; i++) {
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

  function startWitnessing() {
    if (isWitnessing) return;

    calibrateTimer();
    isWitnessing = true;
    invalidateEditorCache();

    chrome.storage.local.set({ [`${storageKey()}`]: true });

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
    invalidateEditorCache();

    chrome.storage.local.remove([`${storageKey()}`]);

    stopObserving();
    document.removeEventListener("keydown", handleKeyDown);
    keystrokeTimestamps = [];

    chrome.runtime.sendMessage({ action: "stop_witnessing" });
  }

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    // SYS-019/M-135: Validate sender is our own extension
    if (sender.id !== chrome.runtime.id) {
      return;
    }

    // SYS-019: Validate message structure and action
    if (!message || typeof message !== "object" || typeof message.action !== "string") {
      return;
    }
    if (!VALID_CONTENT_ACTIONS.includes(message.action)) {
      sendResponse({ ok: false, error: "Unknown action" });
      return true;
    }

    switch (message.action) {
      case "capture_state":
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
          charCount: getDocumentCharCount(),
          isWitnessing,
        });
        break;

      default:
        sendResponse({ ok: false, error: "Unknown action" });
    }
    return true;
  });

  chrome.storage.local.get([`${storageKey()}`, "autoWitness"], (result) => {
    if (result[`${storageKey()}`] || (result.autoWitness && detectSite())) {
      setTimeout(() => {
        startWitnessing();
      }, 3000);
    }
  });
})();
