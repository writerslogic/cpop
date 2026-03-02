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

  let isWitnessing = false;
  let lastCharCount = 0;
  let lastContentHash = "";
  let keystrokeTimestamps = [];
  let timerResolution = 0;
  let observerRetries = 0;
  const JITTER_BATCH_SIZE = 50;
  const MIN_CHANGE_THRESHOLD = 5;
  const MAX_OBSERVER_RETRIES = 20;

  function storageKey() {
    return `witnessing_${window.location.origin}${window.location.pathname}`;
  }

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
    console.log(`[Witnessd] Timer resolution detected: ${timerResolution.toFixed(4)}ms`);
  }

  function getEditorElement() {
    const site = detectSite();

    switch (site) {
      case "google-docs": {
        const pages = document.querySelectorAll(".kix-page");
        if (pages.length > 0) return pages;
        return document.querySelectorAll(
          '.kix-appview-editor [contenteditable="true"]'
        );
      }

      case "overleaf": {
        return document.querySelectorAll(".cm-content");
      }

      case "medium": {
        return document.querySelectorAll(
          'article [contenteditable="true"], .postArticle [contenteditable="true"], [role="textbox"]'
        );
      }

      case "notion": {
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

    chrome.storage.local.remove([`${storageKey()}`]);

    stopObserving();
    document.removeEventListener("keydown", handleKeyDown);
    keystrokeTimestamps = [];

    chrome.runtime.sendMessage({ action: "stop_witnessing" });
  }

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
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
          charCount: getDocumentText().length,
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
