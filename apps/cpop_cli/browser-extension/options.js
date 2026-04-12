/**
 * CPoE Browser Extension — Options Script
 */

const DEFAULTS = {
  autoWitness: false,
  checkpointInterval: 30,
  contentTier: "enhanced",
  captureJitter: true,
  enabledSites: {
    "google-docs": true,
    overleaf: true,
    medium: true,
    notion: true,
  },
};

const elements = {
  autoWitness: document.getElementById("auto-witness"),
  checkpointInterval: document.getElementById("checkpoint-interval"),
  contentTier: document.getElementById("content-tier"),
  captureJitter: document.getElementById("capture-jitter"),
  btnSave: document.getElementById("btn-save"),
  saveStatus: document.getElementById("save-status"),
};

async function loadSettings() {
  const result = await chrome.storage.local.get(Object.keys(DEFAULTS));
  const settings = { ...DEFAULTS, ...result };

  elements.autoWitness.checked = settings.autoWitness;
  elements.checkpointInterval.value = settings.checkpointInterval;
  elements.contentTier.value = settings.contentTier;
  elements.captureJitter.checked = settings.captureJitter;

  document.querySelectorAll(".site-toggle input[data-site]").forEach((input) => {
    const site = input.dataset.site;
    input.checked = settings.enabledSites?.[site] ?? true;
  });
}

async function saveSettings() {
  const enabledSites = {};
  document.querySelectorAll(".site-toggle input[data-site]").forEach((input) => {
    enabledSites[input.dataset.site] = input.checked;
  });

  const settings = {
    autoWitness: elements.autoWitness.checked,
    checkpointInterval: parseInt(elements.checkpointInterval.value, 10) || 30,
    contentTier: elements.contentTier.value,
    captureJitter: elements.captureJitter.checked,
    enabledSites,
  };

  await chrome.storage.local.set(settings);

  elements.saveStatus.textContent = "Saved";
  setTimeout(() => {
    elements.saveStatus.textContent = "";
  }, 2000);
}

elements.btnSave.addEventListener("click", saveSettings);

loadSettings();
