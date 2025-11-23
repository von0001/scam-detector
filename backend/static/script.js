// SCRIPT.JS — FULL VERSION WITH AUTH + QR

const API_BASE_URL = "https://scamdetectorapp.com";

// Core scan elements
const contentInput = document.getElementById("content-input");
const analyzeBtn = document.getElementById("analyze-btn");
const statusEl = document.getElementById("status");

const resultSection = document.getElementById("result-section");
const verdictBadge = document.getElementById("verdict-badge");
const explanationEl = document.getElementById("explanation");
const reasonsList = document.getElementById("reasons-list");
const detailsPre = document.getElementById("details-json");

const ocrBtn = document.getElementById("ocr-btn");
const fileInput = document.getElementById("ocr-file");
const dropZone = document.getElementById("drop-zone");

// Auth / account elements
const accountBtn = document.getElementById("account-button");
const planPill = document.getElementById("plan-pill");

const authModal = document.getElementById("auth-modal");
const authClose = document.getElementById("auth-close");
const authForm = document.getElementById("auth-form");
const authEmail = document.getElementById("auth-email");
const authPassword = document.getElementById("auth-password");
const authStatus = document.getElementById("auth-status");
const authHint = document.getElementById("auth-hint");
const authTabLogin = document.getElementById("auth-tab-login");
const authTabSignup = document.getElementById("auth-tab-signup");

let authMode = "login";
let currentUser = null;

// MODE
function getSelectedMode() {
  const radios = document.querySelectorAll('input[name="mode"]');
  for (const r of radios) if (r.checked) return r.value;
  return "auto";
}

// Verdict color + label
function setVerdictStyle(verdict) {
  verdictBadge.classList.remove(
    "verdict-safe",
    "verdict-suspicious",
    "verdict-dangerous"
  );

  if (verdict === "SAFE") {
    verdictBadge.classList.add("verdict-safe");
  } else if (verdict === "SUSPICIOUS") {
    verdictBadge.classList.add("verdict-suspicious");
  } else if (verdict === "DANGEROUS") {
    verdictBadge.classList.add("verdict-dangerous");
  }
}

// ===================== AUTH UI ======================

function setAuthMode(mode) {
  authMode = mode;
  if (!authTabLogin || !authTabSignup) return;

  if (mode === "login") {
    authTabLogin.classList.add("auth-tab-active");
    authTabSignup.classList.remove("auth-tab-active");
    authHint.innerHTML =
      'No account yet? Switch to <strong>Create Account</strong> to start with the free tier.';
  } else {
    authTabSignup.classList.add("auth-tab-active");
    authTabLogin.classList.remove("auth-tab-active");
    authHint.textContent =
      "We’ll start you on the free plan. Upgrade to Premium anytime for unlimited scans.";
  }
}

if (authTabLogin && authTabSignup) {
  authTabLogin.addEventListener("click", () => setAuthMode("login"));
  authTabSignup.addEventListener("click", () => setAuthMode("signup"));
}

function openAuthModal() {
  if (authModal) authModal.hidden = false;
  if (authStatus) {
    authStatus.textContent = "";
    authStatus.classList.remove("auth-status--error", "auth-status--success");
  }
}

function closeAuthModal() {
  if (authModal) authModal.hidden = true;
}

if (accountBtn) {
  accountBtn.addEventListener("click", (e) => {
    e.preventDefault();
    openAuthModal();
  });
}

if (authClose) {
  authClose.addEventListener("click", (e) => {
    e.preventDefault();
    closeAuthModal();
  });
}

function updatePlanPill() {
  if (!planPill) return;

  if (!currentUser) {
    planPill.innerHTML =
      "Guest mode · Limited free scans. <span>Sign in</span> to sync and unlock more.";
    if (accountBtn) accountBtn.textContent = "Sign In";
    return;
  }

  const user = currentUser.user;
  const plan = user.plan;
  const used = user.daily_scan_count ?? 0;
  const limit = user.daily_limit ?? 0;

  if (plan === "premium") {
    planPill.innerHTML =
      "<span>Premium</span> · Unlimited scans & deep analysis.";
    if (accountBtn) accountBtn.textContent = user.email;
  } else {
    const remaining = Math.max((limit || 0) - used, 0);
    planPill.innerHTML = `<span>Free plan</span> · ${remaining} of ${limit} daily scans left.`;
    if (accountBtn) accountBtn.textContent = user.email;
  }
}

async function loadSession() {
  try {
    const res = await fetch(`${API_BASE_URL}/me`, {
      method: "GET",
      credentials: "include",
    });

    if (!res.ok) {
      currentUser = null;
      updatePlanPill();
      return;
    }

    const data = await res.json();
    if (!data.authenticated) {
      currentUser = null;
    } else {
      currentUser = data;
    }
    updatePlanPill();
  } catch (err) {
    currentUser = null;
    updatePlanPill();
  }
}

loadSession();

if (authForm) {
  authForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!authEmail.value || !authPassword.value) return;

    authStatus.textContent =
      authMode === "login"
        ? "Signing you in…"
        : "Creating your account…";
    authStatus.classList.remove("auth-status--error", "auth-status--success");

    const endpoint = authMode === "login" ? "/login" : "/signup";

    try {
      const res = await fetch(`${API_BASE_URL}${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          email: authEmail.value.trim(),
          password: authPassword.value,
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        authStatus.textContent = data.error || "Authentication failed.";
        authStatus.classList.add("auth-status--error");
        return;
      }

      currentUser = data;
      authStatus.textContent = "You’re in. Syncing your protection…";
      authStatus.classList.add("auth-status--success");
      updatePlanPill();

      setTimeout(() => {
        closeAuthModal();
        authForm.reset();
      }, 600);
    } catch (err) {
      authStatus.textContent = "Network error. Try again in a moment.";
      authStatus.classList.add("auth-status--error");
    }
  });
}

// ===================== MAIN ANALYZE ======================

async function analyzeContent() {
  const content = contentInput.value.trim();
  const mode = getSelectedMode();

  if (!content && mode !== "qr") {
    statusEl.textContent = "Paste a message, link, or conversation first.";
    return;
  }

  statusEl.textContent = "Running scam + manipulation checks…";
  analyzeBtn.disabled = true;

  try {
    const response = await fetch(`${API_BASE_URL}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ content, mode }),
    });

    const result = await response.json();
    if (!response.ok) {
      statusEl.textContent =
        result.error || "Something went wrong during analysis.";
      return;
    }

    let label = "";
    if (result.verdict === "SAFE") {
      label = "SAFE · No major scam patterns detected";
    } else if (result.verdict === "SUSPICIOUS") {
      label = "SUSPICIOUS · Some warning signs present";
    } else if (result.verdict === "DANGEROUS") {
      label = "DANGEROUS · Strong scam or manipulation risk";
    } else {
      label = result.verdict || "Result";
    }

    verdictBadge.textContent = label;
    setVerdictStyle(result.verdict);
    explanationEl.textContent = result.explanation || "";

    reasonsList.innerHTML = "";
    (result.reasons || []).forEach((r) => {
      const li = document.createElement("li");
      li.textContent = r;
      reasonsList.appendChild(li);
    });

    if (detailsPre) {
      detailsPre.hidden = true;
    }

    resultSection.hidden = false;
    statusEl.textContent = "";
    // Refresh session counts if logged in
    loadSession();
  } catch (err) {
    statusEl.textContent = "Network error. Try again in a moment.";
  } finally {
    analyzeBtn.disabled = false;
  }
}

// ===================== QR SCAN ======================

async function analyzeQR(file) {
  statusEl.textContent = "Scanning QR code and checking destination safety…";
  analyzeBtn.disabled = true;

  const form = new FormData();
  form.append("image", file);

  try {
    const response = await fetch(`${API_BASE_URL}/qr`, {
      method: "POST",
      body: form,
      credentials: "include",
    });
    const result = await response.json();

    if (!response.ok) {
      statusEl.textContent =
        result.error || "Failed to analyze QR. Try a clearer image.";
      return;
    }

    const verdict = result.overall?.combined_verdict || "SAFE";
    const score = result.overall?.combined_risk_score ?? 0;

    let label = "";
    if (verdict === "SAFE") {
      label = `SAFE QR · Score ${score}`;
    } else if (verdict === "SUSPICIOUS") {
      label = `SUSPICIOUS QR · Score ${score}`;
    } else if (verdict === "DANGEROUS") {
      label = `DANGEROUS QR · Score ${score}`;
    } else {
      label = `QR Score ${score}`;
    }

    verdictBadge.textContent = label;
    setVerdictStyle(verdict);

    explanationEl.textContent = `Detected ${result.count} QR code(s).`;

    reasonsList.innerHTML = "";
    (result.items || []).forEach((item) => {
      const li = document.createElement("li");
      li.textContent = `${item.qr_type.toUpperCase()} → ${item.verdict}: ${item.content}`;
      reasonsList.appendChild(li);
    });

    if (detailsPre) {
      detailsPre.hidden = true;
    }

    resultSection.hidden = false;
    statusEl.textContent = "";
    loadSession();
  } catch (err) {
    statusEl.textContent = "Failed to analyze QR. Try a clearer image.";
  } finally {
    analyzeBtn.disabled = false;
  }
}

// ===================== OCR ======================

async function runOCR(imageFile) {
  statusEl.textContent = "Reading text from your screenshot…";
  try {
    const worker = await Tesseract.createWorker();
    await worker.load();
    await worker.loadLanguage("eng");
    await worker.initialize("eng");

    const { data } = await worker.recognize(imageFile);
    await worker.terminate();

    const extractedText = data.text.trim();
    if (!extractedText) {
      statusEl.textContent = "No readable text found in the image.";
      return;
    }

    contentInput.value = extractedText;
    statusEl.textContent = "Text extracted — running safety check…";
    analyzeContent();
  } catch (err) {
    statusEl.textContent = "OCR failed. Try a clearer or closer screenshot.";
  }
}

// Upload select
if (ocrBtn && fileInput) {
  ocrBtn.addEventListener("click", () => fileInput.click());

  fileInput.addEventListener("change", () => {
    const file = fileInput.files[0];
    if (!file) return;
    const mode = getSelectedMode();
    if (mode === "qr") analyzeQR(file);
    else runOCR(file);
  });
}

// Drag & drop
if (dropZone) {
  dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.classList.add("dragover");
  });
  dropZone.addEventListener("dragleave", () =>
    dropZone.classList.remove("dragover")
  );
  dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.classList.remove("dragover");
    const file = e.dataTransfer.files[0];
    if (!file) return;
    const mode = getSelectedMode();
    if (mode === "qr") analyzeQR(file);
    else runOCR(file);
  });
}

// Submit
if (analyzeBtn) {
  analyzeBtn.addEventListener("click", (e) => {
    e.preventDefault();
    analyzeContent();
  });
}

// Ctrl+Enter submit
if (contentInput) {
  contentInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) analyzeContent();
  });
}