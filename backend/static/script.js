// SCRIPT.JS — FULL VERSION WITH AUTH + QR + SUBSCRIPTION + GOOGLE

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
const googleBtn = document.getElementById("google-login-btn");

// Subscription page elements (only exist on /subscribe)
const subMonthlyBtn = document.getElementById("subscribe-monthly-btn");
const subYearlyBtn = document.getElementById("subscribe-yearly-btn");
const subscribeStatus = document.getElementById("subscribe-status");

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
  if (!verdictBadge) return;

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
    if (authHint) {
      authHint.innerHTML =
        'No account yet? Switch to <strong>Create Account</strong> to start with the free tier.';
    }
  } else {
    authTabSignup.classList.add("auth-tab-active");
    authTabLogin.classList.remove("auth-tab-active");
    if (authHint) {
      authHint.textContent =
        "We’ll start you on the free plan. Upgrade to Premium anytime for unlimited scans.";
    }
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

// Google sign-in button
if (googleBtn) {
  googleBtn.addEventListener("click", () => {
    window.location.href = `${API_BASE_URL}/auth/google/login`;
  });
}

function updatePlanPill() {
  if (!planPill) {
    // Still update account button text
    if (currentUser && accountBtn) {
      accountBtn.textContent = currentUser.user.email;
    } else if (accountBtn) {
      accountBtn.textContent = "Sign In";
    }
    return;
  }

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

    if (authStatus) {
      authStatus.textContent =
        authMode === "login"
          ? "Signing you in…"
          : "Creating your account…";
      authStatus.classList.remove(
        "auth-status--error",
        "auth-status--success"
      );
    }

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
        if (authStatus) {
          authStatus.textContent = data.error || "Authentication failed.";
          authStatus.classList.add("auth-status--error");
        }
        return;
      }

      currentUser = data;
      if (authStatus) {
        authStatus.textContent = "You’re in. Syncing your protection…";
        authStatus.classList.add("auth-status--success");
      }
      updatePlanPill();

      setTimeout(() => {
        closeAuthModal();
        authForm.reset();
      }, 600);
    } catch (err) {
      if (authStatus) {
        authStatus.textContent = "Network error. Try again in a moment.";
        authStatus.classList.add("auth-status--error");
      }
    }
  });
}

// ===================== PREMIUM MODE BLOCKING (UI) ======================

// Prevent free / guest from selecting premium-only modes
const premiumOnlyModes = new Set(["chat", "manipulation", "qr"]);

const modeRadios = document.querySelectorAll('input[name="mode"]');
if (modeRadios.length && statusEl) {
  modeRadios.forEach((radio) => {
    radio.addEventListener("change", () => {
      const val = radio.value;
      if (!premiumOnlyModes.has(val)) return;

      const plan =
        currentUser?.user?.plan || "guest";

      if (plan !== "premium") {
        statusEl.textContent =
          "This scan mode is for Premium members only. Sign in and upgrade to unlock it.";
        // bounce them back to auto
        const autoRadio = document.querySelector(
          'input[name="mode"][value="auto"]'
        );
        if (autoRadio) autoRadio.checked = true;
        openAuthModal();
      }
    });
  });
}

// ===================== SUBSCRIPTION FRONTEND ======================

async function startCheckout(mode) {
  if (!subscribeStatus) return;
  subscribeStatus.textContent = "Redirecting to secure checkout…";

  try {
    const res = await fetch(`${API_BASE_URL}/create-checkout-session`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ mode }),
    });

    const data = await res.json();

    if (!res.ok) {
      if (res.status === 401) {
        subscribeStatus.textContent =
          "Sign in or create a free account first.";
        openAuthModal();
        return;
      }

      subscribeStatus.textContent =
        data.error || "Unable to start checkout right now.";
      return;
    }

    if (data.url) {
      window.location.href = data.url;
    } else {
      subscribeStatus.textContent =
        "Unexpected response from billing server.";
    }
  } catch (err) {
    subscribeStatus.textContent =
      "Network error starting checkout. Try again.";
  }
}

if (subMonthlyBtn) {
  subMonthlyBtn.addEventListener("click", () => startCheckout("monthly"));
}

if (subYearlyBtn) {
  subYearlyBtn.addEventListener("click", () => startCheckout("yearly"));
}

// ===================== MAIN ANALYZE ======================

async function analyzeContent() {
  if (!contentInput || !statusEl) return;

  const content = contentInput.value.trim();
  const mode = getSelectedMode();

  if (!content && mode !== "qr") {
    statusEl.textContent = "Paste a message, link, or conversation first.";
    return;
  }

  statusEl.textContent = "Running scam + manipulation checks…";
  if (analyzeBtn) analyzeBtn.disabled = true;

  try {
    const response = await fetch(`${API_BASE_URL}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ content, mode }),
    });

    const result = await response.json();

    if (!response.ok) {
      if (response.status === 402) {
        statusEl.textContent =
          result.error ||
          "This feature is reserved for Premium members.";
        // gentle nudge
        openAuthModal();
        return;
      }

      statusEl.textContent =
        result.error || "Something went wrong during analysis.";
      return;
    }

    if (!verdictBadge || !resultSection || !explanationEl || !reasonsList) {
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
      // Details are hidden for now (they're more technical)
      detailsPre.hidden = true;
    }

    resultSection.hidden = false;
    statusEl.textContent = "";
    // Refresh session counts if logged in
    loadSession();
  } catch (err) {
    statusEl.textContent = "Network error. Try again in a moment.";
  } finally {
    if (analyzeBtn) analyzeBtn.disabled = false;
  }
}

// ===================== QR SCAN ======================

async function analyzeQR(file) {
  if (!statusEl) return;

  statusEl.textContent = "Scanning QR code and checking destination safety…";
  if (analyzeBtn) analyzeBtn.disabled = true;

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
      if (response.status === 402) {
        statusEl.textContent =
          result.error ||
          "QR and screenshot analysis are reserved for Premium members.";
        openAuthModal();
        return;
      }

      statusEl.textContent =
        result.error || "Failed to analyze QR. Try a clearer image.";
      return;
    }

    if (!verdictBadge || !resultSection || !explanationEl || !reasonsList) {
      return;
    }

    const verdict = result.verdict || "SAFE";
    const score = result.score ?? 0;

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

    explanationEl.textContent = result.explanation || "";

    reasonsList.innerHTML = "";
    // (Optional) you could list each QR here if you want

    if (detailsPre) {
      detailsPre.hidden = true;
    }

    resultSection.hidden = false;
    statusEl.textContent = "";
    loadSession();
  } catch (err) {
    statusEl.textContent = "Failed to analyze QR. Try a clearer image.";
  } finally {
    if (analyzeBtn) analyzeBtn.disabled = false;
  }
}

// ===================== OCR ======================

async function runOCR(imageFile) {
  if (!statusEl || !contentInput) return;

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