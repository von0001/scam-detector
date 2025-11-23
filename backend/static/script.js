// SCRIPT.JS — AUTH + BILLING + QR + GOOGLE

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

const accountMenu = document.getElementById("account-menu");
const accountMenuEmail = document.getElementById("account-menu-email");
const accountLogoutBtn = document.getElementById("account-logout-btn");
const accountManageBtn = document.getElementById("account-manage-btn");

const authModal = document.getElementById("auth-modal");
const authClose = document.getElementById("auth-close");
const authForm = document.getElementById("auth-form");
const authEmail = document.getElementById("auth-email");
const authPassword = document.getElementById("auth-password");
const authStatus = document.getElementById("auth-status");
const authHint = document.getElementById("auth-hint");
const authTabLogin = document.getElementById("auth-tab-login");
const authTabSignup = document.getElementById("auth-tab-signup");
const googleBtnContainer = document.getElementById("google-btn");

const startFreeBtn = document.getElementById("start-free-btn");
const upgradeMonthlyBtn = document.getElementById("upgrade-monthly");
const upgradeYearlyBtn = document.getElementById("upgrade-yearly");

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
  if (!authTabLogin || !authTabSignup || !authHint) return;

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

function closeAccountMenu() {
  if (accountMenu) accountMenu.hidden = true;
}

function toggleAccountMenu() {
  if (!accountMenu) return;
  accountMenu.hidden = !accountMenu.hidden;
}

if (accountBtn) {
  accountBtn.addEventListener("click", (e) => {
    e.preventDefault();
    if (currentUser) {
      toggleAccountMenu();
    } else {
      openAuthModal();
    }
  });
}

if (authClose) {
  authClose.addEventListener("click", (e) => {
    e.preventDefault();
    closeAuthModal();
  });
}

// Close account menu when clicking outside
document.addEventListener("click", (e) => {
  if (!accountMenu || accountMenu.hidden) return;
  if (
    accountBtn &&
    (e.target === accountBtn || accountBtn.contains(e.target))
  ) {
    return;
  }
  if (accountMenu.contains(e.target)) return;
  closeAccountMenu();
});

function updatePremiumModeLock() {
  const premiumPills = document.querySelectorAll('.mode-pill[data-premium="true"]');
  const plan = currentUser?.user?.plan ?? "guest";

  premiumPills.forEach((pill) => {
    const input = pill.querySelector('input[type="radio"]');
    if (!input) return;
    if (plan === "premium") {
      pill.classList.remove("mode-pill-locked");
      input.disabled = false;
    } else {
      pill.classList.add("mode-pill-locked");
      // still let them select; backend will refuse, but UX shows lock
    }
  });
}

function updatePlanPill() {
  if (!planPill) return;

  if (!currentUser) {
    planPill.innerHTML =
      "Guest mode · Limited free scans. <span>Sign in</span> to sync and unlock more.";
    if (accountBtn) accountBtn.textContent = "Sign In";
    if (accountMenuEmail) accountMenuEmail.textContent = "";
    updatePremiumModeLock();
    return;
  }

  const user = currentUser.user;
  const plan = user.plan;
  const used = user.daily_scan_count ?? 0;
  const limit = user.daily_limit ?? 0;

  if (plan === "premium") {
    planPill.innerHTML =
      "<span>Premium</span> · Unlimited scans & deep analysis.";
  } else {
    const remaining = Math.max((limit || 0) - used, 0);
    planPill.innerHTML = `<span>Free plan</span> · ${remaining} of ${limit} daily scans left.`;
  }

  if (accountBtn) accountBtn.textContent = user.email;
  if (accountMenuEmail) accountMenuEmail.textContent = user.email;
  updatePremiumModeLock();
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

// Call on load
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

// Logout
if (accountLogoutBtn) {
  accountLogoutBtn.addEventListener("click", async (e) => {
    e.preventDefault();
    try {
      await fetch(`${API_BASE_URL}/logout`, {
        method: "POST",
        credentials: "include",
      });
    } catch (_) {}
    currentUser = null;
    closeAccountMenu();
    updatePlanPill();
  });
}

// Manage subscription → jump to pricing or start checkout if already there
if (accountManageBtn) {
  accountManageBtn.addEventListener("click", (e) => {
    e.preventDefault();
    closeAccountMenu();
    if (window.location.pathname === "/pricing") {
      window.scrollTo({ top: 0, behavior: "smooth" });
    } else {
      window.location.href = "/pricing";
    }
  });
}

// ===================== GOOGLE SIGN-IN ======================

function initGoogleButton() {
  if (!googleBtnContainer) return;
  const clientId = googleBtnContainer.dataset.googleClientId || "";
  if (!clientId) return;
  if (!(window.google && window.google.accounts && window.google.accounts.id)) {
    return;
  }

  window.google.accounts.id.initialize({
    client_id: clientId,
    callback: handleGoogleCredential,
  });

  window.google.accounts.id.renderButton(googleBtnContainer, {
    type: "standard",
    theme: "outline",
    size: "large",
    width: "100",
  });
}

async function handleGoogleCredential(response) {
  if (!response || !response.credential) return;
  if (authStatus) {
    authStatus.textContent = "Signing in with Google…";
    authStatus.classList.remove("auth-status--error", "auth-status--success");
  }

  try {
    const res = await fetch(`${API_BASE_URL}/auth/google`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ id_token: response.credential }),
    });
    const data = await res.json();

    if (!res.ok) {
      if (authStatus) {
        authStatus.textContent = data.error || "Google sign-in failed.";
        authStatus.classList.add("auth-status--error");
      }
      return;
    }

    currentUser = data;
    if (authStatus) {
      authStatus.textContent = "You’re in with Google.";
      authStatus.classList.add("auth-status--success");
    }
    updatePlanPill();

    setTimeout(() => {
      closeAuthModal();
      if (authForm) authForm.reset();
    }, 600);
  } catch (err) {
    if (authStatus) {
      authStatus.textContent = "Network error during Google sign-in.";
      authStatus.classList.add("auth-status--error");
    }
  }
}

window.addEventListener("load", () => {
  try {
    initGoogleButton();
  } catch (e) {
    // ignore
  }
});

// ===================== MAIN ANALYZE ======================

async function analyzeContent() {
  const content = contentInput ? contentInput.value.trim() : "";
  const mode = getSelectedMode();

  if (!content && mode !== "qr") {
    if (statusEl) {
      statusEl.textContent = "Paste a message, link, or conversation first.";
    }
    return;
  }

  if (statusEl) {
    statusEl.textContent = "Running scam + manipulation checks…";
  }
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
      if (statusEl) {
        statusEl.textContent =
          result.error || "Something went wrong during analysis.";
      }
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
    if (statusEl) statusEl.textContent = "";
    // Refresh session counts if logged in
    loadSession();
  } catch (err) {
    if (statusEl) {
      statusEl.textContent = "Network error. Try again in a moment.";
    }
  } finally {
    if (analyzeBtn) analyzeBtn.disabled = false;
  }
}

// ===================== QR SCAN ======================

async function analyzeQR(file) {
  if (statusEl) {
    statusEl.textContent = "Scanning QR code and checking destination safety…";
  }
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
      if (statusEl) {
        statusEl.textContent =
          result.error || "Failed to analyze QR. Try a clearer image.";
      }
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
    if (statusEl) statusEl.textContent = "";
    loadSession();
  } catch (err) {
    if (statusEl) {
      statusEl.textContent = "Failed to analyze QR. Try a clearer image.";
    }
  } finally {
    if (analyzeBtn) analyzeBtn.disabled = false;
  }
}

// ===================== OCR ======================

async function runOCR(imageFile) {
  if (statusEl) {
    statusEl.textContent = "Reading text from your screenshot…";
  }
  try {
    const worker = await Tesseract.createWorker();
    await worker.load();
    await worker.loadLanguage("eng");
    await worker.initialize("eng");

    const { data } = await worker.recognize(imageFile);
    await worker.terminate();

    const extractedText = data.text.trim();
    if (!extractedText) {
      if (statusEl) {
        statusEl.textContent = "No readable text found in the image.";
      }
      return;
    }

    if (contentInput) contentInput.value = extractedText;
    if (statusEl) {
      statusEl.textContent = "Text extracted — running safety check…";
    }
    analyzeContent();
  } catch (err) {
    if (statusEl) {
      statusEl.textContent = "OCR failed. Try a clearer or closer screenshot.";
    }
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

// ===================== BILLING (Stripe) ======================

async function startCheckout(period) {
  if (!currentUser) {
    openAuthModal();
    return;
  }

  const btn =
    period === "year" ? upgradeYearlyBtn : upgradeMonthlyBtn;

  if (btn) btn.disabled = true;

  try {
    const res = await fetch(`${API_BASE_URL}/billing/create-checkout-session`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ billing_period: period }),
    });

    const data = await res.json();
    if (!res.ok || !data.url) {
      const msg = data.error || "Unable to start checkout.";
      // keeping it simple here
      alert(msg);
      return;
    }

    window.location.href = data.url;
  } catch (err) {
    alert("Network error starting checkout.");
  } finally {
    if (btn) btn.disabled = false;
  }
}

if (startFreeBtn) {
  startFreeBtn.addEventListener("click", (e) => {
    e.preventDefault();
    openAuthModal();
  });
}

if (upgradeMonthlyBtn) {
  upgradeMonthlyBtn.addEventListener("click", (e) => {
    e.preventDefault();
    startCheckout("month");
  });
}

if (upgradeYearlyBtn) {
  upgradeYearlyBtn.addEventListener("click", (e) => {
    e.preventDefault();
    startCheckout("year");
  });
}