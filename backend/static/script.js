// SCRIPT.JS — FULL VERSION WITH AUTH + ACCOUNT + QR + GOOGLE

const API_BASE_URL = "https://scamdetectorapp.com";

// Core scan elements (home page)
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

// Auth / account elements (shared)
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
const googleBtnContainer = document.getElementById("google-btn");

// account dropdown
const accountMenu = document.getElementById("account-menu");
const accountMenuEmail = document.getElementById("account-menu-email");
const accountManageBtn = document.getElementById("account-manage-btn");
const accountLogoutBtn = document.getElementById("account-logout-btn");

// Account page elements
const overviewEmail = document.getElementById("overview-email");
const overviewPlan = document.getElementById("overview-plan");
const overviewUsage = document.getElementById("overview-usage");
const overviewAuth = document.getElementById("overview-auth");

const passwordForm = document.getElementById("password-form");
const passwordCurrent = document.getElementById("password-current");
const passwordNew = document.getElementById("password-new");
const passwordConfirm = document.getElementById("password-confirm");
const passwordStatus = document.getElementById("password-status");
const passwordHint = document.getElementById("password-hint");

const historyBtn = document.getElementById("download-history-btn");
const historyStatus = document.getElementById("history-status");

const deleteForm = document.getElementById("delete-form");
const deletePassword = document.getElementById("delete-password");
const deleteConfirmText = document.getElementById("delete-confirm-text");
const deleteStatus = document.getElementById("delete-status");

const accountBillingBtn = document.getElementById("account-billing-btn");

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

function openAccountMenu() {
  if (!accountMenu) return;
  accountMenu.hidden = false;
}

function closeAccountMenu() {
  if (!accountMenu) return;
  accountMenu.hidden = true;
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

document.addEventListener("click", (e) => {
  if (!accountMenu || !accountBtn) return;
  if (accountMenu.hidden) return;
  if (
    accountMenu.contains(e.target) ||
    accountBtn.contains(e.target)
  ) {
    return;
  }
  closeAccountMenu();
});

// ===================== OVERVIEW ======================

function updateAccountOverview() {
  if (!currentUser || !overviewEmail) return;

  const u = currentUser.user;
  overviewEmail.textContent = u.email;
  overviewPlan.textContent = u.plan === "premium" ? "Premium" : "Free";

  const used = u.daily_scan_count ?? 0;
  const limit = u.daily_limit ?? 0;
  overviewUsage.textContent =
    u.plan === "premium" ? "Unlimited today" : `${used} / ${limit} scans today`;

  const method = u.auth_method || "password";
  if (overviewAuth) {
    if (method === "google") {
      overviewAuth.textContent = "Google only";
    } else if (method === "mixed") {
      overviewAuth.textContent = "Email + Google";
    } else {
      overviewAuth.textContent = "Email + password";
    }
  }

  if (passwordForm && passwordHint && passwordCurrent && passwordNew && passwordConfirm) {
    if (method === "google") {
      passwordHint.textContent =
        "This account uses Google Sign-In only. Password change is disabled for now.";
      passwordCurrent.disabled = true;
      passwordNew.disabled = true;
      passwordConfirm.disabled = true;
      const btn = passwordForm.querySelector("button[type='submit']");
      if (btn) btn.disabled = true;
    } else {
      passwordHint.textContent =
        "Change your password for email sign-in.";
      passwordCurrent.disabled = false;
      passwordNew.disabled = false;
      passwordConfirm.disabled = false;
      const btn = passwordForm.querySelector("button[type='submit']");
      if (btn) btn.disabled = false;
    }
  }
}

function updatePlanPill() {
  if (!planPill) {
    updateAccountOverview();
    return;
  }

  if (!currentUser) {
    planPill.innerHTML =
      "Guest mode · Limited free scans. <span>Sign in</span> to sync and unlock more.";
    if (accountBtn) accountBtn.textContent = "Sign In";
    if (accountMenuEmail) accountMenuEmail.textContent = "";
    updateAccountOverview();
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

  updateAccountOverview();
}

// ===================== GOOGLE SIGN-IN ======================

function handleGoogleCredential(response) {
  if (!response || !response.credential) return;
  if (!authStatus) return;

  authStatus.textContent = "Signing you in with Google…";
  authStatus.classList.remove("auth-status--error", "auth-status--success");

  fetch(`${API_BASE_URL}/auth/google`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ credential: response.credential }),
  })
    .then((res) => res.json().then((data) => ({ ok: res.ok, data })))
    .then(({ ok, data }) => {
      if (!ok) {
        authStatus.textContent = data.error || "Google sign-in failed.";
        authStatus.classList.add("auth-status--error");
        return;
      }

      currentUser = data;
      authStatus.textContent = "You’re in. Syncing your protection…";
      authStatus.classList.add("auth-status--success");
      updatePlanPill();

      setTimeout(() => {
        closeAuthModal();
        if (authForm) authForm.reset();
      }, 600);
    })
    .catch(() => {
      authStatus.textContent = "Google sign-in failed. Try again.";
      authStatus.classList.add("auth-status--error");
    });
}

function initGoogleButton() {
  if (!googleBtnContainer) return;
  const clientId = googleBtnContainer.dataset.googleClientId;
  if (!clientId || clientId === "YOUR_GOOGLE_CLIENT_ID_HERE") return;
  if (!window.google || !window.google.accounts || !window.google.accounts.id)
    return;

  window.google.accounts.id.initialize({
    client_id: clientId,
    callback: handleGoogleCredential,
  });
  window.google.accounts.id.renderButton(googleBtnContainer, {
    theme: "outline",
    size: "large",
    shape: "pill",
    width: 320,
  });
}

window.addEventListener("load", () => {
  // small delay so GSI script loads
  setTimeout(() => {
    try {
      initGoogleButton();
    } catch (e) {
      // ignore
    }
  }, 400);
});

// ===================== SESSION LOAD ======================

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

// ===================== EMAIL AUTH SUBMIT ======================

if (authForm && authEmail && authPassword && authStatus) {
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
  if (!contentInput || !analyzeBtn || !statusEl) return;

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

    if (!verdictBadge || !explanationEl || !reasonsList) return;

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

    if (resultSection) resultSection.hidden = false;
    statusEl.textContent = "";
    loadSession();
  } catch (err) {
    statusEl.textContent = "Network error. Try again in a moment.";
  } finally {
    analyzeBtn.disabled = false;
  }
}

// ===================== QR SCAN ======================

async function analyzeQR(file) {
  if (!statusEl || !analyzeBtn) return;

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

    if (!verdictBadge || !explanationEl || !reasonsList) return;

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

    if (resultSection) resultSection.hidden = false;
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

// ===================== ACCOUNT DROPDOWN ACTIONS ======================

if (accountManageBtn) {
  accountManageBtn.addEventListener("click", (e) => {
    e.preventDefault();
    closeAccountMenu();
    if (!currentUser) {
      openAuthModal();
      return;
    }
    if (window.location.pathname === "/account") {
      window.scrollTo({ top: 0, behavior: "smooth" });
    } else {
      window.location.href = "/account";
    }
  });
}

if (accountLogoutBtn) {
  accountLogoutBtn.addEventListener("click", async (e) => {
    e.preventDefault();
    closeAccountMenu();
    try {
      await fetch(`${API_BASE_URL}/logout`, {
        method: "POST",
        credentials: "include",
      });
    } catch (e) {
      // ignore
    } finally {
      currentUser = null;
      updatePlanPill();
      if (window.location.pathname === "/account") {
        window.location.href = "/";
      }
    }
  });
}

// ===================== ACCOUNT PAGE ACTIONS ======================

if (passwordForm && passwordStatus) {
  passwordForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!currentUser) {
      openAuthModal();
      return;
    }

    if (
      !passwordCurrent.value ||
      !passwordNew.value ||
      !passwordConfirm.value
    ) {
      passwordStatus.textContent = "Fill in all fields.";
      passwordStatus.classList.add("account-status-danger");
      return;
    }

    if (passwordNew.value !== passwordConfirm.value) {
      passwordStatus.textContent = "New passwords do not match.";
      passwordStatus.classList.add("account-status-danger");
      return;
    }

    passwordStatus.textContent = "Updating password…";
    passwordStatus.classList.remove("account-status-danger");
    passwordStatus.classList.remove("account-status-success");

    try {
      const res = await fetch(`${API_BASE_URL}/account/change-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          current_password: passwordCurrent.value,
          new_password: passwordNew.value,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        passwordStatus.textContent = data.error || "Password change failed.";
        passwordStatus.classList.add("account-status-danger");
        return;
      }

      passwordStatus.textContent = "Password updated.";
      passwordStatus.classList.add("account-status-success");
      passwordCurrent.value = "";
      passwordNew.value = "";
      passwordConfirm.value = "";
    } catch (err) {
      passwordStatus.textContent = "Network error. Try again.";
      passwordStatus.classList.add("account-status-danger");
    }
  });
}

if (historyBtn && historyStatus) {
  historyBtn.addEventListener("click", async (e) => {
    e.preventDefault();
    if (!currentUser) {
      openAuthModal();
      return;
    }

    historyStatus.textContent = "Preparing download…";
    try {
      const res = await fetch(
        `${API_BASE_URL}/scan-history?limit=500`,
        {
          method: "GET",
          credentials: "include",
        }
      );
      const data = await res.json();
      if (!res.ok) {
        historyStatus.textContent =
          data.error || "Could not download history.";
        return;
      }

      const blob = new Blob([JSON.stringify(data, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "scamdetector-history.json";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      historyStatus.textContent = "History downloaded.";
    } catch (err) {
      historyStatus.textContent = "Network error. Try again.";
    }
  });
}

if (deleteForm && deleteStatus) {
  deleteForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!currentUser) {
      openAuthModal();
      return;
    }

    const confirmText = (deleteConfirmText.value || "").trim();
    if (!confirmText) {
      deleteStatus.textContent = "Type DELETE to confirm.";
      deleteStatus.classList.add("account-status-danger");
      return;
    }

    if (confirmText !== "DELETE") {
      deleteStatus.textContent = "Confirmation must be exactly DELETE.";
      deleteStatus.classList.add("account-status-danger");
      return;
    }

    deleteStatus.textContent = "Deleting account…";
    deleteStatus.classList.remove("account-status-danger");
    deleteStatus.classList.remove("account-status-success");

    try {
      const res = await fetch(`${API_BASE_URL}/account/delete`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          password: deletePassword.value || null,
          confirm: confirmText,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        deleteStatus.textContent = data.error || "Could not delete account.";
        deleteStatus.classList.add("account-status-danger");
        return;
      }

      deleteStatus.textContent = "Account deleted. Redirecting…";
      deleteStatus.classList.add("account-status-success");
      currentUser = null;
      setTimeout(() => {
        window.location.href = "/";
      }, 900);
    } catch (err) {
      deleteStatus.textContent = "Network error. Try again.";
      deleteStatus.classList.add("account-status-danger");
    }
  });
}

if (accountBillingBtn) {
  accountBillingBtn.addEventListener("click", (e) => {
    e.preventDefault();
    if (!currentUser) {
      openAuthModal();
      return;
    }
    window.location.href = "/pricing";
  });
}