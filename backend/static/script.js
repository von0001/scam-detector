// SCRIPT.JS - FULL VERSION WITH AUTH + ACCOUNT + QR + GOOGLE

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
const reasonBlock = document.querySelector(".reason-block");

const ocrBtn = document.getElementById("ocr-btn");
const fileInput = document.getElementById("ocr-file");
const dropZone = document.getElementById("drop-zone");

// Feedback replay + context capture
const FEEDBACK_TRACE_KEY = "feedback_trace";
const FEEDBACK_CONTEXT_KEY = "feedback_context";
const TASK_TIMEOUT_MS = 25000;
const flowStart = sessionStorage.getItem("feedback_flow_start") || Date.now().toString();
sessionStorage.setItem("feedback_flow_start", flowStart);

function recordFeedbackEvent(entry) {
  try {
    const trace = JSON.parse(sessionStorage.getItem(FEEDBACK_TRACE_KEY) || "[]");
    trace.push({ ts: Date.now(), ...entry });
    sessionStorage.setItem(FEEDBACK_TRACE_KEY, JSON.stringify(trace.slice(-12)));
  } catch (err) {
    // ignore capture failures
  }
}

function storeFeedbackContext(ctx) {
  try {
    const base = JSON.parse(sessionStorage.getItem(FEEDBACK_CONTEXT_KEY) || "{}");
    sessionStorage.setItem(
      FEEDBACK_CONTEXT_KEY,
      JSON.stringify({ ...base, ...ctx, captured_at: Date.now() })
    );
  } catch (err) {
    // ignore capture failures
  }
}

function getCookie(name) {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(";").shift();
  return null;
}

// Auto-attach CSRF token on same-site authenticated calls
const _origFetch = window.fetch.bind(window);
window.fetch = (url, options = {}) => {
  const opts = { ...options };
  opts.headers = new Headers(opts.headers || {});
  if (opts.credentials === "include") {
    const csrf = getCookie("sd_csrf");
    if (csrf) {
      opts.headers.set("x-csrf-token", csrf);
    }
  }
  return _origFetch(url, opts);
};

function getCookie(name) {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(";").shift();
  return null;
}

function csrfHeaders(additional = {}) {
  const token = getCookie("sd_csrf");
  if (token) {
    additional["x-csrf-token"] = token;
  }
  return additional;
}

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
const overviewBilling = document.getElementById("overview-billing");
const overviewSubscription = document.getElementById("overview-subscription");

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
const accountDowngradeBtn = document.getElementById("account-downgrade-btn");
const accountContent = document.getElementById("account-content");
const accountLocked = document.getElementById("account-locked");
const accountLockedBtn = document.getElementById("account-locked-btn");
const usagePlanLabel = document.getElementById("usage-plan-label");
const usageMeterFill = document.getElementById("usage-meter-fill");
const usageMeterLabel = document.getElementById("usage-meter-label");
const usageLastScan = document.getElementById("usage-last-scan");
const usageActivity = document.getElementById("usage-activity");
const usageFlagged = document.getElementById("usage-flagged");
const flaggedList = document.getElementById("flagged-list");
const flaggedEmpty = document.getElementById("flagged-empty");
const recentScansBody = document.getElementById("recent-scans-body");
const recentEmpty = document.getElementById("recent-empty");
const dashboardStatus = document.getElementById("dashboard-status");
const refreshDashboardBtn = document.getElementById("refresh-dashboard-btn");
const subscribeMonthlyBtn = document.getElementById("subscribe-monthly-btn");
const subscribeYearlyBtn = document.getElementById("subscribe-yearly-btn");
const subscribeStatus = document.getElementById("subscribe-status");

let authMode = "login";
let currentUser = null;
let accountDashboardLoaded = false;
let pendingSubscriptionCycle = null;

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

function formatTimestamp(timestamp, emptyLabel = "No scans yet") {
  if (!timestamp) return emptyLabel;
  const date = new Date(timestamp * 1000);
  return date.toLocaleString(undefined, {
    hour12: true,
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

function sanitizeSnippet(text) {
  if (!text) return "";
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function verdictPillClass(verdict) {
  const label = (verdict || "unknown").toLowerCase();
  if (label === "safe") return "account-pill account-pill-safe";
  if (label === "suspicious") return "account-pill account-pill-suspicious";
  if (label === "dangerous") return "account-pill account-pill-dangerous";
  return "account-pill";
}

function showAccountLocked() {
  if (accountContent) accountContent.hidden = true;
  if (accountLocked) accountLocked.hidden = false;
}

function hideAccountLocked() {
  if (accountContent) accountContent.hidden = false;
  if (accountLocked) accountLocked.hidden = true;
}

// ===================== AUTH UI ======================

function setAuthMode(mode) {
  authMode = mode;
  if (!authTabLogin || !authTabSignup || !authHint) return;

  if (mode === "login") {
    authTabLogin.classList.add("auth-tab-active");
    authTabSignup.classList.remove("auth-tab-active");
    authHint.innerHTML =
      'No account yet... Switch to <strong>Create Account</strong> to start with the free tier.';
  } else {
    authTabSignup.classList.add("auth-tab-active");
    authTabLogin.classList.remove("auth-tab-active");
    authHint.textContent =
      "We'll start you on the free plan. Upgrade to Premium anytime for unlimited scans.";
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
  if (!overviewEmail || !overviewPlan || !overviewUsage || !overviewAuth) return;

  if (!currentUser) {
    overviewEmail.textContent = "-";
    overviewPlan.textContent = "-";
    overviewUsage.textContent = "-";
    overviewAuth.textContent = "-";
    if (typeof overviewBilling !== "undefined" && overviewBilling) {
      overviewBilling.textContent = "-";
    }
    if (typeof overviewSubscription !== "undefined" && overviewSubscription) {
      overviewSubscription.textContent = "-";
    }
    if (window.location.pathname === "/account") {
      showAccountLocked();
    }
    if (passwordForm && passwordCurrent && passwordNew && passwordConfirm) {
      passwordCurrent.disabled = true;
      passwordNew.disabled = true;
      passwordConfirm.disabled = true;
      const btn = passwordForm.querySelector("button[type='submit']");
      if (btn) btn.disabled = true;
    }
    if (accountDowngradeBtn) {
      accountDowngradeBtn.disabled = true;
    }
    return;
  }

  hideAccountLocked();

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

  if (overviewBilling) {
    const cycle = u.billing_cycle || "none";
    overviewBilling.textContent =
      u.plan === "premium" ? `${cycle} billing` : "None";
  }

  if (overviewSubscription) {
    const status = u.subscription_status || "inactive";
    overviewSubscription.textContent =
      u.plan === "premium" ? `Active (${status})` : "Inactive";
  }

  if (accountDowngradeBtn) {
    accountDowngradeBtn.disabled = u.plan !== "premium";
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
      "Guest mode - Limited free scans. <span>Sign in</span> to sync and unlock more.";
    if (accountBtn) accountBtn.textContent = "Sign In";
    if (accountMenuEmail) accountMenuEmail.textContent = "";
    accountDashboardLoaded = false;
    updateAccountOverview();
    return;
  }

  const user = currentUser.user;
  const plan = user.plan;
  const used = user.daily_scan_count ?? 0;
  const limit = user.daily_limit ?? 0;

  if (plan === "premium") {
    planPill.innerHTML =
      "<span>Premium</span> - Unlimited scans & deep analysis.";
  } else {
    const remaining = Math.max((limit || 0) - used, 0);
    planPill.innerHTML = `<span>Free plan</span> - ${remaining} of ${limit} daily scans left.`;
  }

  if (accountBtn) accountBtn.textContent = user.email;
  if (accountMenuEmail) accountMenuEmail.textContent = user.email;

  updateAccountOverview();

  if (subscribeStatus) {
    if (plan === "premium") {
      const cycle = (user.billing_cycle || "monthly").toLowerCase();
      subscribeStatus.textContent = `You're on Premium (${cycle}).`;
      subscribeStatus.classList.remove("account-status-danger");
    } else {
      subscribeStatus.textContent = "Upgrade to unlock unlimited scans and deep analysis.";
      subscribeStatus.classList.remove("account-status-danger");
    }
  }
}

function renderAccountDashboard(snapshot) {
  if (!snapshot || !currentUser) return;

  const usage = snapshot.usage || {};
  const stats = snapshot.stats || {};
  const flagged = snapshot.flagged_logs || [];
  const recent = snapshot.recent_logs || [];

  if (usagePlanLabel) {
    usagePlanLabel.textContent =
      usage.plan === "premium" ? "Premium" : "Free plan";
  }

  if (usageMeterFill && usageMeterLabel) {
    if (usage.plan === "premium" || usage.daily_remaining === -1) {
      usageMeterFill.style.width = "100%";
      usageMeterFill.style.background =
        "linear-gradient(90deg, #34d399, #10b981)";
      usageMeterLabel.textContent = "Unlimited scans today";
    } else {
      const limit = usage.daily_limit || 0;
      const used = usage.daily_used || 0;
      const pct = limit > 0 ? Math.min(100, Math.round((used / limit) * 100)) : 0;
      usageMeterFill.style.width = `${pct}%`;
      usageMeterFill.style.background =
        "linear-gradient(90deg, #22d3ee, #3b82f6)";
      usageMeterLabel.textContent = `${used} of ${limit} scans used today`;
    }
  }

  if (usageLastScan) {
    usageLastScan.textContent = stats.last_scan_ts
      ? formatTimestamp(stats.last_scan_ts)
      : "No scans yet";
  }
  if (usageActivity) {
    usageActivity.textContent = stats.activity_24h ?? 0;
  }
  if (usageFlagged) {
    usageFlagged.textContent = flagged.length;
  }

  renderFlaggedAlerts(flagged);
  renderRecentLogs(recent);

  if (currentUser.user) {
    if (typeof usage.daily_used === "number") {
      currentUser.user.daily_scan_count = usage.daily_used;
    }
    if (typeof usage.daily_limit === "number") {
      currentUser.user.daily_limit = usage.daily_limit;
    }
    updateAccountOverview();
  }
}

function renderFlaggedAlerts(items) {
  if (!flaggedList || !flaggedEmpty) return;
  flaggedList.innerHTML = "";
  if (!items.length) {
    flaggedEmpty.hidden = false;
    return;
  }
  flaggedEmpty.hidden = true;

  items.forEach((item) => {
    const verdict = (item.verdict || "UNKNOWN").toUpperCase();
    const li = document.createElement("li");
    li.innerHTML = `
      <h3>
        <span>${item.category || "unknown"}</span>
        <span class="${verdictPillClass(verdict)}">${verdict}</span>
      </h3>
      <p class="account-flagged-snippet">
        ${sanitizeSnippet(item.snippet || "No snippet provided.")}
      </p>
      <p class="account-meta">
        <span class="account-label">Score</span>
        <span class="account-value">${item.score ?? 0}</span>
      </p>
    `;
    flaggedList.appendChild(li);
  });
}

function renderRecentLogs(logs) {
  if (!recentScansBody || !recentEmpty) return;
  recentScansBody.innerHTML = "";
  if (!logs.length) {
    recentEmpty.hidden = false;
    return;
  }
  recentEmpty.hidden = true;

  logs.forEach((log) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${formatTimestamp(log.timestamp, "Unknown")}</td>
      <td>${log.category || "unknown"}</td>
      <td><span class="${verdictPillClass(log.verdict)}">${(log.verdict || "UNKNOWN").toUpperCase()}</span></td>
      <td>${log.score ?? 0}</td>
      <td>${sanitizeSnippet(log.snippet || "")}</td>
    `;
    recentScansBody.appendChild(row);
  });
}

async function loadAccountDashboard(force = false) {
  if (window.location.pathname !== "/account") return;
  if (!currentUser) {
    accountDashboardLoaded = false;
    showAccountLocked();
    if (dashboardStatus) {
      dashboardStatus.textContent = "";
      dashboardStatus.classList.remove("account-status-danger");
    }
    return;
  }

  if (accountDashboardLoaded && !force) return;

  if (dashboardStatus) {
    dashboardStatus.textContent = "Syncing your account data...";
    dashboardStatus.classList.remove("account-status-danger");
  }

  try {
    const res = await fetch(`${API_BASE_URL}/account/dashboard?limit=50`, {
      method: "GET",
      credentials: "include",
      headers: csrfHeaders(),
    });
    const data = await res.json();
    if (!res.ok) {
      if (dashboardStatus) {
        dashboardStatus.textContent = data.error || "Could not load dashboard.";
        dashboardStatus.classList.add("account-status-danger");
      }
      if (res.status === 401) {
        currentUser = null;
        accountDashboardLoaded = false;
        updatePlanPill();
      }
      return;
    }

    accountDashboardLoaded = true;
    hideAccountLocked();
    renderAccountDashboard(data);
    if (dashboardStatus) {
      dashboardStatus.textContent = "";
      dashboardStatus.classList.remove("account-status-danger");
    }
  } catch (err) {
    if (dashboardStatus) {
      dashboardStatus.textContent = "Network error loading dashboard.";
      dashboardStatus.classList.add("account-status-danger");
    }
  }
}

// ===================== SUBSCRIPTION HELPERS ======================

function setSubscribeStatus(message, isError = false) {
  if (!subscribeStatus) return;
  subscribeStatus.textContent = message;
  if (isError) {
    subscribeStatus.classList.add("account-status-danger");
  } else {
    subscribeStatus.classList.remove("account-status-danger");
  }
}

function ensureLoggedInForSubscription(cycle) {
  if (currentUser) return true;
  pendingSubscriptionCycle = cycle;
  openAuthModal();
  setSubscribeStatus("Sign in to upgrade via secure checkout.", true);
  return false;
}

async function triggerSubscription(billingCycle = "monthly") {
  if (!ensureLoggedInForSubscription(billingCycle)) return;
  if (currentUser && currentUser.user && currentUser.user.plan === "premium") {
    setSubscribeStatus("You're already on Premium.", false);
    pendingSubscriptionCycle = null;
    return;
  }
  setSubscribeStatus("Redirecting you to secure checkout...", false);
  try {
    const res = await fetch(`${API_BASE_URL}/create-checkout-session`, {
      method: "POST",
      headers: csrfHeaders({ "Content-Type": "application/json" }),
      credentials: "include",
      body: JSON.stringify({
        plan: billingCycle === "yearly" ? "yearly" : "monthly",
      }),
    });
    const data = await res.json();
    if (!res.ok) {
      setSubscribeStatus(
        data.error || "Could not start Stripe checkout.",
        true
      );
      return;
    }
    pendingSubscriptionCycle = null;
    if (data.url) {
      window.location.href = data.url;
      return;
    }
    setSubscribeStatus("Could not start Stripe checkout.", true);
  } catch (err) {
    setSubscribeStatus("Network error. Try again.", true);
  }
}

async function triggerDowngrade() {
  if (!currentUser) {
    openAuthModal();
    return;
  }
  if (dashboardStatus) {
    dashboardStatus.textContent = "";
    dashboardStatus.classList.remove("account-status-danger");
  }
  try {
    const res = await fetch(`${API_BASE_URL}/account/downgrade`, {
      method: "POST",
      credentials: "include",
      headers: csrfHeaders(),
    });
    const data = await res.json();
    if (!res.ok) {
      if (dashboardStatus) {
        dashboardStatus.textContent = data.error || "Could not downgrade.";
        dashboardStatus.classList.add("account-status-danger");
      }
      return;
    }
    currentUser = data;
    pendingSubscriptionCycle = null;
    updatePlanPill();
    if (window.location.pathname === "/account") {
      loadAccountDashboard(true);
    }
    setSubscribeStatus("Downgraded to Free. Limits reset.", false);
  } catch (err) {
    if (dashboardStatus) {
      dashboardStatus.textContent = "Network error. Try again.";
      dashboardStatus.classList.add("account-status-danger");
    }
  }
}

// ===================== GOOGLE SIGN-IN ======================

function handleGoogleCredential(response) {
  if (!response || !response.credential) return;
  if (!authStatus) return;

  authStatus.textContent = "Signing you in with Google...";
  authStatus.classList.remove("auth-status--error", "auth-status--success");

  fetch(`${API_BASE_URL}/auth/google`, {
    method: "POST",
    headers: csrfHeaders({ "Content-Type": "application/json" }),
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
      authStatus.textContent = "You're in. Syncing your protection...";
      authStatus.classList.add("auth-status--success");
      updatePlanPill();
      if (pendingSubscriptionCycle) {
        triggerSubscription(pendingSubscriptionCycle);
        return;
      }

      if (window.location.pathname === "/account") {
        loadAccountDashboard(true);
      }
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
      headers: csrfHeaders(),
    });

    if (!res.ok) {
      currentUser = null;
      accountDashboardLoaded = false;
      updatePlanPill();
      return;
    }

    const data = await res.json();
    if (!data.authenticated) {
      currentUser = null;
      accountDashboardLoaded = false;
    } else {
      currentUser = data;
    }
    updatePlanPill();
    if (window.location.pathname === "/account") {
      loadAccountDashboard(true);
    }
  } catch (err) {
    currentUser = null;
    accountDashboardLoaded = false;
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
        ? "Signing you in..."
        : "Creating your account...";
    authStatus.classList.remove("auth-status--error", "auth-status--success");

    const endpoint = authMode === "login" ? "/login" : "/signup";

    try {
      const res = await fetch(`${API_BASE_URL}${endpoint}`, {
        method: "POST",
        headers: csrfHeaders({ "Content-Type": "application/json" }),
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
      authStatus.textContent = "You're in. Syncing your protection...";
      authStatus.classList.add("auth-status--success");
      updatePlanPill();
      if (pendingSubscriptionCycle) {
        triggerSubscription(pendingSubscriptionCycle);
        return;
      }

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

  statusEl.textContent = "Running scam + manipulation checks...";
  analyzeBtn.disabled = true;
  recordFeedbackEvent({ event: "analyze_start", mode, snippet: content.slice(0, 160) });

  try {
    const response = await fetch(`${API_BASE_URL}/analyze`, {
      method: "POST",
      headers: csrfHeaders({ "Content-Type": "application/json" }),
      credentials: "include",
      body: JSON.stringify({ content, mode }),
    });

    let result = {};
    try {
      result = await response.json();
    } catch (parseErr) {
      // Fallback to text to surface useful errors
      const text = await response.text().catch(() => "");
      result = { error: text || "Parse error" };
    }
    if (!response.ok) {
      statusEl.textContent =
        result.error || "Something went wrong during analysis.";
      return;
    }

    if (result.task_id) {
      statusEl.textContent = "Waiting for verdict...";
      await pollTask(result.task_id, content, mode);
      return;
    }

    renderAnalyzeResult(result, content, mode);
  } catch (err) {
    statusEl.textContent = "Network error. Try again in a moment.";
    recordFeedbackEvent({ event: "analyze_error", mode });
  } finally {
    analyzeBtn.disabled = false;
  }
}

function extractJsonBlock(text) {
  if (typeof text !== "string") return null;
  const match = text.match(/\{[\s\S]*\}/);
  return match ? match[0] : null;
}

function tryParseJsonish(text) {
  if (typeof text !== "string") return null;
  const trimmed = text.trim();
  if (!trimmed) return null;

  const candidates = [trimmed];
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    candidates.push(trimmed.slice(1, -1));
  }

  const block = extractJsonBlock(trimmed);
  if (block && block !== trimmed) {
    candidates.push(block);
  }

  for (const candidate of candidates) {
    try {
      return JSON.parse(candidate);
    } catch (err) {
      try {
        return JSON.parse(candidate.replace(/'/g, '"'));
      } catch (_) {
        // keep trying fallbacks
      }
    }
  }
  return null;
}

function pullFieldsFromJsonish(text) {
  if (typeof text !== "string") return {};
  const block = extractJsonBlock(text) || text;
  const parsed = tryParseJsonish(block);

  if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
    const cleaned = {};
    if (parsed.explanation) cleaned.explanation = String(parsed.explanation);
    if (Array.isArray(parsed.reasons)) {
      cleaned.reasons = parsed.reasons.map((r) => String(r));
    }
    if (parsed.verdict) cleaned.verdict = String(parsed.verdict);
    if (parsed.score !== undefined) cleaned.score = parsed.score;
    return cleaned;
  }

  const cleaned = {};
  const verdictMatch = block.match(/"verdict"\s*:\s*"?(SAFE|SUSPICIOUS|DANGEROUS)"?/i);
  if (verdictMatch) cleaned.verdict = verdictMatch[1].toUpperCase();

  const scoreMatch = block.match(/"score"\s*:\s*([0-9]+(?:\.[0-9]+)?)/i);
  if (scoreMatch) cleaned.score = parseFloat(scoreMatch[1]);

  const explanationMatch = block.match(
    /"explanation"\s*:\s*("?)([\s\S]*?)(?=(,\s*"[A-Za-z0-9_ ]+"\s*:|\s*\}))/i
  );
  if (explanationMatch && explanationMatch[2]) {
    cleaned.explanation = explanationMatch[2].replace(/^[\"'\s]+|[\"'\s]+$/g, "").trim();
  }

  const reasonsMatch = block.match(/"reasons"\s*:\s*\[([\s\S]*?)\]/i);
  if (reasonsMatch && reasonsMatch[1]) {
    const items = reasonsMatch[1]
      .split(/,(?=(?:[^"]*"[^"]*")*[^"]*$)/)
      .map((r) => r.replace(/^[\s"']+|[\s"']+$/g, "").trim())
      .filter(Boolean);
    if (items.length) cleaned.reasons = items;
  }

  return cleaned;
}

function stripReasonsFromText(text) {
  if (typeof text !== "string") return "";
  let cleaned = text;

  cleaned = cleaned.replace(/,\s*"reasons"\s*:\s*\[[\s\S]*?\](?=\s*[}\]])/gi, "");
  cleaned = cleaned.replace(/"reasons"\s*:\s*\[[\s\S]*?\]/gi, "");
  cleaned = cleaned.replace(/,\s*'reasons'\s*:\s*\[[\s\S]*?\](?=\s*[}\]])/gi, "");
  cleaned = cleaned.replace(/'reasons'\s*:\s*\[[\s\S]*?\]/gi, "");

  cleaned = cleaned.replace(/\s{2,}/g, " ").trim();
  cleaned = cleaned.replace(/^["']|["']$/g, "");
  return cleaned.trim();
}

function shouldShowReasons(verdict) {
  const v = (verdict || "").toUpperCase();
  return v === "SUSPICIOUS" || v === "DANGEROUS";
}

function countRiskHits(text, patterns) {
  const t = (text || "").toLowerCase();
  let hits = 0;
  for (const pattern of patterns) {
    if (pattern.test(t)) hits += 1;
  }
  return hits;
}

function isLowRiskReason(reason) {
  const r = (reason || "").toLowerCase();
  const lowSignals = [
    "no major red flags",
    "no clear scam signs",
    "offline fallback",
    "no strong warning signs",
    "no clear warning signs",
    "no scam patterns detected",
    "the message is empty",
    "no clear risk detected",
    "looks risky based on its words and tone",
  ];
  return lowSignals.some((p) => r.includes(p));
}

function deriveDisplayVerdict(verdict, explanation, reasons, mode) {
  const v = (verdict || "").toUpperCase();
  if (v && v !== "SAFE") return v;
  if (mode !== "auto" && mode !== "text") return v || "SAFE";

  const reasonText = Array.isArray(reasons) ? reasons.join(" ") : "";
  const blob = `${explanation || ""} ${reasonText}`.toLowerCase();
  if (!blob.trim()) return v || "SAFE";

  const riskSignals = [
    /scam/,
    /fraud/,
    /steal/,
    /coerc/,
    /threat/,
    /pressure/,
    /urgent/,
    /pay/,
    /money/,
    /gift\s*card/,
    /bank/,
    /password/,
    /account\s+closure/,
    /verify/,
    /reset/,
    /fee/,
    /crypto/,
    /bitcoin/,
    /wire/,
    /transfer/,
    /link/,
    /requesting\s+payment/,
    /asking\s+for\s+money/,
  ];

  const hits = countRiskHits(blob, riskSignals);
  const reasonHits = Array.isArray(reasons)
    ? reasons.reduce((acc, r) => {
        if (isLowRiskReason(r)) return acc;
        return acc + countRiskHits(String(r), riskSignals);
      }, 0)
    : 0;
  const strongReasons =
    Array.isArray(reasons) && reasons.filter((r) => !isLowRiskReason(r)).length >= 2;

  if (hits >= 3 || reasonHits >= 3) {
    return "DANGEROUS";
  }
  if (hits >= 1 || reasonHits >= 1 || strongReasons) {
    return "SUSPICIOUS";
  }

  return v || "SAFE";
}

function normalizeResultForDisplay(rawResult) {
  const base = typeof rawResult === "string" ? { explanation: rawResult } : { ...(rawResult || {}) };
  const explanationText = typeof base.explanation === "string" ? base.explanation.trim() : "";
  const extracted = explanationText ? pullFieldsFromJsonish(explanationText) : {};

  const normalized = { ...base };

  if (extracted.explanation) {
    normalized.explanation = extracted.explanation;
  } else {
    normalized.explanation = explanationText.replace(/^["']|["']$/g, "");
  }

  if ((!normalized.reasons || !normalized.reasons.length) && extracted.reasons) {
    normalized.reasons = extracted.reasons;
  }

  if (!normalized.verdict && extracted.verdict) {
    normalized.verdict = extracted.verdict;
  }

  if (
    (normalized.score === undefined || normalized.score === null) &&
    extracted.score !== undefined
  ) {
    normalized.score = extracted.score;
  }

  if (!Array.isArray(normalized.reasons)) {
    normalized.reasons = normalized.reasons ? [String(normalized.reasons).trim()] : [];
  } else {
    normalized.reasons = normalized.reasons.map((r) => String(r).trim()).filter(Boolean);
  }

  normalized.explanation =
    typeof normalized.explanation === "string" ? stripReasonsFromText(normalized.explanation) : "";

  return normalized;
}

function renderAnalyzeResult(result, content, mode) {
  if (!verdictBadge || !explanationEl || !reasonsList) return;

  const cleanResult = normalizeResultForDisplay(result);
  const displayVerdict = deriveDisplayVerdict(
    cleanResult.verdict,
    cleanResult.explanation,
    cleanResult.reasons,
    mode
  );

  let label = "";
  if (displayVerdict === "SAFE") {
    label = "SAFE - No major scam patterns detected";
  } else if (displayVerdict === "SUSPICIOUS") {
    label = "SUSPICIOUS - Some warning signs present";
  } else if (displayVerdict === "DANGEROUS") {
    label = "DANGEROUS - Strong scam or manipulation risk";
  } else {
    label = displayVerdict || "Result";
  }

  verdictBadge.textContent = label;
  setVerdictStyle(displayVerdict);
  explanationEl.textContent = cleanResult.explanation || "";

  if (reasonBlock) {
    reasonBlock.hidden = !shouldShowReasons(displayVerdict);
  }

  reasonsList.innerHTML = "";
  (cleanResult.reasons || []).forEach((r) => {
    const li = document.createElement("li");
    li.textContent = r;
    reasonsList.appendChild(li);
  });

  if (detailsPre) {
    detailsPre.hidden = true;
  }

  storeFeedbackContext({
    mode,
    risk_score: cleanResult.score,
    verdict: displayVerdict,
    risk_label: label,
    page: window.location.pathname,
    snippet: content.slice(0, 180),
  });
  recordFeedbackEvent({
    event: "analyze_result",
    mode,
    verdict: displayVerdict,
    score: cleanResult.score,
  });

  if (resultSection) resultSection.hidden = false;
  statusEl.textContent = "";
  loadSession();
}

async function pollTask(taskId, content, mode) {
  const start = Date.now();
  while (Date.now() - start < TASK_TIMEOUT_MS) {
    try {
      const resp = await fetch(`${API_BASE_URL}/tasks/status/${taskId}`, {
        method: "GET",
        credentials: "include",
        headers: csrfHeaders(),
      });
      let data = {};
      try {
        data = await resp.json();
      } catch {
        const text = await resp.text().catch(() => "");
        data = { error: text || "Parse error" };
      }
      if (data?.status === "finished") {
        renderAnalyzeResult(data.result || {}, content, mode);
        return;
      }
      if (data?.status === "failed") {
        statusEl.textContent = data.error || "Scan failed. Please try again.";
        analyzeBtn.disabled = false;
        return;
      }
    } catch (err) {
      // continue polling
    }
    await new Promise((res) => setTimeout(res, 1200));
  }
  statusEl.textContent = "Scan timed out. Try again.";
  analyzeBtn.disabled = false;
}

// ===================== QR SCAN ======================

async function analyzeQR(file) {
  if (!statusEl || !analyzeBtn) return;

  statusEl.textContent = "Scanning QR code and checking destination safety...";
  analyzeBtn.disabled = true;
  recordFeedbackEvent({ event: "qr_start", mode: "qr" });

  const form = new FormData();
  form.append("image", file);

  try {
    const response = await fetch(`${API_BASE_URL}/qr`, {
      method: "POST",
      body: form,
      credentials: "include",
      headers: csrfHeaders(),
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
      label = `SAFE QR - Score ${score}`;
    } else if (verdict === "SUSPICIOUS") {
      label = `SUSPICIOUS QR - Score ${score}`;
    } else if (verdict === "DANGEROUS") {
      label = `DANGEROUS QR - Score ${score}`;
    } else {
      label = `QR Score ${score}`;
    }

    verdictBadge.textContent = label;
    setVerdictStyle(verdict);
    if (reasonBlock) {
      reasonBlock.hidden = !shouldShowReasons(verdict);
    }

    explanationEl.textContent = `Detected ${result.count} QR code(s).`;

    reasonsList.innerHTML = "";
    (result.items || []).forEach((item) => {
      const li = document.createElement("li");
      li.textContent = `${item.qr_type.toUpperCase()} -> ${item.verdict}: ${item.content}`;
      reasonsList.appendChild(li);
    });

    if (detailsPre) {
      detailsPre.hidden = true;
    }

    storeFeedbackContext({
      mode: "qr",
      risk_score: score,
      verdict,
      risk_label: label,
      page: window.location.pathname,
    });
    recordFeedbackEvent({
      event: "qr_result",
      mode: "qr",
      verdict,
      score,
    });

    if (resultSection) resultSection.hidden = false;
    statusEl.textContent = "";
    loadSession();
  } catch (err) {
    statusEl.textContent = "Failed to analyze QR. Try a clearer image.";
    recordFeedbackEvent({ event: "qr_error", mode: "qr" });
  } finally {
    analyzeBtn.disabled = false;
  }
}

// ===================== OCR ======================

function ocrLuminance(r, g, b) {
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function clampChannel(v) {
  return Math.max(0, Math.min(255, Math.round(v)));
}

function detectTextBoundingBox(ctx, width, height) {
  const data = ctx.getImageData(0, 0, width, height).data;
  const borderSample = [];
  const marginX = Math.max(2, Math.floor(width * 0.08));
  const marginY = Math.max(2, Math.floor(height * 0.08));

  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      if (x < marginX || x >= width - marginX || y < marginY || y >= height - marginY) {
        const idx = (y * width + x) * 4;
        borderSample.push(ocrLuminance(data[idx], data[idx + 1], data[idx + 2]));
      }
    }
  }

  const bg = borderSample.length
    ? borderSample.reduce((acc, v) => acc + v, 0) / borderSample.length
    : 128;
  const sampleStep = Math.max(1, Math.floor(Math.max(width, height) / 320));
  const threshold = Math.max(14, Math.min(48, Math.abs(bg - 128) * 0.35 + 20));

  let minX = width;
  let minY = height;
  let maxX = 0;
  let maxY = 0;
  let hits = 0;

  for (let y = 0; y < height; y += sampleStep) {
    for (let x = 0; x < width; x += sampleStep) {
      const idx = (y * width + x) * 4;
      const diff = Math.abs(ocrLuminance(data[idx], data[idx + 1], data[idx + 2]) - bg);
      if (diff > threshold) {
        hits += 1;
        if (x < minX) minX = x;
        if (y < minY) minY = y;
        if (x > maxX) maxX = x;
        if (y > maxY) maxY = y;
      }
    }
  }

  if (!hits) return null;
  const padding = Math.max(6, Math.round(Math.min(width, height) * 0.05));
  const boxX = Math.max(0, minX - padding);
  const boxY = Math.max(0, minY - padding);
  return {
    x: boxX,
    y: boxY,
    w: Math.min(width - boxX, maxX - minX + padding * 2),
    h: Math.min(height - boxY, maxY - minY + padding * 2),
  };
}

function computeAverageLuminance(data, step, width, height) {
  let sum = 0;
  let count = 0;
  const stride = Math.max(1, step);
  for (let y = 0; y < height; y += stride) {
    for (let x = 0; x < width; x += stride) {
      const idx = (y * width + x) * 4;
      sum += ocrLuminance(data[idx], data[idx + 1], data[idx + 2]);
      count += 1;
    }
  }
  return count ? sum / count : 0;
}

function enhanceContrastAndSharpen(ctx, width, height) {
  const imageData = ctx.getImageData(0, 0, width, height);
  const data = imageData.data;
  const contrastBoost = 24;
  const factor = (259 * (contrastBoost + 255)) / (255 * (259 - contrastBoost));

  for (let i = 0; i < data.length; i += 4) {
    data[i] = clampChannel(factor * (data[i] - 128) + 128);
    data[i + 1] = clampChannel(factor * (data[i + 1] - 128) + 128);
    data[i + 2] = clampChannel(factor * (data[i + 2] - 128) + 128);
  }

  const sharpened = new Uint8ClampedArray(data.length);
  const src = new Uint8ClampedArray(data);
  const kernel = [0, -1, 0, -1, 5, -1, 0, -1, 0];

  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const base = (y * width + x) * 4;
      for (let c = 0; c < 3; c++) {
        let acc = 0;
        let k = 0;
        for (let ky = -1; ky <= 1; ky++) {
          const py = Math.min(height - 1, Math.max(0, y + ky));
          for (let kx = -1; kx <= 1; kx++) {
            const px = Math.min(width - 1, Math.max(0, x + kx));
            const idx = (py * width + px) * 4 + c;
            acc += src[idx] * kernel[k];
            k += 1;
          }
        }
        sharpened[base + c] = clampChannel(acc);
      }
      sharpened[base + 3] = src[base + 3];
    }
  }

  imageData.data.set(sharpened);
  ctx.putImageData(imageData, 0, 0);
}

function expandBox(box, factor, width, height) {
  const cx = box.x + box.w / 2;
  const cy = box.y + box.h / 2;
  const newW = Math.min(width, box.w * factor);
  const newH = Math.min(height, box.h * factor);
  const x = Math.max(0, Math.min(width - newW, cx - newW / 2));
  const y = Math.max(0, Math.min(height - newH, cy - newH / 2));
  return { x: Math.round(x), y: Math.round(y), w: Math.round(newW), h: Math.round(newH) };
}

function normalizeDimensions(width, height, minSide = 900, maxSide = 1800) {
  const maxInputSide = Math.max(width, height);
  const upscale = maxInputSide < minSide ? minSide / maxInputSide : 1;
  const downscale = maxInputSide > maxSide ? maxSide / maxInputSide : 1;
  const scale = Math.min(2.2, Math.max(upscale, downscale));
  return {
    targetWidth: Math.max(1, Math.round(width * scale)),
    targetHeight: Math.max(1, Math.round(height * scale)),
    scale,
  };
}

async function loadImageElement(file) {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => {
      URL.revokeObjectURL(url);
      resolve(img);
    };
    img.onerror = (err) => {
      URL.revokeObjectURL(url);
      reject(err);
    };
    img.src = url;
  });
}

async function preprocessImageForOcr(file) {
  try {
    const img = await loadImageElement(file);
    const detectLimit = 900;
    const detectScale = Math.min(1, detectLimit / Math.max(img.width, img.height));
    const detectW = Math.max(1, Math.round(img.width * detectScale));
    const detectH = Math.max(1, Math.round(img.height * detectScale));
    const detectCanvas = document.createElement("canvas");
    detectCanvas.width = detectW;
    detectCanvas.height = detectH;
    const detectCtx = detectCanvas.getContext("2d", { willReadFrequently: true });
    detectCtx.drawImage(img, 0, 0, detectW, detectH);

    const rawBox = detectTextBoundingBox(detectCtx, detectW, detectH);
    const cropBox = rawBox
      ? expandBox(
          {
            x: rawBox.x / detectScale,
            y: rawBox.y / detectScale,
            w: rawBox.w / detectScale,
            h: rawBox.h / detectScale,
          },
          1.05,
          img.width,
          img.height
        )
      : { x: 0, y: 0, w: img.width, h: img.height };

    const { targetWidth, targetHeight, scale } = normalizeDimensions(
      cropBox.w,
      cropBox.h
    );

    const canvas = document.createElement("canvas");
    canvas.width = targetWidth;
    canvas.height = targetHeight;
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    ctx.imageSmoothingEnabled = scale < 1.1;
    ctx.imageSmoothingQuality = "high";
    ctx.drawImage(
      img,
      cropBox.x,
      cropBox.y,
      cropBox.w,
      cropBox.h,
      0,
      0,
      targetWidth,
      targetHeight
    );

    const preEnhanceData = ctx.getImageData(0, 0, targetWidth, targetHeight);
    const preEnhanceAvg = computeAverageLuminance(
      preEnhanceData.data,
      Math.max(2, Math.round(Math.max(targetWidth, targetHeight) / 512)),
      targetWidth,
      targetHeight
    );

    enhanceContrastAndSharpen(ctx, targetWidth, targetHeight);

    const postData = ctx.getImageData(0, 0, targetWidth, targetHeight);
    const postAvg = computeAverageLuminance(
      postData.data,
      Math.max(2, Math.round(Math.max(targetWidth, targetHeight) / 512)),
      targetWidth,
      targetHeight
    );

    const blob = await new Promise((resolve, reject) => {
      canvas.toBlob(
        (b) => {
          if (b) resolve(b);
          else reject(new Error("Failed to encode preprocessed image."));
        },
        "image/png",
        1
      );
    });

    return {
      blob,
      meta: {
        cropApplied: !!rawBox,
        scale,
        source: { width: img.width, height: img.height },
        cropBox,
        preEnhanceAvg,
        postEnhanceAvg,
      },
    };
  } catch (err) {
    console.warn("[ocr] Preprocessing failed, falling back to raw file", err);
    return {
      blob: file,
      meta: {
        fallback: true,
        reason: err?.message || "preprocess_error",
      },
    };
  }
}

let ocrWorkerPromise = null;

async function getOrInitOcrWorker() {
  if (!ocrWorkerPromise) {
    ocrWorkerPromise = (async () => {
      const worker = await Tesseract.createWorker();
      await worker.load();
      await worker.loadLanguage("eng");
      await worker.initialize("eng");
      return worker;
    })();
  }
  return ocrWorkerPromise;
}

function resetOcrWorker() {
  if (ocrWorkerPromise) {
    ocrWorkerPromise
      .then((worker) => {
        try {
          worker.terminate();
        } catch (e) {
          // ignore termination errors
        }
      })
      .catch(() => {});
  }
  ocrWorkerPromise = null;
}

async function runBaseGrayscalePass(worker, file, source, meta) {
  const img = await loadImageElement(file);
  const canvas = document.createElement("canvas");
  canvas.width = img.width;
  canvas.height = img.height;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  ctx.drawImage(img, 0, 0, canvas.width, canvas.height);

  const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const data = imageData.data;
  for (let i = 0; i < data.length; i += 4) {
    const lum = ocrLuminance(data[i], data[i + 1], data[i + 2]);
    data[i] = data[i + 1] = data[i + 2] = clampChannel(lum);
  }
  ctx.putImageData(imageData, 0, 0);

  const avg = computeAverageLuminance(
    data,
    Math.max(2, Math.round(Math.max(canvas.width, canvas.height) / 512)),
    canvas.width,
    canvas.height
  );
  if (avg < 2) {
    console.warn("[ocr] Fallback grayscale canvas appears blank", {
      avg,
      width: canvas.width,
      height: canvas.height,
    });
    recordFeedbackEvent({
      event: "ocr_canvas_blank",
      source,
      meta: { ...meta, fallbackAvg: avg },
    });
    return { text: "", pixelOk: false, canvasAvg: avg };
  }

  const blob = await new Promise((resolve, reject) => {
    canvas.toBlob(
      (b) => {
        if (b) resolve(b);
        else reject(new Error("Failed to encode grayscale image."));
      },
      "image/png",
      1
    );
  });

  const { data: ocrData } = await worker.recognize(blob);
  const text = (ocrData?.text || "").trim();
  return { text, pixelOk: true, canvasAvg: avg };
}

async function runOCR(imageFile, { source = "upload" } = {}) {
  if (!statusEl || !contentInput) return;
  if (!imageFile) {
    statusEl.textContent = "No image detected. Try again.";
    return;
  }

  statusEl.textContent = "Reading text from your screenshot...";
  try {
    const fileMeta = {
      type: imageFile.type || "unknown",
      size: imageFile.size || 0,
    };
    const { blob, meta } = await preprocessImageForOcr(imageFile);
    const dims = meta?.source || {};
    console.info("[ocr] Image received", {
      source,
      file: fileMeta,
      dimensions: dims,
      mimeDetected: blob?.type || "unknown",
    });
    recordFeedbackEvent({
      event: "ocr_image_received",
      source,
      file: fileMeta,
      meta: { ...meta, dimensions: dims },
      mimeDetected: blob?.type || "unknown",
    });

    const pixelAvg = meta?.postEnhanceAvg ?? meta?.preEnhanceAvg ?? 0;
    const pixelOk = pixelAvg >= 2;
    if (!pixelOk) {
      console.warn("[ocr] Canvas appears blank after preprocessing, skipping OCR", {
        source,
        meta,
        pixelAvg,
      });
      statusEl.textContent = "Processing image...";
      return;
    }

    const worker = await getOrInitOcrWorker();
    const { data } = await worker.recognize(blob);
    let extractedText = (data?.text || "").trim();
    const enhancedEmpty = !extractedText;
    let finalPixelOk = pixelOk;

    if (enhancedEmpty) {
      recordFeedbackEvent({
        event: "ocr_enhanced_empty",
        source,
        meta: { ...meta, pixelAvg, mimeDetected: blob?.type || "unknown" },
      });
      console.warn("[ocr] Enhanced OCR empty, retrying with base grayscale", meta);
      const baseResult = await runBaseGrayscalePass(worker, imageFile, source, meta);
      extractedText = baseResult.text;
      finalPixelOk = baseResult.pixelOk;
      if (!extractedText && baseResult.pixelOk) {
        recordFeedbackEvent({
          event: "ocr_base_empty",
          source,
          meta: { ...meta, baseAvg: baseResult.canvasAvg },
        });
        console.warn("[ocr] Base grayscale pass returned empty text", {
          source,
          baseAvg: baseResult.canvasAvg,
        });
      }
    }

    if (!extractedText) {
      if (!finalPixelOk) {
        statusEl.textContent = "Processing image...";
        recordFeedbackEvent({
          event: "ocr_canvas_invalid",
          source,
          meta: { ...meta, pixelAvg },
        });
        console.warn("[ocr] Canvas invalid, suppressing user-facing error", { meta, pixelAvg });
        return;
      }
      statusEl.textContent = "OCR failed. Try a clearer or closer screenshot.";
      console.warn("[ocr] No text detected; likely OCR engine miss", meta);
      recordFeedbackEvent({
        event: "ocr_no_text",
        source,
        meta: { ...meta, pixelAvg },
        reason: "engine_empty_valid_pixels",
      });
      return;
    }

    recordFeedbackEvent({
      event: "ocr_success",
      source,
      chars: extractedText.length,
      crop: meta?.cropApplied ? "cropped" : "full",
      pixelAvg,
    });

    contentInput.value = extractedText;
    statusEl.textContent = "Text extracted - running safety check...";
    analyzeContent();
  } catch (err) {
    console.error(`[ocr] OCR failed for ${source}: ${err?.message || err}`, err);
    recordFeedbackEvent({ event: "ocr_error", source, reason: err?.message || "unknown" });
    resetOcrWorker();
    statusEl.textContent = "Unable to process the image right now. Please try again.";
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
    else runOCR(file, { source: "upload" });
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
    const dt = e.dataTransfer;
    const file =
      (dt && dt.files && dt.files[0]) ||
      (dt && dt.items && Array.from(dt.items).find((item) => item.kind === "file")?.getAsFile());
    if (!file) {
      if (statusEl) statusEl.textContent = "No image detected. Drop a screenshot or QR image.";
      return;
    }
    const mode = getSelectedMode();
    if (mode === "qr") analyzeQR(file);
    else runOCR(file, { source: "drop" });
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
        headers: csrfHeaders(),
      });
    } catch (e) {
      // ignore
    } finally {
      currentUser = null;
      accountDashboardLoaded = false;
      updatePlanPill();
      if (window.location.pathname === "/account") {
        showAccountLocked();
        window.location.href = "/";
      }
    }
  });
}

if (accountLockedBtn) {
  accountLockedBtn.addEventListener("click", (e) => {
    e.preventDefault();
    openAuthModal();
  });
}

if (subscribeMonthlyBtn) {
  subscribeMonthlyBtn.addEventListener("click", (e) => {
    e.preventDefault();
    triggerSubscription("monthly");
  });
}

if (subscribeYearlyBtn) {
  subscribeYearlyBtn.addEventListener("click", (e) => {
    e.preventDefault();
    triggerSubscription("yearly");
  });
}

// ===================== ACCOUNT PAGE ACTIONS ======================

if (refreshDashboardBtn) {
  refreshDashboardBtn.addEventListener("click", (e) => {
    e.preventDefault();
    loadAccountDashboard(true);
  });
}

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

    passwordStatus.textContent = "Updating password...";
    passwordStatus.classList.remove("account-status-danger");
    passwordStatus.classList.remove("account-status-success");

    try {
      const res = await fetch(`${API_BASE_URL}/account/change-password`, {
        method: "POST",
        headers: csrfHeaders({ "Content-Type": "application/json" }),
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

    historyStatus.textContent = "Preparing download...";
    try {
      const res = await fetch(
        `${API_BASE_URL}/scan-history?limit=500`,
        {
          method: "GET",
          credentials: "include",
          headers: csrfHeaders(),
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

    deleteStatus.textContent = "Deleting account...";
    deleteStatus.classList.remove("account-status-danger");
    deleteStatus.classList.remove("account-status-success");

    try {
      const res = await fetch(`${API_BASE_URL}/account/delete`, {
        method: "POST",
        headers: csrfHeaders({ "Content-Type": "application/json" }),
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

      deleteStatus.textContent = "Account deleted. Redirecting...";
      deleteStatus.classList.add("account-status-success");
      currentUser = null;
      accountDashboardLoaded = false;
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
    window.location.href = "/subscribe";
  });
}

if (accountDowngradeBtn) {
  accountDowngradeBtn.addEventListener("click", (e) => {
    e.preventDefault();
    triggerDowngrade();
  });
}
