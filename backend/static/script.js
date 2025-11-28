// SCRIPT.JS - FULL VERSION WITH AUTH + ACCOUNT + QR + GOOGLE

const API_BASE_URL = "https://scamdetectorapp.com";
const CHROME_EXTENSION_URL =
  "https://chromewebstore.google.com/detail/scamdetector-%E2%80%93-link-text/aoiglmnmpicbkkplnlfifipdgmajeich";

// Core scan elements (home page)
const contentInput = document.getElementById("content-input");
const notesInput = document.getElementById("notes-input");
const analyzeBtn = document.getElementById("analyze-btn");
const statusEl = document.getElementById("status");
const modeSelect = document.getElementById("mode-select");
const advancedToggle = document.getElementById("advanced-toggle");
const advancedPanel = document.getElementById("advanced-panel");
const sampleChips = document.querySelectorAll(".sample-chip");

const resultSection = document.getElementById("result-section");
const verdictBadge = document.getElementById("verdict-badge");
const explanationEl = document.getElementById("explanation");
const reasonsList = document.getElementById("reasons-list");
const detailsPre = document.getElementById("details-json");
const reasonBlock = document.querySelector(".reason-block");
const confidenceWrap = document.getElementById("confidence-wrap");
const confidenceFill = document.getElementById("confidence-fill");
const confidenceLabel = document.getElementById("confidence-label");

const ocrBtn = document.getElementById("ocr-btn");
const fileInput = document.getElementById("ocr-file");
const dropZone = document.getElementById("drop-zone");
const deepAnalyzeBtn = document.getElementById("deep-analyze-btn");
const realtimeBtn = document.getElementById("realtime-btn");

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
const historyList = document.getElementById("history-list");
const historyLoadMoreBtn = document.getElementById("history-load-more");
const historyVerdictFilter = document.getElementById("history-filter-verdict");
const historyTypeFilter = document.getElementById("history-filter-type");
const historyPageStatus = document.getElementById("history-page-status");
const historyExportBtn = document.getElementById("history-export-btn");

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
const recentFeed = document.getElementById("recent-feed");
const dashboardStatus = document.getElementById("dashboard-status");
const refreshDashboardBtn = document.getElementById("refresh-dashboard-btn");
const subscribeMonthlyBtn = document.getElementById("subscribe-monthly-btn");
const subscribeYearlyBtn = document.getElementById("subscribe-yearly-btn");
const subscribeStatus = document.getElementById("subscribe-status");
const startFreeBtn = document.getElementById("start-free-btn");
const tierBanner = document.getElementById("tier-banner");
const tierBannerText = document.getElementById("tier-banner-text");
const tierBadge = document.getElementById("tier-badge");
const tierUpgradeBtn = document.getElementById("tier-upgrade-btn");

let authMode = "login";
let currentUser = null;
let accountDashboardLoaded = false;
let pendingSubscriptionCycle = null;
const FEATURE_GATES = {
  auto: { tier: "premium", label: "Auto-detect" },
  ai_detector: { tier: "premium", label: "Actor profiling" },
  psychology: { tier: "premium", label: "Manipulation analysis" },
  qr_scan: { tier: "premium", label: "QR and screenshot scanning" },
  screenshot_scan: { tier: "premium", label: "Screenshot / image scanning" },
  deep_ai_analysis: { tier: "premium", label: "Detailed analysis" },
  deep_ai: { tier: "premium", label: "Detailed analysis" },
  full_history: { tier: "premium", label: "Full history export" },
  real_time: { tier: "premium", label: "Real-time scanning" },
};

let upgradeModal = null;
let upgradeFeatureLabel = null;
let upgradeModalMessage = null;
let upgradeNowBtn = null;
let viewPlansBtn = null;

// Ensure auth modal stays closed on load
if (authModal) authModal.hidden = true;
let currentConfidencePct = 0;
const normalizeConfidence = (raw) => {
  const num = Number(raw);
  if (!Number.isFinite(num)) return null;
  const pct = num <= 1 ? num * 100 : num;
  return Math.min(100, Math.max(0, Math.round(pct)));
};
const normalizeConfidence = (raw) => {
  const num = Number(raw);
  if (!Number.isFinite(num)) return null;
  const pct = num <= 1 ? num * 100 : num;
  return Math.min(100, Math.max(0, Math.round(pct)));
};

// MODE
function getSelectedMode() {
  if (modeSelect) return modeSelect.value;
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

function applyHeaderIdentity() {
  if (!accountBtn) return;
  if (currentUser && currentUser.user && currentUser.user.email) {
    accountBtn.textContent = currentUser.user.email;
    if (accountMenuEmail) accountMenuEmail.textContent = currentUser.user.email;
  } else {
    accountBtn.textContent = "Sign In";
    if (accountMenuEmail) accountMenuEmail.textContent = "";
  }
}

function currentPlan() {
  if (currentUser && currentUser.user && currentUser.user.plan === "premium") return "premium";
  if (currentUser && currentUser.user) return "free";
  return "guest";
}

function isFeatureUnlocked(featureKey) {
  const gate = FEATURE_GATES[featureKey];
  if (!gate) return true;
  const plan = currentPlan();
  return gate.tier === "free" || plan === "premium";
}

function ensureUpgradeModal() {
  if (upgradeModal) return;
  const wrapper = document.createElement("div");
  wrapper.id = "upgrade-modal";
  wrapper.className = "upgrade-modal";
  wrapper.hidden = true;
  wrapper.innerHTML = `
    <div class="upgrade-modal-backdrop"></div>
    <div class="upgrade-card">
      <button class="upgrade-close" aria-label="Close upgrade modal">x</button>
      <div class="upgrade-eyebrow">Premium access required</div>
      <h3>This capability is part of the Premium tier.</h3>
      <p data-upgrade-message>This tool requires Premium analysis access. Upgrade to enable detailed reviews and unlimited scans.</p>
      <p class="upgrade-feature">Feature: <span data-upgrade-feature>Premium analysis</span></p>
      <div class="upgrade-actions">
        <button id="upgrade-now-btn" class="primary-btn">Upgrade Now</button>
        <button id="view-plans-btn" class="ghost-btn">View Plans</button>
      </div>
    </div>
  `;
  document.body.appendChild(wrapper);
  upgradeModal = wrapper;
  upgradeFeatureLabel = wrapper.querySelector("[data-upgrade-feature]");
  upgradeModalMessage = wrapper.querySelector("[data-upgrade-message]");
  upgradeNowBtn = wrapper.querySelector("#upgrade-now-btn");
  viewPlansBtn = wrapper.querySelector("#view-plans-btn");
  const closeBtn = wrapper.querySelector(".upgrade-close");
  const backdrop = wrapper.querySelector(".upgrade-modal-backdrop");
  const close = () => closeUpgradeModal();
  closeBtn.addEventListener("click", close);
  backdrop.addEventListener("click", close);
  upgradeNowBtn.addEventListener("click", () => {
    closeUpgradeModal();
    if (!currentUser) {
      pendingSubscriptionCycle = "monthly";
      openAuthModal();
      return;
    }
    triggerSubscription("monthly");
  });
  viewPlansBtn.addEventListener("click", () => {
    closeUpgradeModal();
    window.location.href = "/subscribe";
  });
}

function openUpgradeModal(featureKey = "premium", message) {
  ensureUpgradeModal();
  const gate = FEATURE_GATES[featureKey] || {};
  if (upgradeFeatureLabel) {
    upgradeFeatureLabel.textContent = gate.label || "Premium feature";
  }
  if (upgradeModalMessage) {
    upgradeModalMessage.textContent =
      message ||
      "This tool requires Premium analysis access. Upgrade to unlock detailed reviews and higher limits.";
  }
  upgradeModal.hidden = false;
}

function closeUpgradeModal() {
  if (upgradeModal) upgradeModal.hidden = true;
}

function requireFeatureAccess(featureKey, message) {
  if (isFeatureUnlocked(featureKey)) return true;
  if (!currentUser) openAuthModal();
  if (statusEl && message) {
    statusEl.textContent = message;
  }
  openUpgradeModal(featureKey, message);
  return false;
}

function applyFeatureLocks() {
  const plan = currentPlan();
  const premiumNodes = document.querySelectorAll('[data-tier="premium"]');
  premiumNodes.forEach((node) => {
    if (node.classList.contains("locked-row")) {
      node.classList.toggle("unlocked-premium", plan === "premium");
    }
    node.classList.remove("locked-pill");
    node.classList.remove("locked-action");
    const input = node.tagName === "INPUT" ? node : node.querySelector("input");
    if (input) input.disabled = false;
  });

  if (deepAnalyzeBtn) {
    deepAnalyzeBtn.classList.remove("locked-action");
    deepAnalyzeBtn.disabled = false;
  }
  if (ocrBtn) {
    ocrBtn.classList.remove("locked-action");
  }
  if (dropZone) {
    dropZone.classList.remove("locked-action");
  }
  if (historyBtn && historyStatus) {
    historyBtn.disabled = false;
    historyBtn.classList.remove("locked-action");
    if (plan === "premium") {
      historyStatus.textContent = "";
    }
  }
}

function handleUpgradeResponse(result, featureKey) {
  const message = (result && result.error) || "This feature requires Premium access.";
  if (statusEl) statusEl.textContent = message;
  openUpgradeModal(featureKey || (result && result.feature) || "premium", message);
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
      'No account yet? Switch to <strong>Create Account</strong> to start on the free tier.';
  } else {
    authTabSignup.classList.add("auth-tab-active");
    authTabLogin.classList.remove("auth-tab-active");
    authHint.textContent =
      "Free plan enabled at signup. Upgrade to Premium anytime for higher limits and detailed analysis.";
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
    applyFeatureLocks();
    applyHeaderIdentity();
    return;
  }

  if (!currentUser) {
    planPill.textContent = "Plan: Guest - Sign in to sync scans and manage limits.";
    if (accountBtn) accountBtn.textContent = "Sign In";
    if (accountMenuEmail) accountMenuEmail.textContent = "";
    if (tierBannerText) tierBannerText.textContent = "Sign in to see your tier and usage.";
    if (tierBadge) tierBadge.hidden = true;
    if (tierUpgradeBtn) tierUpgradeBtn.hidden = false;
    accountDashboardLoaded = false;
    updateAccountOverview();
    applyFeatureLocks();
    return;
  }

  const user = currentUser.user;
  const plan = user.plan;
  const used = user.daily_scan_count ?? 0;
  const limit = user.daily_limit ?? 0;

  if (plan === "premium") {
    planPill.textContent = "Plan: Premium - Priority queue enabled.";
    if (tierBannerText) tierBannerText.textContent = "Plan: Premium";
    if (tierBadge) tierBadge.hidden = false;
    if (tierUpgradeBtn) tierUpgradeBtn.hidden = true;
    if (analyzeBtn) analyzeBtn.disabled = false;
    if (deepAnalyzeBtn) deepAnalyzeBtn.disabled = false;
  } else {
    const remaining = Math.max((limit || 0) - used, 0);
    const remainingLabel = limit > 0 ? remaining : "unlimited";
    const totalLabel = limit > 0 ? limit : "unlimited";
    planPill.textContent = `Plan: Free - ${remainingLabel} of ${totalLabel} scans available today.`;
    if (tierBannerText) tierBannerText.textContent = "Plan: Free";
    if (tierBadge) tierBadge.hidden = true;
    if (tierUpgradeBtn) tierUpgradeBtn.hidden = false;
  }

  if (accountBtn) accountBtn.textContent = user.email;
  if (accountMenuEmail) accountMenuEmail.textContent = user.email;

  updateAccountOverview();
  applyFeatureLocks();

  if (subscribeStatus) {
    if (plan === "premium") {
      const cycle = (user.billing_cycle || "monthly").toLowerCase();
      subscribeStatus.textContent = `You're on Premium (${cycle}).`;
      subscribeStatus.classList.remove("account-status-danger");
    } else {
      subscribeStatus.textContent = "Upgrade to unlock unlimited scans and detailed analysis.";
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
  renderRecentLogs(recent.slice(0, 5));
  if (dashboardStatus) {
    if (usage.history_limited) {
      dashboardStatus.textContent = "Free plan shows the most recent scans. Upgrade for full history and logs.";
      dashboardStatus.classList.remove("account-status-danger");
    } else if (!dashboardStatus.textContent) {
      dashboardStatus.textContent = "";
    }
  }

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
  if (!recentFeed || !recentEmpty) return;
  recentFeed.innerHTML = "";
  if (!logs.length) {
    recentEmpty.hidden = false;
    return;
  }
  recentEmpty.hidden = true;

  logs.slice(0, 5).forEach((log) => {
    const verdictClass = verdictPillClass(log.verdict);
    const li = document.createElement("li");
    li.className = "recent-feed-item";
    li.innerHTML = `
      <div class="recent-feed-top">
        <span class="${verdictClass}">${(log.verdict || "UNKNOWN").toUpperCase()}</span>
        <span class="recent-feed-type">${(log.category || log.mode || "unknown").toUpperCase()}</span>
        <span class="recent-feed-time">${formatTimestamp(log.timestamp, "Unknown")}</span>
      </div>
      <div class="recent-feed-snippet">${sanitizeSnippet(log.snippet || "No snippet provided.")}</div>
    `;
    recentFeed.appendChild(li);
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
    const res = await fetch(`${API_BASE_URL}/account/dashboard?limit=5`, {
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
      authStatus.textContent = "Signed in. Syncing your account...";
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
    applyHeaderIdentity();
    if (window.location.pathname === "/account") {
      loadAccountDashboard(true);
    }
  } catch (err) {
    currentUser = null;
    accountDashboardLoaded = false;
    updatePlanPill();
    applyHeaderIdentity();
  }
}

applyFeatureLocks();
loadSession();

if (window.location.pathname === "/history") {
  loadHistoryPage(true);
}

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
      authStatus.textContent = "Signed in. Syncing your account...";
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
  const contextNote = notesInput ? notesInput.value.trim() : "";
  let lockedByLimit = false;
  const modeFeatureMap = {
    auto: "auto",
    chat: "ai_detector",
    manipulation: "psychology",
    qr: "qr_scan",
  };
  const modeFeatureKey = modeFeatureMap[mode];
  if (modeFeatureKey && !requireFeatureAccess(modeFeatureKey, "This mode requires Premium access.")) {
    return;
  }

  if (!content && mode !== "qr") {
    statusEl.textContent = "Paste a message, link, or conversation first.";
    return;
  }

  const plan = currentPlan();
  statusEl.textContent =
    plan === "premium"
      ? "Analyzing with priority processing"
      : plan === "guest"
        ? "Processing (guest access - URL/Text only)"
        : "Processing (standard queue)";
  analyzeBtn.disabled = true;
  recordFeedbackEvent({
    event: "analyze_start",
    mode,
    snippet: content.slice(0, 160),
    context: contextNote.slice(0, 120),
  });

  try {
    const payload = { content, mode };
    if (contextNote) payload.context = contextNote;
    const response = await fetch(`${API_BASE_URL}/analyze`, {
      method: "POST",
      headers: csrfHeaders({ "Content-Type": "application/json" }),
      credentials: "include",
      body: JSON.stringify(payload),
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
      if (result.upgrade_prompt) {
        if (result.lock_reason === "daily_limit") {
          lockedByLimit = true;
          analyzeBtn.disabled = true;
          if (deepAnalyzeBtn) deepAnalyzeBtn.disabled = true;
        }
        handleUpgradeResponse(result, result.feature || mode);
        return;
      }
      statusEl.textContent = result.error || "Something went wrong during analysis.";
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
    analyzeBtn.disabled = lockedByLimit ? true : false;
    if (deepAnalyzeBtn) {
      deepAnalyzeBtn.disabled = lockedByLimit ? true : false;
    }
  }
}

async function runDeepAnalysis() {
  if (!requireFeatureAccess("deep_ai", "Detailed analysis is available on Premium.")) return;
  if (!contentInput || !statusEl) return;

  const content = contentInput.value.trim();
  if (!content) {
    statusEl.textContent = "Paste a message or link to run a detailed review.";
    return;
  }

  statusEl.textContent = "Running detailed analysis...";
  analyzeBtn.disabled = true;
  if (deepAnalyzeBtn) deepAnalyzeBtn.disabled = true;

  try {
    const response = await fetch(`${API_BASE_URL}/scan/deep-ai`, {
      method: "POST",
      headers: csrfHeaders({ "Content-Type": "application/json" }),
      credentials: "include",
      body: JSON.stringify({
        content,
        include_psychology: true,
        include_actor: true,
      }),
    });
    let result = {};
    try {
      result = await response.json();
    } catch {
      result = { error: "Unable to parse deep analysis response." };
    }
    if (!response.ok) {
      if (result.upgrade_prompt) {
        handleUpgradeResponse(result, result.feature || "deep_ai");
        return;
      }
      statusEl.textContent = result.error || "Deep analysis failed.";
      return;
    }

    renderAnalyzeResult(result, content, "deep_ai");
    statusEl.textContent = "Detailed verdict delivered.";
  } catch (err) {
    statusEl.textContent = "Network error. Try again in a moment.";
  } finally {
    analyzeBtn.disabled = false;
    if (deepAnalyzeBtn) deepAnalyzeBtn.disabled = false;
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
  if (
    !cleanResult.confidence_score &&
    result?.details &&
    typeof result.details.confidence_score === "number"
  ) {
    cleanResult.confidence_score = result.details.confidence_score;
  }
  if (
    !cleanResult.confidence_score &&
    result?.details &&
    typeof result.details.confidence === "number"
  ) {
    cleanResult.confidence_score = result.details.confidence;
  }
  if (
    !cleanResult.confidence_score &&
    result?.details &&
    typeof result.details.confidence_score === "number"
  ) {
    cleanResult.confidence_score = result.details.confidence_score;
  }
  if (
    !cleanResult.confidence_score &&
    result?.details &&
    typeof result.details.confidence === "number"
  ) {
    cleanResult.confidence_score = result.details.confidence;
  }

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

  const normalizedConfidence = normalizeConfidence(cleanResult.confidence_score);
  if (confidenceWrap && confidenceFill && confidenceLabel) {
    if (normalizedConfidence !== null) {
      confidenceWrap.hidden = false;
      const start = currentConfidencePct;
      const target = normalizedConfidence;
      const startTs = performance.now();
      const duration = 220;
      const step = (ts) => {
        const progress = Math.min(1, (ts - startTs) / duration);
        const val = Math.round(start + (target - start) * progress);
        confidenceFill.style.width = `${val}%`;
        confidenceLabel.textContent = `${val}% confidence`;
        if (progress < 1) requestAnimationFrame(step);
        else currentConfidencePct = target;
      };
      requestAnimationFrame(step);
    } else {
      confidenceWrap.hidden = true;
      confidenceFill.style.width = "0%";
      confidenceLabel.textContent = "";
      currentConfidencePct = 0;
    }
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

  if (resultSection) {
    resultSection.hidden = false;
    resultSection.scrollIntoView({ behavior: "smooth", block: "start" });
  }
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
      if (result.upgrade_prompt) {
        handleUpgradeResponse(result, result.feature || "qr_scan");
        return;
      }
      statusEl.textContent = result.error || "Failed to analyze QR. Try a clearer image.";
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
  // Convert to grayscale and compute mean/std for adaptive normalization
  let sum = 0;
  let sumSq = 0;
  const total = width * height;
  for (let i = 0; i < data.length; i += 4) {
    const lum = ocrLuminance(data[i], data[i + 1], data[i + 2]);
    sum += lum;
    sumSq += lum * lum;
    data[i] = data[i + 1] = data[i + 2] = clampChannel(lum);
  }
  const mean = total ? sum / total : 128;
  const variance = total ? sumSq / total - mean * mean : 0;
  const std = Math.max(8, Math.sqrt(Math.max(variance, 0)));
  const targetStd = 55; // mild adaptive contrast
  const norm = targetStd / std;

  // Adaptive contrast normalization
  for (let i = 0; i < data.length; i += 4) {
    const v = data[i];
    const adjusted = clampChannel((v - mean) * norm + 128);
    data[i] = data[i + 1] = data[i + 2] = adjusted;
  }

  // Mild unsharp mask (radius ~1, amount 0.6)
  const blurred = new Uint8ClampedArray(data.length);
  const kernel = [1, 2, 1, 2, 4, 2, 1, 2, 1];
  const kernelWeight = 16;
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      let acc = 0;
      let k = 0;
      for (let ky = -1; ky <= 1; ky++) {
        const py = Math.min(height - 1, Math.max(0, y + ky));
        for (let kx = -1; kx <= 1; kx++) {
          const px = Math.min(width - 1, Math.max(0, x + kx));
          const idx = (py * width + px) * 4;
          acc += data[idx] * kernel[k];
          k += 1;
        }
      }
      const base = (y * width + x) * 4;
      const blurVal = acc / kernelWeight;
      const sharpened = clampChannel(data[base] + 0.6 * (data[base] - blurVal));
      blurred[base] = blurred[base + 1] = blurred[base + 2] = sharpened;
      blurred[base + 3] = data[base + 3];
    }
  }

  imageData.data.set(blurred);
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
  let scale = Math.min(2.2, Math.max(upscale, downscale));
  if (width < 800) {
    scale = Math.max(scale, 2);
  }
  if (width < 600) {
    scale = Math.max(scale, 2.2);
  }
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
    const inferredDpi = (img.width >= 300 && img.height >= 300) ? 72 : 72;
    const lowDpi = inferredDpi < 150 || img.width < 600;
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
    if (lowDpi) {
      // Additional pass to ensure low-resolution sources get a cleaner edge profile
      enhanceContrastAndSharpen(ctx, targetWidth, targetHeight);
    }

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
        postEnhanceAvg: postAvg,
        lowDpi,
        inferredDpi,
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

const OCR_CHAR_WHITELIST = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.,:/-$%()";

function isDistortedText(text) {
  if (!text) return true;
  const allowed = text.replace(/[A-Za-z0-9.,:\/\-$%()\s]/g, "");
  const distortionRatio = allowed.length / Math.max(text.length, 1);
  return distortionRatio > 0.25 || text.length < 5;
}

function wordEntropy(text) {
  if (!text) return 0;
  const words = text
    .split(/\s+/)
    .map((w) => w.trim().toLowerCase())
    .filter(Boolean);
  if (!words.length) return 0;
  const counts = {};
  for (const w of words) counts[w] = (counts[w] || 0) + 1;
  const total = words.length;
  let entropy = 0;
  for (const w of Object.keys(counts)) {
    const p = counts[w] / total;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

async function sendToOcrEndpoint(file, source) {
  const form = new FormData();
  form.append("image", file);
  console.log("Frontend attempting OCR upload", file?.name);
  const resp = await fetch(`/ocr`, {
    method: "POST",
    credentials: "include",
    headers: csrfHeaders(),
    body: form,
  });
  let data = {};
  try {
    data = await resp.json();
  } catch (err) {
    // ignore JSON parse issues; logging happens server-side
  }
  if (!resp.ok) {
    const msg = data?.error || "OCR upload failed";
    throw new Error(msg);
  }
  console.log("OCR response received", resp.status);
  recordFeedbackEvent({
    event: "ocr_upload_complete",
    source,
    payload: {
      filename: data?.filename,
      size: data?.size,
      width: data?.width,
      height: data?.height,
    },
  });
  return data;
}

async function handleImageForOcr(file, source = "upload") {
  if (!file) {
    if (statusEl) statusEl.textContent = "No image detected. Try again.";
    return;
  }
  if (statusEl) statusEl.textContent = "Uploading image for OCR...";

  try {
    await sendToOcrEndpoint(file, source);
  } catch (err) {
    console.error("OCR upload FAILED - network or routing issue");
  }

  if (statusEl) statusEl.textContent = "Processing image...";
  await runOCR(file, { source });
}

async function maybeRepairOcrText(rawText, { confidence = 0, distorted = false, entropy = 0, source = "upload" } = {}) {
  const aiThreshold = 90;
  const entropyThreshold = 3.8;
  const shouldUseAi = confidence < aiThreshold || distorted || entropy > entropyThreshold;
  if (!shouldUseAi || !rawText) return { text: rawText, usedAi: false };

  try {
    const resp = await fetch("/ocr/repair", {
      method: "POST",
      credentials: "include",
      headers: csrfHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({
        text: rawText,
        confidence,
        distorted,
        entropy,
        source,
      }),
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data?.error || "AI repair failed");
    const repaired = (data?.repaired_text || "").trim();
    if (repaired && repaired !== rawText) {
      recordFeedbackEvent({
        event: "ocr_ai_repair",
        source,
        used_ai: true,
        confidence_before: confidence,
        repaired_len: repaired.length,
        original_len: rawText.length,
      });
      return { text: repaired, usedAi: true, confidenceDelta: data?.confidence_delta ?? null };
    }
  } catch (err) {
    recordFeedbackEvent({
      event: "ocr_ai_repair_error",
      source,
      reason: err?.message || "unknown",
    });
  }
  return { text: rawText, usedAi: false };
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
  const confidence = typeof ocrData?.confidence === "number" ? ocrData.confidence : 0;
  return { text, pixelOk: true, canvasAvg: avg, confidence };
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

    const worker = await getOrInitOcrWorker();
    let usedBlob = blob;
    let extractedText = "";
    let enhancedEmpty = false;
    let finalPixelOk = pixelOk;

    if (!pixelOk) {
      console.warn("[ocr] Canvas appears blank after preprocessing, using raw image", {
        source,
        meta,
        pixelAvg,
      });
      recordFeedbackEvent({
        event: "ocr_canvas_blank_preprocess",
        source,
        meta: { ...meta, pixelAvg },
      });
      usedBlob = imageFile;
      finalPixelOk = true; // force attempt even if average was low
    }

    const firstPass = await worker.recognize(usedBlob, {
      tessedit_char_whitelist: OCR_CHAR_WHITELIST,
    });
    const firstConfidence =
      typeof firstPass?.data?.confidence === "number" ? firstPass.data.confidence : 0;
    recordFeedbackEvent({
      event: "ocr_confidence",
      source,
      pass: "enhanced",
      confidence: firstConfidence,
      chars: (firstPass?.data?.text || "").length,
    });
    extractedText = (firstPass?.data?.text || "").trim();
    enhancedEmpty = !extractedText && usedBlob === blob;

    let bestConfidence = firstConfidence || 0;
    const distortionDetected = isDistortedText(extractedText);
    const entropyScore = wordEntropy(extractedText);

    const needSoftPass =
      (extractedText && (bestConfidence < 85 || distortionDetected)) || enhancedEmpty;

    if (needSoftPass) {
      if (enhancedEmpty) {
        recordFeedbackEvent({
          event: "ocr_enhanced_empty",
          source,
          meta: { ...meta, pixelAvg, mimeDetected: blob?.type || "unknown" },
        });
        console.warn("[ocr] Enhanced OCR empty, retrying with base grayscale", meta);
      } else {
        recordFeedbackEvent({
          event: "ocr_low_confidence",
          source,
          confidence: firstConfidence,
          chars: extractedText.length,
        });
        console.warn("[ocr] Low-confidence OCR, retrying with softer filtering", {
          confidence: firstConfidence,
        });
      }

      const baseResult = await runBaseGrayscalePass(worker, imageFile, source, meta);
      if (typeof baseResult.confidence === "number") {
        recordFeedbackEvent({
          event: "ocr_confidence",
          source,
          pass: "soft",
          confidence: baseResult.confidence,
          chars: baseResult.text.length,
        });
      }

      if (baseResult.text && (baseResult.confidence || 0) >= firstConfidence) {
        extractedText = baseResult.text;
        finalPixelOk = baseResult.pixelOk;
        bestConfidence = Math.max(bestConfidence, baseResult.confidence || 0);
      } else if (!baseResult.text && baseResult.pixelOk) {
        recordFeedbackEvent({
          event: "ocr_base_empty",
          source,
          meta: { ...meta, baseAvg: baseResult.canvasAvg },
        });
        console.warn("[ocr] Base grayscale pass returned empty text", {
          source,
          baseAvg: baseResult.canvasAvg,
        });
      } else if (!baseResult.pixelOk) {
        // even grayscale looked blank; still attempt raw image directly as last resort
        try {
          const rawResult = await worker.recognize(imageFile, {
            tessedit_char_whitelist: OCR_CHAR_WHITELIST,
          });
          extractedText = (rawResult?.data?.text || "").trim();
          finalPixelOk = true;
          const rawConfidence =
            typeof rawResult?.data?.confidence === "number" ? rawResult.data.confidence : 0;
          recordFeedbackEvent({
            event: "ocr_confidence",
            source,
            pass: "raw",
            confidence: rawConfidence,
            chars: extractedText.length,
          });
          bestConfidence = Math.max(bestConfidence, rawConfidence);
        } catch (rawErr) {
          console.warn("[ocr] Raw direct OCR failed after blank grayscale", rawErr);
        }
      }
    }

    // AI repair (post-processing) if quality signals are low
    const aiResult = await maybeRepairOcrText(extractedText, {
      confidence: bestConfidence,
      distorted: distortionDetected,
      entropy: entropyScore,
      source,
    });
    const finalText = aiResult.text || extractedText;

    if (aiResult.usedAi) {
      recordFeedbackEvent({
        event: "ocr_ai_repair_applied",
        source,
        original_text: extractedText,
        repaired_text: finalText,
        confidence_before: bestConfidence,
        confidence_delta: aiResult.confidenceDelta ?? 0,
      });
    }

    if (!finalText) {
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
      chars: finalText.length,
      crop: meta?.cropApplied ? "cropped" : "full",
      pixelAvg,
    });

    contentInput.value = finalText;
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
  ocrBtn.addEventListener("click", () => {
    if (!requireFeatureAccess("screenshot_scan", "Premium feature - screenshot scanning requires a Premium plan.")) {
      return;
    }
    fileInput.click();
  });

  fileInput.addEventListener("change", () => {
    const file = fileInput.files[0];
    if (!file) return;
    if (!requireFeatureAccess("screenshot_scan", "Premium feature - screenshot scanning requires a Premium plan.")) {
      fileInput.value = "";
      return;
    }
    const mode = getSelectedMode();
    if (mode === "qr") analyzeQR(file);
    else handleImageForOcr(file, "upload");
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
    if (!requireFeatureAccess("screenshot_scan", "Premium feature - screenshot scanning requires a Premium plan.")) {
      return;
    }
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
    else handleImageForOcr(file, "drop");
  });
}

const modeInputs = document.querySelectorAll('input[name="mode"]');
modeInputs.forEach((input) => {
  input.addEventListener("change", (e) => {
    if (input.dataset.tier === "premium" || input.dataset.featureKey) {
      const featureKey =
        input.dataset.featureKey || input.parentElement?.dataset.featureKey || input.value;
      if (!requireFeatureAccess(featureKey, "This mode is Premium only.")) {
        e.preventDefault();
        const fallback = document.querySelector('input[name="mode"][value="auto"]');
        if (fallback) fallback.checked = true;
      }
    }
  });
});

if (advancedToggle && advancedPanel) {
  advancedToggle.addEventListener("click", () => {
    const shouldShow = advancedPanel.hidden;
    advancedPanel.hidden = !shouldShow;
    advancedToggle.textContent = shouldShow ? "Hide advanced options" : "Advanced options";
  });
}

if (modeSelect) {
  modeSelect.addEventListener("change", (e) => {
    const selected = modeSelect.value;
    const selectFeatureMap = {
      manipulation: "psychology",
      qr: "qr_scan",
      chat: "ai_detector",
      auto: "auto",
    };
    const feature = FEATURE_GATES[selectFeatureMap[selected] || selected];
    if (feature && feature.tier === "premium" && currentPlan() !== "premium") {
      const ok = requireFeatureAccess(selected, `${feature.label} is available on Premium.`);
      if (!ok) modeSelect.value = "auto";
    }
  });
}

if (sampleChips && sampleChips.length) {
  sampleChips.forEach((chip) => {
    chip.addEventListener("click", () => {
      const content = chip.dataset.content || "";
      const mode = chip.dataset.mode || "auto";
      if (contentInput) contentInput.value = content;
      if (modeSelect && modeSelect.querySelector(`option[value='${mode}']`)) {
        modeSelect.value = mode;
      }
      statusEl.textContent = "Sample loaded. Run a scan to see the report.";
    });
  });
}

const premiumModeLabels = document.querySelectorAll(".mode-pill[data-tier='premium']");
premiumModeLabels.forEach((label) => {
  label.addEventListener("click", (e) => {
    if (currentPlan() === "premium") return;
    e.preventDefault();
    const featureKey = label.dataset.featureKey || "premium";
    requireFeatureAccess(featureKey, "This mode is Premium only.");
  });
});

// Submit
if (analyzeBtn) {
  analyzeBtn.addEventListener("click", (e) => {
    e.preventDefault();
    analyzeContent();
  });
}

if (deepAnalyzeBtn) {
  deepAnalyzeBtn.addEventListener("click", (e) => {
    e.preventDefault();
    runDeepAnalysis();
  });
}

if (realtimeBtn) {
  realtimeBtn.addEventListener("click", (e) => {
    e.preventDefault();
    statusEl.textContent =
      "Real-time checks run through the Chrome extension. Opening the install page.";
    window.open(CHROME_EXTENSION_URL, "_blank", "noopener,noreferrer");
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

if (tierUpgradeBtn) {
  tierUpgradeBtn.addEventListener("click", (e) => {
    e.preventDefault();
    openUpgradeModal("deep_ai", "Upgrade to unlock unlimited scans and deep intelligence.");
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
      applyHeaderIdentity();
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

if (startFreeBtn) {
  startFreeBtn.addEventListener("click", (e) => {
    e.preventDefault();
    setAuthMode("signup");
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
    if (!requireFeatureAccess("full_history", "Full history export is a Premium feature.")) {
      historyStatus.textContent = "Upgrade to download full history.";
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
        if (data.upgrade_prompt) {
          handleUpgradeResponse(data, data.feature || "full_history");
          return;
        }
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

let historyOffset = 0;
const HISTORY_PAGE_SIZE = 25;

async function loadHistoryPage(reset = false) {
  if (!historyList) return;
  if (!currentUser) {
    openAuthModal();
    if (historyPageStatus) historyPageStatus.textContent = "Sign in to view your history.";
    return;
  }
  if (reset) {
    historyOffset = 0;
    historyList.innerHTML = "";
  }
  const verdict = historyVerdictFilter ? historyVerdictFilter.value : "all";
  const type = historyTypeFilter ? historyTypeFilter.value : "all";
  const isPremium = currentUser && currentUser.user && currentUser.user.plan === "premium";
  const pageSize = isPremium ? HISTORY_PAGE_SIZE : FREE_HISTORY_LIMIT;
  const params = new URLSearchParams({
    limit: pageSize.toString(),
    offset: historyOffset.toString(),
  });
  try {
    const res = await fetch(`${API_BASE_URL}/scan-history?${params.toString()}`, {
      method: "GET",
      credentials: "include",
      headers: csrfHeaders(),
    });
    const data = await res.json();
    if (!res.ok) {
      if (data.upgrade_prompt) {
        handleUpgradeResponse(data, data.feature || "full_history");
        return;
      }
      if (historyPageStatus) historyPageStatus.textContent = data.error || "Could not load history.";
      return;
    }

    const items = (data.items || []).filter((item) => {
      const verdictOk = verdict === "all" || (item.verdict || "").toLowerCase() === verdict;
      const typeOk = type === "all" || (item.category || item.mode || "").toLowerCase() === type;
      return verdictOk && typeOk;
    });

    if (reset) historyList.innerHTML = "";
    items.forEach((item) => {
      const li = document.createElement("li");
      li.className = "history-item";
      li.innerHTML = `
        <div class="history-item-top">
          <span class="${verdictPillClass(item.verdict)}">${(item.verdict || "UNKNOWN").toUpperCase()}</span>
          <span class="history-item-type">${(item.category || item.mode || "unknown").toUpperCase()}</span>
          <span class="history-item-time">${formatTimestamp(item.timestamp, "Unknown")}</span>
        </div>
        <div class="history-item-snippet">${sanitizeSnippet(item.snippet || "")}</div>
        <details class="history-item-details">
          <summary>View details</summary>
          <pre>${JSON.stringify(item.details || {}, null, 2)}</pre>
        </details>
      `;
      historyList.appendChild(li);
    });

    const limited = data.history_limited || data.plan !== "premium";
    const received = items.length;
    if (historyPageStatus) {
      historyPageStatus.textContent =
        limited && !data.offset ? "Free plan shows the last 5 scans." : "";
    }
    if (historyLoadMoreBtn) {
      const noMore = limited || received < pageSize;
      historyLoadMoreBtn.hidden = noMore;
    }
    historyOffset += received;
  } catch (err) {
    if (historyPageStatus) historyPageStatus.textContent = "Network error loading history.";
  }
}

if (historyLoadMoreBtn) {
  historyLoadMoreBtn.addEventListener("click", (e) => {
    e.preventDefault();
    loadHistoryPage(false);
  });
}

if (historyVerdictFilter) {
  historyVerdictFilter.addEventListener("change", () => loadHistoryPage(true));
}
if (historyTypeFilter) {
  historyTypeFilter.addEventListener("change", () => loadHistoryPage(true));
}

if (historyExportBtn) {
  historyExportBtn.addEventListener("click", async (e) => {
    e.preventDefault();
    if (!currentUser) {
      openAuthModal();
      return;
    }
    if (!requireFeatureAccess("full_history", "Full history export is a Premium feature.")) {
      return;
    }
    historyPageStatus.textContent = "Preparing export...";
    try {
      const res = await fetch(`${API_BASE_URL}/scan-history?limit=500`, {
        method: "GET",
        credentials: "include",
        headers: csrfHeaders(),
      });
      const data = await res.json();
      if (!res.ok) {
        historyPageStatus.textContent = data.error || "Could not export history.";
        return;
      }
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "scamdetector-history.json";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      historyPageStatus.textContent = "Export ready.";
    } catch (err) {
      historyPageStatus.textContent = "Network error exporting history.";
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
