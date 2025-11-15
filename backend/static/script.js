// If your backend is hosted somewhere else later, change this:
const API_BASE_URL = "";

const contentInput = document.getElementById("content-input");
const analyzeBtn = document.getElementById("analyze-btn");
const statusEl = document.getElementById("status");

const resultSection = document.getElementById("result-section");
const verdictBadge = document.getElementById("verdict-badge");
const explanationEl = document.getElementById("explanation");
const reasonsList = document.getElementById("reasons-list");

// Get selected mode (auto/url/text)
function getSelectedMode() {
  const radios = document.querySelectorAll('input[name="mode"]');
  for (const r of radios) {
    if (r.checked) return r.value;
  }
  return "auto";
}

// Update badge color
function setVerdictStyle(verdict) {
  verdictBadge.classList.remove(
    "verdict-safe",
    "verdict-suspicious",
    "verdict-dangerous"
  );

  if (verdict === "SAFE") verdictBadge.classList.add("verdict-safe");
  else if (verdict === "SUSPICIOUS") verdictBadge.classList.add("verdict-suspicious");
  else if (verdict === "DANGEROUS") verdictBadge.classList.add("verdict-dangerous");
}

// Run analysis
async function analyzeContent() {
  const content = contentInput.value.trim();
  const mode = getSelectedMode();

  if (!content) {
    statusEl.textContent = "Please enter something first.";
    return;
  }

  statusEl.textContent = "Analyzing…";
  analyzeBtn.disabled = true;

  try {
    const response = await fetch(`${API_BASE_URL}/analyze`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ content, mode }),
    });

    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      statusEl.textContent = data.detail || "Error occurred.";
      return;
    }

    const result = await response.json();

    // Update UI
    verdictBadge.textContent = `${result.verdict} (${result.category.toUpperCase()})`;
    setVerdictStyle(result.verdict);

    explanationEl.textContent = result.explanation;

    // Reasons
    reasonsList.innerHTML = "";
    result.reasons.forEach((reason) => {
      const li = document.createElement("li");
      li.textContent = reason;
      reasonsList.appendChild(li);
    });

    resultSection.hidden = false;
    statusEl.textContent = "";
  } catch (err) {
    console.error(err);
    statusEl.textContent = "Network error (is backend running?).";
  } finally {
    analyzeBtn.disabled = false;
  }
}

// Button click
analyzeBtn.addEventListener("click", (e) => {
  e.preventDefault();
  analyzeContent();
});

// Ctrl+Enter or Cmd+Enter submits
contentInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
    e.preventDefault();
    analyzeContent();
  }
});