// If your backend is hosted somewhere else later, change this:
const API_BASE_URL = "https://scamdetectorapp.com";

const contentInput = document.getElementById("content-input");
const analyzeBtn = document.getElementById("analyze-btn");
const statusEl = document.getElementById("status");

const resultSection = document.getElementById("result-section");
const verdictBadge = document.getElementById("verdict-badge");
const explanationEl = document.getElementById("explanation");
const reasonsList = document.getElementById("reasons-list");

const ocrBtn = document.getElementById("ocr-btn");
const fileInput = document.getElementById("ocr-file");
const dropZone = document.getElementById("drop-zone");

// ----------------------
// GET SELECTED MODE
// ----------------------
function getSelectedMode() {
  const radios = document.querySelectorAll('input[name="mode"]');
  for (const r of radios) if (r.checked) return r.value;
  return "auto";
}

// ----------------------
// SET VERDICT COLOR
// ----------------------
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

// ----------------------
// RUN ANALYSIS
// ----------------------
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

    verdictBadge.textContent = `Score: ${result.score}`;
    setVerdictStyle(result.score === 0 ? "SAFE" : "SUSPICIOUS");

    explanationEl.textContent =
      result.score === 0 ? "No scam detected." : "Potential scam indicators detected.";

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

// -------------------------------------------------------------------
// OCR (Tesseract.js) — Upload + Drag/Drop + Paste
// -------------------------------------------------------------------
async function runOCR(imageFile) {
  statusEl.textContent = "Reading screenshot…";
  statusEl.classList.add("loading");

  try {
    const worker = await Tesseract.createWorker();

    await worker.load();
    await worker.loadLanguage("eng");
    await worker.initialize("eng");

    const { data } = await worker.recognize(imageFile);

    await worker.terminate();

    const extractedText = data.text.trim();

    if (!extractedText) {
      statusEl.textContent = "No readable text found.";
      statusEl.classList.remove("loading");
      return;
    }

    contentInput.value = extractedText;
    statusEl.textContent = "Text extracted — analyzing…";
    statusEl.classList.remove("loading");

    analyzeContent();
  } catch (err) {
    console.error(err);
    statusEl.textContent = "Failed to read image.";
    statusEl.classList.remove("loading");
  }
}

// Upload button
ocrBtn.addEventListener("click", () => fileInput.click());

// File upload selection
fileInput.addEventListener("change", () => {
  if (fileInput.files.length) {
    runOCR(fileInput.files[0]);
  }
});

// ------- Drag & Drop -------
dropZone.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropZone.classList.add("dragover");
});

dropZone.addEventListener("dragleave", () => {
  dropZone.classList.remove("dragover");
});

dropZone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropZone.classList.remove("dragover");

  const file = e.dataTransfer.files[0];
  if (file) runOCR(file);
});

// ------- Paste screenshot (Ctrl+V) -------
document.addEventListener("paste", (e) => {
  for (const item of e.clipboardData.items) {
    if (item.type.startsWith("image/")) {
      const file = item.getAsFile();
      runOCR(file);
      return;
    }
  }
});

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
