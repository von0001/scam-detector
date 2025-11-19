// SCRIPT.JS — FULL UPDATED VERSION

const API_BASE_URL = "https://scamdetectorapp.com";

const contentInput = document.getElementById("content-input");
const analyzeBtn = document.getElementById("analyze-btn");
const statusEl = document.getElementById("status");

const resultSection = document.getElementById("result-section");
const verdictBadge = document.getElementById("verdict-badge");
const explanationEl = document.getElementById("explanation");
const reasonsList = document.getElementById("reasons-list");
const detailsPre = document.getElementById("details-json"); // ADD THIS IN HTML

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
  verdictBadge.classList.remove("verdict-safe", "verdict-suspicious", "verdict-dangerous");

  if (verdict === "SAFE") verdictBadge.classList.add("verdict-safe");
  else if (verdict === "SUSPICIOUS") verdictBadge.classList.add("verdict-suspicious");
  else if (verdict === "DANGEROUS") verdictBadge.classList.add("verdict-dangerous");
}

// ----------------------
// RUN /analyze
// ----------------------
async function analyzeContent() {
  const content = contentInput.value.trim();
  const mode = getSelectedMode();

  if (!content && mode !== "qr") {
    statusEl.textContent = "Enter text or select QR mode.";
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

    const result = await response.json();
    if (!response.ok) {
      statusEl.textContent = result.error || "Error.";
      return;
    }

    verdictBadge.textContent = `Score: ${result.score}`;
    setVerdictStyle(result.verdict);
    explanationEl.textContent = result.explanation;

    reasonsList.innerHTML = "";
    (result.reasons || []).forEach((r) => {
      const li = document.createElement("li");
      li.textContent = r;
      reasonsList.appendChild(li);
    });

    // SHOW FULL RAW JSON DETAILS
    if (result.details) {
      detailsPre.textContent = JSON.stringify(result.details, null, 2);
      detailsPre.hidden = false;
    } else {
      detailsPre.hidden = true;
    }

    resultSection.hidden = false;
    statusEl.textContent = "";
  } catch (err) {
    console.error(err);
    statusEl.textContent = "Network error.";
  } finally {
    analyzeBtn.disabled = false;
  }
}

// ----------------------
// QR MODE — /qr ENDPOINT
// ----------------------
async function analyzeQR(file) {
  statusEl.textContent = "Scanning QR…";
  analyzeBtn.disabled = true;

  const form = new FormData();
  form.append("image", file);

  try {
    const response = await fetch(`${API_BASE_URL}/qr`, {
      method: "POST",
      body: form,
    });

    const result = await response.json();

    verdictBadge.textContent = `QR: ${result.overall.combined_risk_score}`;
    setVerdictStyle(result.overall.combined_verdict);

    explanationEl.textContent = `Detected ${result.qr_count} QR code(s).`;

    reasonsList.innerHTML = "";
    (result.items || []).forEach((item) => {
      const li = document.createElement("li");
      li.textContent = `${item.qr_type.toUpperCase()} → ${item.content_verdict}: ${item.raw_data}`;
      reasonsList.appendChild(li);
    });

    detailsPre.textContent = JSON.stringify(result, null, 2);
    detailsPre.hidden = false;

    resultSection.hidden = false;
    statusEl.textContent = "";
  } catch (err) {
    console.error(err);
    statusEl.textContent = "Failed to analyze QR.";
  } finally {
    analyzeBtn.disabled = false;
  }
}

// ----------------------
// OCR
// ----------------------
async function runOCR(imageFile) {
  statusEl.textContent = "Reading screenshot…";
  try {
    const worker = await Tesseract.createWorker();
    await worker.load();
    await worker.loadLanguage("eng");
    await worker.initialize("eng");

    const { data } = await worker.recognize(imageFile);
    await worker.terminate();

    const extractedText = data.text.trim();
    if (!extractedText) {
      statusEl.textContent = "No text found.";
      return;
    }

    contentInput.value = extractedText;
    statusEl.textContent = "Text extracted — analyzing…";
    analyzeContent();
  } catch (err) {
    statusEl.textContent = "OCR failed.";
  }
}

// Upload
ocrBtn.addEventListener("click", () => fileInput.click());

fileInput.addEventListener("change", () => {
  const mode = getSelectedMode();
  const file = fileInput.files[0];
  if (!file) return;

  if (mode === "qr") analyzeQR(file);
  else runOCR(file);
});

// Drag & Drop
dropZone.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropZone.classList.add("dragover");
});
dropZone.addEventListener("dragleave", () => dropZone.classList.remove("dragover"));
dropZone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropZone.classList.remove("dragover");
  const file = e.dataTransfer.files[0];
  if (!file) return;
  const mode = getSelectedMode();
  if (mode === "qr") analyzeQR(file);
  else runOCR(file);
});

// Submit
analyzeBtn.addEventListener("click", (e) => {
  e.preventDefault();
  analyzeContent();
});

// Ctrl+Enter
contentInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
    analyzeContent();
  }
});