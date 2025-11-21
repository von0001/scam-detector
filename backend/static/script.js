// SCRIPT.JS — FULL PATCHED VERSION (QR FIXED)

const API_BASE_URL = "https://scamdetectorapp.com";

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

// MODE
function getSelectedMode() {
  const radios = document.querySelectorAll('input[name="mode"]');
  for (const r of radios) if (r.checked) return r.value;
  return "auto";
}

// Verdict color + label
function setVerdictStyle(verdict) {
  verdictBadge.classList.remove("verdict-safe", "verdict-suspicious", "verdict-dangerous");

  if (verdict === "SAFE") {
    verdictBadge.classList.add("verdict-safe");
  } else if (verdict === "SUSPICIOUS") {
    verdictBadge.classList.add("verdict-suspicious");
  } else if (verdict === "DANGEROUS") {
    verdictBadge.classList.add("verdict-dangerous");
  }
}

// MAIN ANALYZE
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
      body: JSON.stringify({ content, mode }),
    });

    const result = await response.json();
    if (!response.ok) {
      statusEl.textContent = result.error || "Something went wrong during analysis.";
      return;
    }

    // Big, emotionally clear verdict badge
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
  } catch (err) {
    statusEl.textContent = "Network error. Try again in a moment.";
  } finally {
    analyzeBtn.disabled = false;
  }
}

// QR SCAN
async function analyzeQR(file) {
  statusEl.textContent = "Scanning QR code and checking destination safety…";
  analyzeBtn.disabled = true;

  const form = new FormData();
  form.append("image", file);

  try {
    const response = await fetch(`${API_BASE_URL}/qr`, { method: "POST", body: form });
    const result = await response.json();

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
  } catch (err) {
    statusEl.textContent = "Failed to analyze QR. Try a clearer image.";
  } finally {
    analyzeBtn.disabled = false;
  }
}

// OCR (unchanged logic, improved status text)
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
ocrBtn.addEventListener("click", () => fileInput.click());

fileInput.addEventListener("change", () => {
  const file = fileInput.files[0];
  if (!file) return;
  const mode = getSelectedMode();
  if (mode === "qr") analyzeQR(file);
  else runOCR(file);
});

// Drag & drop
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

// Ctrl+Enter submit
contentInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) analyzeContent();
});