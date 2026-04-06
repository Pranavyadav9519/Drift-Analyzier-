/**
 * popup.js — Drift Analyzer Extension Popup
 *
 * Shows the last threat detected on the current tab.
 * If no threat: green "safe" card.
 * If threat detected: red card with threat type, score, and remedy steps.
 * Badge colour is set by background.js via chrome.action.setBadgeBackgroundColor.
 */

const PHISHING_API = "http://localhost:5050";

// DOM references
const statusBadge = document.getElementById("status-badge");
const statusIcon = document.getElementById("status-icon");
const statusText = document.getElementById("status-text");
const threatCard = document.getElementById("threat-card");
const safeCard = document.getElementById("safe-card");
const threatTypeLabel = document.getElementById("threat-type-label");
const threatSeverity = document.getElementById("threat-severity");
const threatScore = document.getElementById("threat-score");
const threatDescription = document.getElementById("threat-description");
const remedyList = document.getElementById("remedy-list");
const statTotal = document.getElementById("stat-total");
const statThreats = document.getElementById("stat-threats");
const statLatency = document.getElementById("stat-latency");

// ── Load and render state from storage ───────────────────────────────────────

function renderSafeState() {
  statusBadge.className = "status-badge status-safe";
  statusIcon.textContent = "🛡️";
  statusText.textContent = "Protected";
  threatCard.classList.add("hidden");
  safeCard.classList.remove("hidden");
}

function renderThreatState(threatData) {
  const isHighSeverity = threatData.severity === "high" || threatData.severity === "critical";
  const isMediumSeverity = threatData.severity === "medium";

  // Update header badge
  statusBadge.className = "status-badge " + (isHighSeverity ? "status-threat" : "status-warning");
  statusIcon.textContent = isHighSeverity ? "🚨" : "⚠️";
  statusText.textContent = isHighSeverity ? "Threat Detected" : "Warning";

  // Populate threat card
  const threatTypeReadable = (threatData.threat_type || "unknown").replace(/_/g, " ");
  threatTypeLabel.textContent = threatTypeReadable;
  threatSeverity.textContent = (threatData.severity || "UNKNOWN").toUpperCase();
  threatScore.textContent = Math.round((threatData.risk_score || 0) * 100) + "%";
  threatDescription.textContent = threatData.description || "";

  // Apply warning colour variant for medium severity
  if (isMediumSeverity) {
    threatCard.classList.add("warning");
  } else {
    threatCard.classList.remove("warning");
  }

  // Render remedy steps
  remedyList.innerHTML = "";
  const steps = threatData.remedy_steps || [];
  steps.forEach(function(step) {
    const li = document.createElement("li");
    li.textContent = step;
    remedyList.appendChild(li);
  });

  safeCard.classList.add("hidden");
  threatCard.classList.remove("hidden");
}

function loadPopupState() {
  chrome.storage.local.get(["drift_last_threat", "drift_stats"], function(result) {
    const lastThreat = result.drift_last_threat;
    const sessionStats = result.drift_stats || { total: 0, threats: 0 };

    // Update session statistics
    statTotal.textContent = sessionStats.total || 0;
    statThreats.textContent = sessionStats.threats || 0;

    if (lastThreat && lastThreat.threat_type) {
      renderThreatState(lastThreat);
    } else {
      renderSafeState();
    }
  });

  // Fetch average latency from the phishing API (non-blocking)
  fetch(PHISHING_API + "/stats")
    .then(function(response) { return response.json(); })
    .then(function(data) {
      if (data.avg_latency_ms) {
        statLatency.textContent = data.avg_latency_ms + " ms";
      }
    })
    .catch(function() {
      statLatency.textContent = "—";
    });
}

// Render immediately when the popup opens
loadPopupState();
