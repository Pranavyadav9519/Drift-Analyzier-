/**
 * background.js — Drift Analyzer Service Worker
 *
 * Runs silently in the background and handles:
 *   1. Native OS notifications when a threat is detected
 *   2. Extension badge colour updates (green = safe, red = threat)
 *   3. Persisting the last threat to storage so the popup can display it
 *
 * This is the only file that can trigger OS-level notifications in
 * a Manifest V3 extension — content scripts cannot do this directly.
 */

const PHISHING_API = "http://localhost:5050";
const ML_API = "http://localhost:5001";

// Badge colours
const BADGE_SAFE = "#16a34a";       // Green — no active threat
const BADGE_THREAT = "#dc2626";     // Red — threat detected
const BADGE_WARNING = "#d97706";    // Amber — suspicious

// ── Message handler ───────────────────────────────────────────────────────────
//
// Content scripts send messages here when they detect a threat.
// We respond by showing a native OS notification and updating the badge.

chrome.runtime.onMessage.addListener(function(message, sender, sendResponse) {
  if (message.type === "THREAT_DETECTED") {
    handleThreatDetected(message.payload, sender.tab);
    sendResponse({ received: true });
  }
  return false;
});

// ── Tab navigation monitoring ────────────────────────────────────────────────
//
// Watch for completed page navigations and check the new URL via the
// /threat endpoint. This catches navigations that bypass link clicks
// (e.g. typed URLs, redirects, bookmarks).

chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
  if (changeInfo.status !== "complete") return;
  if (!tab.url) return;

  let parsedUrl;
  try {
    parsedUrl = new URL(tab.url);
  } catch {
    return;
  }

  // Only check http/https pages — skip chrome://, about:, etc.
  if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") return;

  checkTabUrl(tab.url, tabId);
});

async function checkTabUrl(url, tabId) {
  try {
    const response = await fetch(PHISHING_API + "/threat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url }),
    });

    if (!response.ok) return;

    const threatData = await response.json();

    if (threatData.threat_type) {
      handleThreatDetected(threatData, { id: tabId });
    } else {
      // Safe — set green badge
      setBadge(tabId, "OK", BADGE_SAFE);
      clearLastThreat();
    }

  } catch {
    // API unreachable — clear badge, don't interfere
    clearBadge(tabId);
  }
}

// ── Threat response ───────────────────────────────────────────────────────────

function handleThreatDetected(threatData, tab) {
  const tabId = tab ? tab.id : undefined;
  const isHighSeverity = threatData.severity === "high" || threatData.severity === "critical";

  // Update the extension badge to red or amber
  const badgeColour = isHighSeverity ? BADGE_THREAT : BADGE_WARNING;
  const badgeLabel = isHighSeverity ? "!" : "?";
  setBadge(tabId, badgeLabel, badgeColour);

  // Persist threat so the popup can show it when the user clicks the badge
  chrome.storage.local.set({ drift_last_threat: threatData });

  // Show a native OS notification with the top 2 remedy steps
  showNativeNotification(threatData);
}

function clearLastThreat() {
  chrome.storage.local.remove("drift_last_threat");
}

// ── Badge helpers ─────────────────────────────────────────────────────────────

function setBadge(tabId, text, colour) {
  const options = { text: text };
  const colourOptions = { color: colour };

  if (tabId !== undefined) {
    options.tabId = tabId;
    colourOptions.tabId = tabId;
  }

  chrome.action.setBadgeText(options).catch(function() {});
  chrome.action.setBadgeBackgroundColor(colourOptions).catch(function() {});
}

function clearBadge(tabId) {
  setBadge(tabId, "", BADGE_SAFE);
}

// ── Native OS notification ────────────────────────────────────────────────────
//
// Chrome's notifications API triggers a real OS desktop notification —
// no Node.js, no Python subprocess, just the browser runtime.

function showNativeNotification(threatData) {
  const threatLabel = (threatData.threat_type || "threat").replace(/_/g, " ");
  const scorePercent = Math.round((threatData.risk_score || 0) * 100);

  // Sanitize remedy steps: keep only plain strings, strip to 150 chars each to prevent
  // overly long notification bodies if the API response is unexpectedly large.
  const rawSteps = Array.isArray(threatData.remedy_steps) ? threatData.remedy_steps : [];
  const topRemedies = rawSteps
    .filter(function(step) { return typeof step === "string" && step.length > 0; })
    .slice(0, 3)
    .map(function(step) { return step.substring(0, 150); });

  const title = "Drift Analyzer \u2014 " + threatLabel.toUpperCase() + " Detected (" + scorePercent + "% risk)";
  const message = (typeof threatData.description === "string" && threatData.description)
    ? threatData.description.substring(0, 200)
    : "A threat was detected on the current page.";

  const notificationOptions = {
    type: "basic",
    iconUrl: "icon48.png",
    title: title,
    message: message,
    priority: 2,
  };

  // Append top remedy steps to the notification body if space allows
  if (topRemedies.length > 0) {
    notificationOptions.message = message + "\n\nWhat to do:\n" + topRemedies
      .map(function(step, i) { return (i + 1) + ". " + step; })
      .join("\n");
  }

  chrome.notifications.create(
    "drift-threat-" + Date.now(),
    notificationOptions,
    function() {}
  );
}

// ── Startup: set green badge to signal the extension is active ────────────────

chrome.runtime.onStartup.addListener(function() {
  clearLastThreat();
});

chrome.runtime.onInstalled.addListener(function() {
  // Show a green badge with "ON" text to confirm the extension is loaded
  chrome.action.setBadgeText({ text: "ON" });
  chrome.action.setBadgeBackgroundColor({ color: BADGE_SAFE });
  clearLastThreat();
});
