// =====================
// Handle incoming messages
// =====================
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "accountSwitched") {
    simulateFeed(request.token);
    sendResponse({ status: "ok", message: "Simulated feed triggered" });
    return true;
  }

  if (request.action === "requestTokenExtraction") {
    extractAndSendTokens();
    sendResponse({ status: "ok", message: "Token extraction triggered" });
    return true;
  }

  if (request.type === "REPLACE_FEED" && request.html) {
    try {
      // Prefer replacing within the primaryColumn for safety
      const feedContainer = document.querySelector('[data-testid="primaryColumn"]') 
                            || document.querySelector('main') 
                            || document.body;

      if (feedContainer) {
        feedContainer.innerHTML = request.html;
        console.log("✅ Friend's feed injected!");
        addViewerIndicator?.();
        disableInteractions?.();
        sendResponse({ status: "success", message: "Feed replaced successfully" });
      } else {
        console.error("❌ Could not find primaryColumn or fallback container to replace feed.");
        sendResponse({ status: "error", message: "Target container not found." });
      }
    } catch (error) {
      console.error("❌ Error replacing feed:", error);
      sendResponse({ status: "error", message: error.message });
    }
    return true;
  }

  return true; // keeps the message channel open for async responses
});


// =====================
// Check for active account on page load
// =====================
chrome.storage.sync.get(['activeAccount'], (result) => {
  if (result.activeAccount) {
    chrome.runtime.sendMessage({
      action: "getAccountToken",
      accountId: result.activeAccount
    }, (response) => {
      if (response?.token) {
        simulateFeed(response.token);
      }
    });
  }
});

// =====================
// Simulate feed for a given token
// =====================
function simulateFeed(token) {
  addViewerIndicator();
  disableInteractions();
  // Real simulation logic happens in the background script or injected scripts
}

// =====================
// Add indicator bar for read-only mode
// =====================
function addViewerIndicator() {
  const existing = document.getElementById('x-feed-viewer-indicator');
  if (existing) existing.remove();

  const indicator = document.createElement('div');
  indicator.id = 'x-feed-viewer-indicator';
  indicator.textContent = 'Viewing as another user (Read-only mode)';
  indicator.style.cssText = `
    background: #ffd;
    padding: 6px;
    text-align: center;
    font-weight: bold;
    border-bottom: 1px solid #ccc;
  `;
  document.body.prepend(indicator);
}

// =====================
// Disable interactions on tweets
// =====================
function disableInteractions() {
  const styleId = 'x-feed-viewer-styles';
  let style = document.getElementById(styleId);

  if (!style) {
    style = document.createElement('style');
    style.id = styleId;
    document.head.appendChild(style);
  }

  style.textContent = `
    [data-testid="like"],
    [data-testid="retweet"],
    [data-testid="reply"],
    [data-testid="tweetButton"],
    [aria-label="Like"],
    [aria-label="Retweet"],
    [aria-label="Reply"] {
      pointer-events: none !important;
      opacity: 0.5 !important;
    }
  `;
}

// =====================
// Extract tokens from cookies or localStorage and send to background
// =====================
function extractAndSendTokens() {
  // First try from localStorage/session
  let authToken = localStorage.getItem('auth_token') ||
    JSON.parse(localStorage.getItem('twitter-session'))?.auth_token;

  // Fallback: check cookies
  if (!authToken) {
    authToken = document.cookie.match(/auth_token=([^;]+)/)?.[1];
  }
  const ct0 = document.cookie.match(/ct0=([^;]+)/)?.[1];

  if (authToken && ct0) {
    chrome.runtime.sendMessage({
      action: "extractedToken",
      tokenData: {
        auth_token: authToken,
        ct0: ct0
      }
    });
    console.log("🍪 Tokens found:", authToken, ct0);
    console.log("🍪 Tokens sent to background.js");
  } else if (authToken) {
    chrome.runtime.sendMessage({
      action: "extractedToken",
      tokenData: {
        auth_token: authToken
      }
    });
    console.log("🍪 auth_token sent (ct0 not found)");
  } else {
    console.log("⚠ Could not find auth_token or ct0 in cookies/localStorage");
  }
}

// =====================
// Extract tokens on script load
// =====================
extractAndSendTokens();