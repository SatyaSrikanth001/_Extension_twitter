// popup.js

document.addEventListener('DOMContentLoaded', () => {
  // Load existing accounts
  loadAccounts();

  // Setup event listeners
  document.getElementById('start-sharing-btn').addEventListener('click', startSharing);
  document.getElementById('cancel-sharing-btn').addEventListener('click', cancelSharing);
  document.getElementById("login-btn").addEventListener("click", initiateTwitterLogin);

  // Setup view friend's feed button
  document.getElementById("view-feed-btn")?.addEventListener("click", () => {
    const username = document.getElementById("friend-username")?.value.trim();

    if (!username || !username.startsWith("@")) {
      showStatus("Please enter a valid @username", "error");
      return;
    }

    chrome.runtime.sendMessage({
      action: "VIEW_FEED",
      username: username
    }, (response) => {
      if (chrome.runtime.lastError) {
        console.error("Message failed:", chrome.runtime.lastError.message);
        showStatus("Failed to send message", "error");
      } else {
        console.log("VIEW_FEED message sent.");
        showStatus("Loading feed...", "info");
      }
    });
  });

  // Listen for token capture completion
  chrome.runtime.onMessage.addListener((request) => {
    if (request.action === "tokenCaptured") {
      chrome.storage.local.set({ token: request.token }, () => {
        console.log("JWT saved to local storage");
        chrome.storage.local.get("token", ({ token }) => {
          fetch("http://localhost:8000/feeds/", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Authorization": `Bearer ${token}`
            },
            body: JSON.stringify({
              account_id: request.accountId,
              name: request.accountName,
              token: request.xToken
            })
          })
          .then(res => res.json())
          .then(data => {
            console.log("Shared feed response:", data);
            showStatus(`Successfully shared feed: ${request.accountName}`, 'success');
            document.getElementById('sharing-status').classList.add('hidden');
            document.getElementById('start-sharing-btn').disabled = false;
            loadAccounts();
          })
          .catch(err => {
            console.error("Error sharing feed:", err);
            showStatus("Error sharing feed", "error");
            document.getElementById('start-sharing-btn').disabled = false;
          });
        });
      });
    }
  });
});

function loadAccounts() {
  chrome.storage.sync.get(['xFeedAccounts', 'activeAccount'], (result) => {
    const accountList = document.querySelector('.account-list');
    const accounts = result.xFeedAccounts || {};

    accountList.innerHTML = `
      <div class="account-item" data-account-id="default">
        <input type="radio" name="account" id="default" ${!result.activeAccount ? 'checked' : ''}>
        <label for="default">My Feed</label>
      </div>
    `;

    for (const [id, account] of Object.entries(accounts)) {
      const accountItem = document.createElement('div');
      accountItem.className = 'account-item';
      accountItem.dataset.accountId = id;

      const radio = document.createElement('input');
      radio.type = 'radio';
      radio.name = 'account';
      radio.id = id;
      if (result.activeAccount === id) radio.checked = true;
      radio.addEventListener('change', () => {
        if (radio.checked) switchAccount(id);
      });

      const label = document.createElement('label');
      label.htmlFor = id;
      label.textContent = account.name || `Shared Feed ${id.slice(-4)}`;

      accountItem.appendChild(radio);
      accountItem.appendChild(label);
      accountList.appendChild(accountItem);
    }
  });
}

function switchAccount(accountId) {
  showStatus('Switching feed...', 'info');
  chrome.runtime.sendMessage({ action: "getSharedFeeds" }, (response) => {
  const feeds = response.feeds || [];
  const container = document.getElementById("feedOptionsContainer");

  // Add "My Feed" option
  const myFeedRadio = document.createElement("input");
  myFeedRadio.type = "radio";
  myFeedRadio.name = "feedOption";
  myFeedRadio.value = "default";
  myFeedRadio.checked = true;
  myFeedRadio.addEventListener("change", () => switchAccount("default"));
  container.appendChild(myFeedRadio);
  container.appendChild(document.createTextNode(" My Feed"));

  container.appendChild(document.createElement("br"));

  // Add shared feeds
  feeds.forEach(feedId => {
    const radio = document.createElement("input");
    radio.type = "radio";
    radio.name = "feedOption";
    radio.value = feedId;
    radio.addEventListener("change", () => switchAccount(feedId));
    container.appendChild(radio);
    container.appendChild(document.createTextNode(` ${feedId}`));
    container.appendChild(document.createElement("br"));
  });
});

}

function startSharing() {
  const accountName = document.getElementById('share-account-name').value.trim() || "My Shared Feed";
  showStatus('Preparing to share feed...', 'info');
  document.getElementById('start-sharing-btn').disabled = true;

  chrome.runtime.sendMessage({
    action: "startTokenCapture",
    accountName
  }, (response) => {
    if (response?.status === "ready") {
      document.getElementById('sharing-status').classList.remove('hidden');
      showStatus('Please refresh your X.com feed to share it', 'info');
    } else {
      showStatus('Failed to start sharing', 'error');
      document.getElementById('start-sharing-btn').disabled = false;
    }
  });
}

function cancelSharing() {
  chrome.runtime.sendMessage({ action: "cancelTokenCapture" });
  document.getElementById('sharing-status').classList.add('hidden');
  document.getElementById('start-sharing-btn').disabled = false;
  showStatus('Sharing cancelled', 'warning');
}

function showStatus(message, type) {
  const statusEl = document.getElementById('status-message');
  statusEl.textContent = message;
  statusEl.className = `status-message ${type}`;
  setTimeout(() => {
    if (statusEl.textContent === message) {
      statusEl.textContent = '';
      statusEl.className = 'status-message';
    }
  }, 3000);
}

function generateCodeVerifier() {
  const array = new Uint32Array(32);
  window.crypto.getRandomValues(array);
  return Array.from(array, dec => ('0' + dec.toString(16)).slice(-2)).join('');
}

async function generateCodeChallenge(codeVerifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

async function initiateTwitterLogin() {
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);
  const clientId = "RS1ZUTZxZ3dERzRRYTRUcVRwS3U6MTpjaQ";
  const redirectUri = `https://dikhijadkhbaicckhieiofniahbfecgo.chromiumapp.org/`;
  const state = crypto.randomUUID();

  await chrome.storage.local.set({ codeVerifier, oauthState: state });

  const authUrl = `https://twitter.com/i/oauth2/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=tweet.read%20users.read%20offline.access&state=${state}&code_challenge=${codeChallenge}&code_challenge_method=S256`;

  chrome.identity.launchWebAuthFlow({ url: authUrl, interactive: true }, async (redirectUrl) => {
    if (chrome.runtime.lastError || !redirectUrl) {
      console.error("Auth failed", chrome.runtime.lastError);
      return;
    }

    const url = new URL(redirectUrl);
    const code = url.searchParams.get("code");
    const returnedState = url.searchParams.get("state");

    const { oauthState, codeVerifier } = await chrome.storage.local.get(["oauthState", "codeVerifier"]);
    if (returnedState !== oauthState) {
      console.error("State mismatch");
      return;
    }

    exchangeCodeForToken(code, codeVerifier, redirectUri, clientId);
  });
}

async function exchangeCodeForToken(code, codeVerifier, redirectUri, clientId) {
  const tokenUrl = 'https://api.twitter.com/2/oauth2/token';
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri,
    client_id: clientId,
    code_verifier: codeVerifier
  });

  const response = await fetch(tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body
  });

  const data = await response.json();
  if (data.access_token) {
    await chrome.storage.local.set({
      twitterAccessToken: data.access_token,
      twitterRefreshToken: data.refresh_token
    });
    console.log("Access token saved");
  } else {
    console.error("Failed to get token", data);
  }
}
