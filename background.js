// Configuration
const API_BASE_URL = "http://localhost:8000"; // Local development
const TOKEN_REFRESH_INTERVAL = 30 * 60 * 1000; // 30 minutes
const TWITTER_CLIENT_ID = "RS1ZUTZxZ3dERzRRYTRUcVRwS3U6MTpjaQ";
const redirect_uri = `https://dikhijadkhbaicckhieiofniahbfecgo.chromiumapp.org/`;

// State management
let twitterClient = null;
let activeAccount = null;
let accounts = {};

chrome.storage.sync.get(['xFeedAccounts', 'activeAccount'], (result = {}) => {
  if (!result.xFeedAccounts) {
    chrome.storage.sync.set({ xFeedAccounts: {} });
  }
  if (!result.activeAccount) {
    chrome.storage.sync.set({ activeAccount: null });
  }

  accounts = result.xFeedAccounts || {};
  activeAccount = result.activeAccount || null;
});


// Message handling

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log("📬 Message received in background.js:", request);

  switch (request.action) {
    case "login":
    case "oauthLogin":
      initiateTwitterLogin();
      return true;

    case "switchAccount":
      handleAccountSwitch(request.accountId, sendResponse);
      return true;

    case "shareFeed":
      handleShareFeed(request.feedName, sendResponse);
      return true;

    case "getSharedFeeds":
      getSharedFeeds(sendResponse);
      return true;

    case "revokeAccess":
      revokeAccess(request.feedId, sendResponse);
      return true;

    case "startTokenCapture":
      console.log("🚀 startTokenCapture received with name:", request.accountName);
      handleStartTokenCapture(request.accountName, sendResponse);
      return true;

    case "cancelTokenCapture":
      sendResponse({ status: "cancelled" });
      return true;

    case "getTwitterUser":
      chrome.storage.local.get("twitterAccessToken", ({ twitterAccessToken }) => {
        if (twitterAccessToken) {
          fetch("https://api.twitter.com/2/users/me", {
            headers: {
              "Authorization": `Bearer ${twitterAccessToken}`
            }
          })
          .then(res => res.json())
          .then(data => {
            console.log("👤 Twitter user:", data);
            sendResponse({ status: "success", data });
          })
          .catch(err => {
            console.error("Failed to fetch user", err);
            sendResponse({ status: "error", error: err });
          });
          return true;
        } else {
          sendResponse({ status: "error", message: "No access token found" });
        }
      });
      return true;

case "VIEW_FEED": {
  const twitter_id = request.username.replace("@", "");

  fetch(`http://localhost:8000/get-feed?user_id=${twitter_id}`)
    .then(res => res.text())
    .then(feedHTML => {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const tab = tabs[0];
        console.log("🔍 Tab URL:", tab?.url);

        if (!tab || !tab.url || (!tab.url.includes("x.com") && !tab.url.includes("twitter.com"))) {
          console.error("❌ Not a Twitter/X tab.");
          sendResponse({ status: "error", message: "This action only works on Twitter/X tabs." });
          return;
        }

        chrome.scripting.executeScript({
          target: { tabId: tab.id },
          files: ["content.js"]
        }, () => {
          if (chrome.runtime.lastError) {
            console.error("❌ Failed to inject content script:", chrome.runtime.lastError.message);
            sendResponse({ status: "error", message: "Could not inject script." });
          } else {
            chrome.tabs.sendMessage(tab.id, {
              type: "REPLACE_FEED",
              html: feedHTML
            }, () => {
              if (chrome.runtime.lastError) {
                console.error("❌ Failed to send message to content script:", chrome.runtime.lastError.message);
                sendResponse({ status: "error", message: chrome.runtime.lastError.message });
              } else {
                console.log("✅ Sent REPLACE_FEED to content script and replaced successfully.");
                sendResponse({ status: "success" });
              }
            });
          }
        });
      });
    })
    .catch(err => {
      console.error("❌ Failed to fetch friend's feed:", err);
      sendResponse({ status: "error", error: err.message });
    });

  return true; // ✅ Keep the message channel open
}


    
// ✅ background.js

case "extractedToken":
  if (request.tokenData) {
    const twitter_id = "Srikanth1776661"; // Replace with dynamic logic later
    console.log("Encrypting token data:",request.tokenData);
    // ⬇️ Fix: Wait for encryption to finish
    encryptToken(request.tokenData)
      .then((encrypted) => {
        console.log("Encrypted value:", encrypted)
        // Send encrypted token to backend
        fetch("http://localhost:8000/store-token", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            twitter_id,
            encrypted_tokens: encrypted
          })
        })
        .then(res => res.json())
        .then(() => {
          console.log(`✅ Token stored for ${twitter_id}`);
        })
        .catch(err => {
          console.error("❌ Failed to store token:", err);
        });
      })
      .catch(err => {
        console.error("❌ Encryption failed:", err);
      });
  }
  return true;

  }
});

// PKCE OAuth functions
function generateCodeVerifier() {
  const array = new Uint32Array(56 / 2);
  window.crypto.getRandomValues(array);
  return Array.from(array, dec => ('0' + dec.toString(16)).substr(-2)).join('');
}

async function generateCodeChallenge(codeVerifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}







async function exchangeCodeForToken(code, codeVerifier, redirectUri, clientId) {
  const tokenUrl = 'https://api.twitter.com/2/oauth2/token';

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: code,
    redirect_uri: redirectUri,
    client_id: clientId,
    code_verifier: codeVerifier
  });

  const response = await fetch(tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body
  });

  const data = await response.json();

  if (data.access_token) {
    console.log("✅ Access token received");

    // ✅ Store tokens
    await chrome.storage.local.set({
      twitterAccessToken: data.access_token,
      twitterRefreshToken: data.refresh_token,
      tokenExpiresIn: Date.now() + data.expires_in * 1000
    });

    // Optional: Notify popup or UI
    chrome.runtime.sendMessage({ action: "oauthSuccess", token: data.access_token });

  } else {
    console.error("❌ Failed to exchange code:", data);
  }
}






async function initiateTwitterLogin() {
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);

  const authUrl = `https://twitter.com/i/oauth2/authorize?response_type=code&client_id=${TWITTER_CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=tweet.read users.read offline.access&state=state123&code_challenge=${codeChallenge}&code_challenge_method=S256`;

  chrome.identity.launchWebAuthFlow({
    url: authUrl,
    interactive: true
  }, async function (redirectUrl) {
    if (chrome.runtime.lastError || !redirectUrl) {
      console.error("Auth failed", chrome.runtime.lastError);
      return;
    }

    const url = new URL(redirectUrl);
    const authorizationCode = url.searchParams.get('code');
    await exchangeCodeForToken(authorizationCode, codeVerifier);
  });
}


function getSharedFeeds(sendResponse) {
  chrome.storage.sync.get(["xFeedAccounts"], (result) => {
    if (chrome.runtime.lastError) {
      console.error("Error fetching shared feeds:", chrome.runtime.lastError);
      sendResponse({ status: "error", message: "Storage error" });
      return;
    }

    const accounts = result.xFeedAccounts || {};

    const feeds = Object.keys(accounts)
      .filter(username => username !== "default")
      .map(username => ({
        username,
        feedData: accounts[username]
      }));

    sendResponse({ status: "success", feeds });
  });

  // IMPORTANT: must return true to keep sendResponse valid
  return true;
}





// Authentication with Twikit
async function handleLogin(credentials, sendResponse) {
  try {
    twitterClient = new TwikitClient();
    await twitterClient.login({
      email: credentials.email,
      username: credentials.username,
      password: credentials.password,
      two_factor_code: credentials.twoFACode
    });

    const user = await twitterClient.get_current_user();
    const accountId = `acc_${user.id}`;

    accounts[accountId] = {
      id: accountId,
      name: credentials.feedName || `${user.screen_name}'s Feed`,
      username: user.screen_name,
      token: twitterClient.get_auth_token(),
      lastUpdated: new Date().toISOString()
    };

    await chrome.storage.sync.set({ xFeedAccounts: accounts });
    sendResponse({ status: "success", accountId });

    scheduleTokenRefresh(accountId);
  } catch (error) {
    console.error("Login failed:", error);
    sendResponse({ status: "error", message: error.message });
  }
}

async function handleAccountSwitch(accountId, sendResponse) {
  try {
    if (accountId === 'default') {
      activeAccount = null;
      await chrome.storage.sync.remove(['activeAccount']);
      await reloadActiveTab();
      sendResponse({ status: "switched_to_default" });
      return;
    }

    const account = accounts[accountId];
    if (!account) throw new Error("Account not found");

    twitterClient = new TwikitClient();
    twitterClient.set_auth_token(account.token);

    try {
      await twitterClient.get_current_user();
    } catch (error) {
      await refreshAccountToken(accountId);
    }

    activeAccount = accountId;
    await chrome.storage.sync.set({ activeAccount: accountId });
    await updateBrowserSession();
    sendResponse({ status: "success" });
  } catch (error) {
    console.error("Account switch failed:", error);
    sendResponse({ status: "error", message: error.message });
  }
}

console.log()

console.log("🟢 handleSharedFeed triggered");

async function handleShareFeed(feedName, sendResponse) {
  try {
    if (!twitterClient) {
      console.error("❌ twitterClient not initialized");
      throw new Error("Not authenticated");
    }

    const user = await twitterClient.get_current_user();
    const accountId = `acc_${user.id}`;
    const token = twitterClient.get_auth_token();

    console.log("👤 Twitter user:", user);
    console.log("🔐 Access token from twitterClient:", token);

    accounts[accountId] = {
      id: accountId,
      name: feedName,
      username: user.screen_name,
      token,
      sharedAt: new Date().toISOString()
    };

    await chrome.storage.sync.set({ xFeedAccounts: accounts });
    console.log("💾 Account saved to chrome.storage.sync:", accounts[accountId]);

    console.log("📨 Calling registerSharedFeedWithBackend with:", {
      accountId,
      feedName,
      token
    });

    await registerSharedFeedWithBackend(accountId, feedName, token);

    console.log("✅ registerSharedFeedWithBackend completed successfully");

    sendResponse({
      status: "success",
      accountId,
      shareableCode: generateShareCode(accountId, token)
    });
  } catch (err) {
    console.error("❌ handleSharedFeed failed:", err.message || err);
    sendResponse({ status: "error", message: err.message || "Unknown error" });
  }
}


async function refreshAccountToken(accountId) {
  const account = accounts[accountId];
  if (!account) return;

  try {
    twitterClient = new TwikitClient();
    twitterClient.set_auth_token(account.token);
    await twitterClient.get_current_user();

    const newToken = twitterClient.get_auth_token();
    if (newToken !== account.token) {
      account.token = newToken;
      account.lastUpdated = new Date().toISOString();
      await chrome.storage.sync.set({ xFeedAccounts: accounts });
    }
  } catch (error) {
    console.error("Token refresh failed:", error);
    account.needsReauth = true;
    await chrome.storage.sync.set({ xFeedAccounts: accounts });
    throw error;
  }
}

function scheduleTokenRefresh(accountId) {
  setInterval(async () => {
    if (activeAccount === accountId) {
      await refreshAccountToken(accountId);
    }
  }, TOKEN_REFRESH_INTERVAL);
}

async function updateBrowserSession() {
  if (!activeAccount || !accounts[activeAccount]) return;

  const account = accounts[activeAccount];
  const [tab] = await chrome.tabs.query({ 
    active: true, 
    currentWindow: true,
    url: ["*://*.x.com/*", "*://*.twitter.com/*"]
  });

  if (tab) {
    await chrome.tabs.sendMessage(tab.id, {
      action: "accountSwitched",
      token: account.token,
      username: account.username
    });
  }
}

async function reloadActiveTab() {
  const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
  if (tab) {
    await chrome.tabs.reload(tab.id);
  }
}

function generateShareCode(accountId, token) {
  return btoa(JSON.stringify({ id: accountId, t: token.slice(-16) })).replace(/=/g, '');
}

































// const API_BASE_URL = "http://localhost:8000";

async function registerSharedFeedWithBackend(accountId, feedName, token) {
  console.log("📦 Inside registerSharedFeedWithBackend");
  const jwt = await new Promise(resolve => {
    chrome.storage.local.get("token", ({ token }) => {
      console.log("🔍 token in chrome.storage.local:", token);
      resolve(token);
    });
  });

  console.log("Sending feed to backend with:", {
    jwt,
    accountId,
    feedName,
    token
  });

  const response = await fetch(`${API_BASE_URL}/feeds/`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${jwt}`
    },
    body: JSON.stringify({
      account_id: accountId,
      name: feedName,
      token: token
    })
  });

  if (!response.ok) {
    const errorText = await response.text();
    console.error("❌ Failed to register feed:", errorText);
    throw new Error("Failed to register feed");
  }

  console.log("✅ registerSharedFeedWithBackend successful");
}

























// Keep service worker alive
chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create('keepAlive', { periodInMinutes: 1 });
});

chrome.alarms.onAlarm.addListener((alarm) => {
  console.log("Alarm triggered:", alarm.name);
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'keepAlive') {
    // No-op
  }
});

// Twikit Client Wrapper
class TwikitClient {
  constructor() {
    this.client = new Client();
    this.authenticated = false;
  }

  async login({ email, username, password, two_factor_code }) {
    await this.client.login({
      auth_info_1: email,
      auth_info_2: username,
      password: password,
      two_factor_code: two_factor_code
    });
    this.authenticated = true;
  }

  set_auth_token(token) {
    this.client.set_auth_token(token);
    this.authenticated = true;
  }

  get_auth_token() {
    return this.client.get_auth_token();
  }

  async get_current_user() {
    return await this.client.get_current_user();
  }

  async get_home_timeline() {
    return await this.client.get_home_timeline();
  }
}

async function initiateTwitterLogin() {
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);
  const clientId = "RS1ZUTZxZ3dERzRRYTRUcVRwS3U6MTpjaQ";
  const redirectUri = `https://dikhijadkhbaicckhieiofniahbfecgo.chromiumapp.org/`;

  const authUrl = `https://twitter.com/i/oauth2/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=tweet.read users.read offline.access&state=state123&code_challenge=${codeChallenge}&code_challenge_method=S256`;

  chrome.storage.local.set({ codeVerifier });

  chrome.identity.launchWebAuthFlow({
    url: authUrl,
    interactive: true
  }, function (redirectUrl) {
    if (chrome.runtime.lastError || !redirectUrl) {
      console.error("Auth failed", chrome.runtime.lastError);
      return;
    }

    const url = new URL(redirectUrl);
    const authorizationCode = url.searchParams.get('code');
    if (!authorizationCode) {
      console.error("No authorization code found");
      return;
    }

    chrome.storage.local.get("codeVerifier", ({ codeVerifier }) => {
      exchangeCodeForToken(authorizationCode, codeVerifier, redirectUri, clientId);
    });
  });
}


function generateCodeVerifier() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function generateCodeChallenge(codeVerifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}


// Utility functions
function generateCodeVerifier() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function generateCodeChallenge(codeVerifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}



// Handle start token capture in background.js
async function handleStartTokenCapture(accountName, sendResponse) {
  try {
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = await generateCodeChallenge(codeVerifier);
    const clientId = "RS1ZUTZxZ3dERzRRYTRUcVRwS3U6MTpjaQ"; // Replace with your actual Twitter client ID
    const redirectUri = `https://dikhijadkhbaicckhieiofniahbfecgo.chromiumapp.org/`;

    const authUrl = `https://twitter.com/i/oauth2/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(
      redirectUri
    )}&scope=tweet.read%20users.read%20offline.access&state=state123&code_challenge=${codeChallenge}&code_challenge_method=S256`;

    chrome.identity.launchWebAuthFlow(
      {
        url: authUrl,
        interactive: true,
      },
      async (redirectUrl) => {
        if (chrome.runtime.lastError || !redirectUrl) {
          console.error("❌ Auth failed", chrome.runtime.lastError);
          sendResponse({ status: "error", message: "Authorization failed" });
          return;
        }

        const url = new URL(redirectUrl);
        const authorizationCode = url.searchParams.get("code");

        const tokenResponse = await exchangeCodeForToken(
          authorizationCode,
          codeVerifier,
          redirectUri,
          clientId
        );

        if (tokenResponse?.access_token) {
          await chrome.storage.local.set({
            token: tokenResponse.access_token,
            refresh_token: tokenResponse.refresh_token,
          });

          // ✅ Step: Inject content.js to grab cookies (auth_token and ct0)
          chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (!tabs.length) {
              console.error("❌ No active tab to inject");
              sendResponse({ status: "error", message: "No active tab found" });
              return;
            }

            chrome.scripting.executeScript({
              target: { tabId: tabs[0].id },
              files: ["content.js"],
            }, () => {
              console.log("✅ content.js injected to tab for token capture");

              // Optionally notify popup to tell user to refresh X.com now
              sendResponse({ status: "ready" });
            });
          });

        } else {
          sendResponse({ status: "error", message: "Token exchange failed" });
        }
      }
    );
  } catch (err) {
    console.error("❌ Error in token capture:", err);
    sendResponse({ status: "error", message: err.message });
  }

  return true;
}

async function encryptToken(plainText) {
  const encoder = new TextEncoder();

  // 🔐 Use a fixed 256-bit key (32 bytes) — must match backend
  const rawKey = encoder.encode("0123456789abcdef0123456789abcdef");

  // ⚙ Generate a random IV (initialization vector) — 16 bytes for AES-CBC
  const iv = crypto.getRandomValues(new Uint8Array(16));

  // 🔤 Encode the plaintext string into a Uint8Array
  const data = encoder.encode(plainText);

  // 🔑 Import the raw key as a CryptoKey object
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    rawKey,
    "AES-CBC",
    false,
    ["encrypt"]
  );

  // 🔒 Encrypt the data
  const encryptedBuffer = await crypto.subtle.encrypt(
    { name: "AES-CBC", iv },
    cryptoKey,
    data
  );

  // 📦 Combine IV and encrypted data
  const combined = new Uint8Array([
    ...iv,
    ...new Uint8Array(encryptedBuffer)
  ]);

  // 🔁 Convert combined buffer to base64 for storage/transmission
  return btoa(String.fromCharCode(...combined));
}