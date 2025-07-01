# _Extension_twitter
XFeed Share is a Chrome extension that allows users to view Twitter/X feeds from different accounts. It enables you to share your own feed and switch between multiple feeds using tokens and DOM manipulation.

Features:

View your own Twitter/X timeline using Twikit authentication

Share your Twitter/X feed as a “shared feed”

Receive a friend's feed and view it directly on X.com

Encrypts and stores tokens securely

Allows switching between multiple feeds

Backend integration for storing and retrieving shared tokens

Technology Stack:

JavaScript (Chrome Extension APIs)

Twikit.js (unofficial Twitter client)

AES-CBC token encryption

Backend (Node.js/Flask) to store and serve encrypted tokens

LocalStorage & chrome.storage.sync for state management

Folder Structure:

/background.js – Handles core logic, messaging, and Twitter API

/popup/ – Contains popup.html, popup.js (UI for login, feed switching, sharing)

/content/ – Injected scripts that modify Twitter/X DOM (replace feed, extract tokens)

/manifest.json – Extension metadata and permissions

Installation (Development Setup):

Clone or download the repo to your local machine.

Go to chrome://extensions in your Chrome browser.

Enable "Developer Mode" (top right).

Click "Load Unpacked" and select the extension directory.

The extension will appear in the toolbar.

Backend Setup (Local Dev):

Ensure a backend is running at http://localhost:8000 with the following endpoints:

POST /store-token – to store encrypted tokens

GET /get-feed – returns HTML for the user's timeline (via Twikit or API)

POST /feeds/ – register a shared feed with token

Start the backend server (Flask or Node.js depending on your code).

Usage Guide:

To Share Your Feed:

Click the extension icon

Log in with your Twitter credentials using Twikit

Click “Start Sharing” and authorize Twitter

Token will be captured and stored on the backend

You’ll receive a share code

To View a Friend’s Feed:

Paste the friend’s username or share code in the input box

Click “View Feed”

Their feed will appear in place of yours on Twitter.com

Troubleshooting:

If "Failed to send message" appears:

Ensure content.js is correctly injected into Twitter/X tabs

Confirm tab is on x.com or twitter.com

Reload Twitter tab before viewing feed

If “Failed to register feed”, check:

Backend server is running

Token is properly encrypted and sent

chrome.storage.local has the token stored

Security Notes:

Tokens are encrypted using AES-CBC before sending to backend

Your access token is stored securely in chrome.storage.local

Always use HTTPS in production

Permissions Required:

"identity"

"tabs"

"scripting"

"storage"

"https://.twitter.com/"

"https://.x.com/"

"http://localhost:8000/*"

License

MIT License – feel free to fork, use, and modify.

Contributors

Lolla Srikanth 22117075

Mutyalapati Rushi 22116058

A Jayendra 22117001
