// content.js — injected into Gmail tabs
// Injects the Helios sidebar and handles phish reporting

const HELIOS_API = 'https://app.himaya.ai';

let currentMessageId = null;
let currentUserEmail = null;
let sidebarMounted = false;

// ─── Init ──────────────────────────────────────────────────────────────────

function init() {
  extractUserEmail();
  mountSidebar();
  observeGmailNavigation();
}

// ─── Extract user email from Gmail DOM ────────────────────────────────────

function extractUserEmail() {
  // Method 1: aria-label on account button (most reliable 2025+ Gmail)
  const accountBtns = document.querySelectorAll('a[aria-label], button[aria-label]');
  for (const btn of accountBtns) {
    const label = btn.getAttribute('aria-label') || '';
    const match = label.match(/([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})/);
    if (match) { currentUserEmail = match[1]; return; }
  }
  // Method 2: data-email attribute anywhere
  const dataEmailEl = document.querySelector('[data-email]');
  if (dataEmailEl) {
    const email = dataEmailEl.getAttribute('data-email');
    if (email && email.includes('@')) { currentUserEmail = email; return; }
  }
  // Method 3: data-hovercard-id containing @
  const hoverEls = document.querySelectorAll('[data-hovercard-id]');
  for (const el of hoverEls) {
    const v = el.getAttribute('data-hovercard-id') || '';
    if (v.includes('@')) { currentUserEmail = v; return; }
  }
  // Method 4: title/document.title
  const titleMatch = document.title.match(/([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})/);
  if (titleMatch) { currentUserEmail = titleMatch[1]; return; }
  // Method 5: profile images often have email in src/alt
  const profileImgs = document.querySelectorAll('img[alt*="@"]');
  for (const img of profileImgs) {
    const alt = img.getAttribute('alt') || '';
    const m = alt.match(/([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})/);
    if (m) { currentUserEmail = m[1]; return; }
  }
}

// ─── Extract Gmail message ID from DOM ────────────────────────────────────

function extractMessageId() {
  // Pattern 1: new Gmail alphanumeric IDs in URL hash
  const hashMatch = window.location.hash.match(/#[^/]+\/([A-Za-z0-9]{8,})(?:[?#]|$)/);
  if (hashMatch) return hashMatch[1];
  // Pattern 2: data-message-id attribute
  const msgEl = document.querySelector('[data-message-id]');
  if (msgEl) return msgEl.getAttribute('data-message-id');
  // Pattern 3: data-legacy-message-id
  const legacyEl = document.querySelector('[data-legacy-message-id]');
  if (legacyEl) return legacyEl.getAttribute('data-legacy-message-id');
  // Pattern 4: jslog attribute on email containers sometimes has msgid
  return null;
}

// ─── Extract email metadata from DOM ──────────────────────────────────────

function extractEmailMeta() {
  const meta = {
    subject: '',
    sender: '',
    sender_email: '',
    body_preview: '',
    message_id: currentMessageId || ''
  };

  // Subject
  const subjectEl = document.querySelector('h2.hP');
  if (subjectEl) meta.subject = subjectEl.textContent.trim();

  // Sender
  const fromEl = document.querySelector('span.gD');
  if (fromEl) {
    meta.sender = fromEl.getAttribute('name') || fromEl.textContent.trim();
    meta.sender_email = fromEl.getAttribute('email') || '';
  }

  // Body preview (first 500 chars of visible text)
  const bodyEl = document.querySelector('div.a3s.aiL');
  if (bodyEl) meta.body_preview = bodyEl.innerText.substring(0, 500);

  return meta;
}

// ─── Mount sidebar into DOM ────────────────────────────────────────────────

function mountSidebar() {
  if (sidebarMounted) return;
  sidebarMounted = true;

  // Toggle button
  const toggle = document.createElement('button');
  toggle.id = 'helios-toggle';
  toggle.title = 'Helios Phish Reporter';
  toggle.innerHTML = `
    <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
      <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/>
    </svg>`;
  toggle.addEventListener('click', toggleSidebar);
  document.body.appendChild(toggle);

  // Sidebar
  const sidebar = document.createElement('div');
  sidebar.id = 'helios-sidebar';
  sidebar.innerHTML = `
    <div id="helios-header">
      <img src="${chrome.runtime.getURL('icons/icon48.png')}" alt="Helios"/>
      <div id="helios-header-text">
        <div id="helios-header-title">Helios Phish Reporter</div>
        <div id="helios-header-sub">Himaya Technologies</div>
      </div>
      <button id="helios-close" title="Close">✕</button>
    </div>
    <div id="helios-body">
      <div class="helios-section-title">Report Suspicious Email</div>
      <div class="helios-description">
        If this email appears to be a phishing attempt, social engineering, or business email compromise, submit it for analysis. It will be escalated to your security team immediately.
      </div>
      <button class="helios-btn-report" id="helios-report-btn" disabled onclick="window._heliosReport()">
        Report as Phishing
      </button>
      <div class="helios-status" id="helios-status"></div>
    </div>
    <div id="helios-footer">
      Helios by <a href="https://app.himaya.ai" target="_blank">Himaya Technologies</a>
    </div>`;

  document.body.appendChild(sidebar);

  document.getElementById('helios-close').addEventListener('click', closeSidebar);

  // Expose report function globally (used by inline onclick)
  window._heliosReport = reportPhishing;
}

// ─── Sidebar open/close ────────────────────────────────────────────────────

function toggleSidebar() {
  const sidebar = document.getElementById('helios-sidebar');
  const toggle = document.getElementById('helios-toggle');
  if (!sidebar) return;

  const isOpen = sidebar.classList.contains('helios-visible');
  if (isOpen) {
    closeSidebar();
  } else {
    openSidebar();
  }
}

function openSidebar() {
  const sidebar = document.getElementById('helios-sidebar');
  const toggle = document.getElementById('helios-toggle');
  sidebar.classList.add('helios-visible');
  toggle.classList.add('helios-open');
  refreshSidebarState();
}

function closeSidebar() {
  const sidebar = document.getElementById('helios-sidebar');
  const toggle = document.getElementById('helios-toggle');
  sidebar.classList.remove('helios-visible');
  toggle.classList.remove('helios-open');
}

// ─── Refresh sidebar button state based on current email ──────────────────

function refreshSidebarState() {
  const btn = document.getElementById('helios-report-btn');
  const status = document.getElementById('helios-status');
  if (!btn) return;

  currentMessageId = extractMessageId();

  if (!currentMessageId) {
    btn.disabled = true;
    btn.textContent = 'Report as Phishing';
    btn.className = 'helios-btn-report';
    if (status) { status.className = 'helios-status helios-warning'; status.textContent = 'Open an email to report it.'; }
    return;
  }

  // Reset to ready state
  btn.disabled = false;
  btn.textContent = 'Report as Phishing';
  btn.className = 'helios-btn-report';
  if (status) { status.className = 'helios-status'; status.style.display = 'none'; }
}

// ─── Report phishing ───────────────────────────────────────────────────────

async function reportPhishing() {
  const btn = document.getElementById('helios-report-btn');
  const statusEl = document.getElementById('helios-status');

  btn.disabled = true;
  btn.textContent = 'Submitting...';
  statusEl.className = 'helios-status';
  statusEl.style.display = 'none';

  // Re-extract in case email changed
  if (!currentUserEmail) extractUserEmail();
  currentMessageId = extractMessageId();

  if (!currentMessageId) {
    showStatus('error', 'Could not identify the email. Please open the email and try again.');
    btn.disabled = false;
    btn.textContent = 'Report as Phishing';
    return;
  }

  // Get org key from storage (set by admin via popup)
  const keyResult = await chrome.runtime.sendMessage({ type: 'GET_ORG_KEY' });

  if (!keyResult.key) {
    showStatus('error', 'Extension not configured. Ask your IT admin for the Helios organization key.');
    btn.disabled = false;
    btn.textContent = 'Report as Phishing';
    return;
  }

  const meta = extractEmailMeta();

  try {
    const res = await fetch(`${HELIOS_API}/api/phish-report/submit`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Phish-Report-Key': keyResult.key
      },
      body: JSON.stringify({
        reporter_email: currentUserEmail || '',
        subject: meta.subject,
        sender: meta.sender,
        sender_email: meta.sender_email,
        sender_domain: meta.sender_email.includes('@') ? meta.sender_email.split('@').pop() : '',
        body_preview: meta.body_preview,
        message_id: currentMessageId,
        received_at: new Date().toISOString(),
        provider: 'gmail'
      })
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}`);

    btn.textContent = 'Reported';
    btn.className = 'helios-btn-report helios-success';
    showStatus('success', 'Report submitted. Your security team has been notified and the email is under investigation.');
  } catch (e) {
    showStatus('error', `Submission failed${e.message ? ' (' + e.message + ')' : ''}. Please try again or contact your IT administrator.`);
    btn.disabled = false;
    btn.textContent = 'Report as Phishing';
    btn.className = 'helios-btn-report';
  }
}

function showStatus(type, message) {
  const el = document.getElementById('helios-status');
  if (!el) return;
  el.className = `helios-status helios-${type}`;
  el.textContent = message;
}

// ─── Observe Gmail navigation (SPA — URL changes without page reload) ──────

function observeGmailNavigation() {
  let lastUrl = window.location.href;

  // Gmail is a SPA — watch for URL/hash changes
  const observer = new MutationObserver(() => {
    if (window.location.href !== lastUrl) {
      lastUrl = window.location.href;
      currentMessageId = extractMessageId();

      const sidebar = document.getElementById('helios-sidebar');
      if (sidebar && sidebar.classList.contains('helios-visible')) {
        refreshSidebarState();
      }
    }
  });

  observer.observe(document.body, { childList: true, subtree: true });

  // Also handle hashchange
  window.addEventListener('hashchange', () => {
    currentMessageId = extractMessageId();
    const sidebar = document.getElementById('helios-sidebar');
    if (sidebar && sidebar.classList.contains('helios-visible')) {
      refreshSidebarState();
    }
  });
}

// ─── Start ─────────────────────────────────────────────────────────────────

// Retry logic — Gmail is a slow SPA
let _initDone = false;
function _tryInit() {
  if (_initDone) return;
  init();
  _initDone = true;
}

// Handle PING from popup to check if content script is alive
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'PING') {
    sendResponse({ ok: true, email: currentUserEmail || null });
    return true;
  }
});

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => setTimeout(_tryInit, 1500));
} else {
  setTimeout(_tryInit, 1500);
}
setTimeout(_tryInit, 3000);
setTimeout(_tryInit, 6000);
