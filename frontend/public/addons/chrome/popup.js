// popup.js

const HELIOS_API = 'https://app.himaya.ai';

document.addEventListener('DOMContentLoaded', async () => {
  const dot = document.getElementById('status-dot');
  const statusText = document.getElementById('status-text');
  const input = document.getElementById('org-key-input');
  const saveBtn = document.getElementById('save-btn');
  const msg = document.getElementById('msg');

  // Load saved org key
  const result = await chrome.runtime.sendMessage({ type: 'GET_ORG_KEY' });
  if (result.key) {
    input.value = result.key;
    checkStatus(result.key, dot, statusText);
  } else {
    dot.className = 'dot error';
    statusText.textContent = 'Not configured';
  }

  saveBtn.addEventListener('click', async () => {
    const key = input.value.trim();
    if (!key) {
      showMsg('error', 'Please enter your organization key.');
      return;
    }

    saveBtn.textContent = 'Saving...';
    saveBtn.disabled = true;

    // Validate key with backend
    try {
      const res = await fetch(`${HELIOS_API}/api/phish-report/validate-key`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key })
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();

      if (data.valid) {
        await chrome.runtime.sendMessage({ type: 'SET_ORG_KEY', key });
        dot.className = 'dot active';
        statusText.textContent = `Connected — ${data.org_name || 'Organization'}`;
        showMsg('success', 'Key saved. Extension is active.');
      } else {
        dot.className = 'dot error';
        statusText.textContent = 'Invalid key';
        showMsg('error', 'Invalid key. Please check with your IT administrator.');
      }
    } catch (e) {
      showMsg('error', `Could not validate key: ${e.message}`);
    }

    saveBtn.textContent = 'Save Key';
    saveBtn.disabled = false;
  });
});

async function checkStatus(key, dot, statusText) {
  try {
    const res = await fetch(`${HELIOS_API}/api/phish-report/validate-key`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key })
    });
    if (!res.ok) throw new Error();
    const data = await res.json();
    if (data.valid) {
      dot.className = 'dot active';
      statusText.textContent = `Connected — ${data.org_name || 'Organization'}`;
    } else {
      dot.className = 'dot error';
      statusText.textContent = 'Invalid key';
    }
  } catch {
    dot.className = 'dot error';
    statusText.textContent = 'Connection error';
  }
}

function showMsg(type, text) {
  const el = document.getElementById('msg');
  el.className = `msg ${type}`;
  el.textContent = text;
}

// Check if current tab is Gmail and if content script is loaded
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const tab = tabs[0];
  if (!tab || !tab.url || !tab.url.includes('mail.google.com')) return;
  const row = document.getElementById('gmail-status-row');
  const dot = document.getElementById('gmail-dot');
  const text = document.getElementById('gmail-status-text');
  if (row) row.style.display = 'flex';
  chrome.tabs.sendMessage(tab.id, { type: 'PING' }, (response) => {
    if (chrome.runtime.lastError || !response) {
      if (dot) dot.className = 'dot error';
      if (text) text.textContent = 'Sidebar not loaded — reload Gmail tab';
    } else {
      if (dot) dot.className = 'dot active';
      if (text) text.textContent = response.email ? `Active — ${response.email}` : 'Sidebar active';
    }
  });
});
