// background.js — service worker
// Stores and provides the org's phish report key to the content script

const HELIOS_API = 'https://app.himaya.ai';
const ORG_KEY_STORAGE_KEY = 'helios_org_key';

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'GET_ORG_KEY') {
    chrome.storage.local.get([ORG_KEY_STORAGE_KEY], (result) => {
      sendResponse({ key: result[ORG_KEY_STORAGE_KEY] || null });
    });
    return true; // keep channel open for async
  }

  if (request.type === 'SET_ORG_KEY') {
    chrome.storage.local.set({ [ORG_KEY_STORAGE_KEY]: request.key }, () => {
      sendResponse({ ok: true });
    });
    return true;
  }
});
