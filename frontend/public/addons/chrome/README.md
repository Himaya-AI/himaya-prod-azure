# Helios Chrome Extension — Phish Reporter

Gmail sidebar for reporting suspicious emails. Matches the Outlook Add-in flow exactly.

## Files

```
manifest.json     Chrome extension manifest (MV3)
content.js        Injected into Gmail — mounts sidebar, handles reporting
sidebar.css       Sidebar styles (injected alongside content.js)
background.js     Service worker — stores org key
popup.html/js     Extension icon popup — admin enters org key here
icons/            16/48/128px icons (copy from Himaya assets)
```

## How It Works

1. Extension injects a sidebar toggle button into Gmail
2. User clicks the shield icon → sidebar slides open
3. User clicks "Report as Phishing" → submits to `/api/phish-report/submit`
4. Auth: `X-Phish-Report-Key` header (same key as Outlook add-in, same endpoint)
5. Threat is created in Helios, security team notified

## Setup Per Customer

### You (Himaya ops):
1. Get the org's `phish_report_key` from Helios admin panel (Settings → Integrations → Report Key)
2. Send the key to the customer's IT admin along with the `.crx` / extension ID

### Customer's IT Admin:
1. Open Chrome extension popup → enter the org key → Save
   OR — for enterprise rollout, pre-configure via Chrome policy:
   ```json
   {
     "3rdparty": {
       "extensions": {
         "<extension-id>": {
           "helios_org_key": "<key>"
         }
       }
     }
   }
   ```
2. Force-install via Google Admin Console:
   `Devices → Chrome → Apps & Extensions → Add → By Chrome Web Store ID`
   Set: **Force install** for all users or specific OUs

### Loading in Dev (unpacked):
1. `chrome://extensions` → Enable Developer Mode → Load unpacked → select this folder
2. Add icons (copy `himaya-3-16.png`, `himaya-3-32.png`, `himaya-3-80.png` → rename to `icon16/48/128.png`)
3. Open Gmail → shield icon should appear on right edge

## Backend Endpoints Used

| Endpoint | Purpose |
|---|---|
| `POST /api/phish-report/submit` | Submit the phishing report (key auth) |
| `POST /api/phish-report/validate-key` | Popup key validation |

Both already exist in `backend/routers/phish_report.py`.

## Publishing for Enterprise Rollout (no Marketplace needed)

Option A — Chrome Web Store (Unlisted):
- Upload the extension zip to Chrome Web Store
- Set visibility: **Unlisted** (not searchable)
- Share the install link with customers
- Admin force-installs via Admin Console using the extension ID

Option B — Self-hosted CRX:
- Build and sign the `.crx` file
- Host it on `app.himaya.ai/addons/chrome/helios-phish-reporter.crx`
- Push via Chrome Enterprise policy
