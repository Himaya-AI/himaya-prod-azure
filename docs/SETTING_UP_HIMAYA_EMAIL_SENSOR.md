---
title: Setting up Himaya Email Sensor
description: Connect Microsoft 365 (Outlook) and Google Workspace (Gmail) mailboxes to the Himaya Email Threat Engine for inline scanning, quarantine, and hard-capture.
---

# Setting up Himaya Email Sensor

The **Himaya Email Sensor** connects to your organization's mailboxes and continuously
ingests mail so the Email Threat Engine can:

- **Scan** every inbound message (reputation, graph history, content, URL detonation, attachment analysis).
- **Auto-triage** threats through the LLM verdict engine (Bedrock Kimi K2.5) and apply a verdict.
- **Quarantine** malicious mail into a **hidden** provider folder/label (out of the user's inbox).
- **Hard-capture** high-risk mail — pull the raw message *out of the mailbox entirely* (encrypted at rest in Himaya, original permanently removed), and reinject it only on release.

The sensor runs **app-only** (no per-user sign-in): a **Google service account with Domain-Wide Delegation** for Gmail, and a **Microsoft Entra ID application with Graph Application permissions** for Outlook/M365. This means once an administrator authorizes the sensor, it protects every mailbox in the tenant without individual user consent.

> **Two setups, one sensor.** Complete the section for each mail platform you use. You can run both simultaneously (mixed Gmail + Outlook orgs are fully supported).

---

## Capability &rarr; permission matrix

Each Himaya capability maps to a specific provider permission. Grant the full set to enable hard-capture (the strongest containment).

| Capability | Gmail (Google Workspace) | Outlook (Microsoft 365) |
|---|---|---|
| Read mail for scanning | `https://www.googleapis.com/auth/gmail.readonly` *(or `gmail.modify`)* | `Mail.Read` *(or `Mail.ReadWrite`)* |
| Enumerate mailboxes / users | `.../auth/admin.directory.user.readonly` | `User.Read.All`, `Directory.Read.All` |
| Quarantine to hidden folder/label | `.../auth/gmail.modify` | `Mail.ReadWrite` |
| Posture (filters / forwarding checks) | `.../auth/gmail.settings.basic`, `.../auth/admin.directory.user.security` | `MailboxSettings.Read` |
| **Hard-capture (permanent removal)** | **`https://mail.google.com/`** | **`Mail.ReadWrite`** |

> **Key difference:** Gmail requires the broad **`https://mail.google.com/`** scope for permanent delete (`users.messages.delete`) — `gmail.modify` only allows *trash* (recoverable). Microsoft Graph has **no separate delete permission**: `Mail.ReadWrite` already authorizes move + delete, so if quarantine works, hard-capture works.

---

## Section 1 — Outlook / Microsoft 365

The M365 sensor authenticates with the **OAuth 2.0 client-credentials** flow (app-only) against Microsoft Graph.

### 1.1 Register the application

1. Go to **[portal.azure.com](https://portal.azure.com)** &rarr; **Microsoft Entra ID** &rarr; **App registrations** &rarr; **New registration**.
2. **Name:** `Himaya Email Sensor`.
3. **Supported account types:** *Accounts in this organizational directory only* (single tenant) is recommended for a sensor.
4. Leave Redirect URI blank (app-only does not need one). Click **Register**.
5. From the **Overview** page, copy the **Application (client) ID** and **Directory (tenant) ID**.

### 1.2 Grant Microsoft Graph **Application** permissions

1. Open the app &rarr; **API permissions** &rarr; **Add a permission** &rarr; **Microsoft Graph** &rarr; **Application permissions**.
2. Add:
   - **`Mail.ReadWrite`** — read, quarantine (create/hide folder + move), and **hard-capture** (move to Deleted Items + purge).
   - **`MailboxSettings.Read`** — posture checks (forwarding rules, delegates).
   - **`User.Read.All`** — enumerate mailboxes.
   - **`Directory.Read.All`** — org/group structure.
3. Click **Grant admin consent for &lt;tenant&gt;**. Every permission must show a green **Granted** check.

> **Application vs Delegated:** the sensor is app-only, so you must add **Application** permissions (not Delegated). Delegated permissions will not work for background scanning.

### 1.3 Create a client secret

1. **Certificates & secrets** &rarr; **New client secret** &rarr; set an expiry (e.g. 24 months) &rarr; **Add**.
2. Copy the secret **Value** immediately (it is shown only once).

### 1.4 (Recommended) Restrict to specific mailboxes — least privilege

`Mail.ReadWrite` (Application) grants access to **all** mailboxes tenant-wide. To scope the sensor to only the mailboxes you protect, create an **Application Access Policy** in Exchange Online PowerShell:

```powershell
# Connect first: Connect-ExchangeOnline
New-ApplicationAccessPolicy `
  -AppId <APPLICATION_CLIENT_ID> `
  -PolicyScopeGroupId himaya-protected@yourtenant.onmicrosoft.com `
  -AccessRight RestrictAccess `
  -Description "Himaya Email Sensor — restrict to protected mailboxes"

# Verify it resolves correctly for a user:
Test-ApplicationAccessPolicy -AppId <APPLICATION_CLIENT_ID> -Identity user@yourtenant.onmicrosoft.com
```

### 1.5 Configure the sensor

Provide these to Himaya (environment / secrets):

```
M365_CLIENT_ID=<Application (client) ID>
M365_CLIENT_SECRET=<Client secret value>
M365_TENANT_ID=<Directory (tenant) ID>   # e.g. yourtenant.onmicrosoft.com
```

### 1.6 Validate

- In the Himaya dashboard, the M365 connector shows **Connected** and a mailbox count.
- Send a test message to a protected mailbox; within a few minutes it appears in **Threats** (or is scored clean).
- Confirm the hidden quarantine folder exists via Graph:
  ```
  GET /users/{email}/mailFolders?includeHiddenFolders=true
  # Look for "Himaya-Quarantine" with "isHidden": true
  ```
- **Hard-capture check:** after a message is quarantined at high risk, it is removed from the mailbox (not visible in OWA even with hidden folders shown) and a capture row is retained by Himaya for release.

---

## Section 2 — Gmail / Google Workspace

The Gmail sensor authenticates with a **Google service account** using **Domain-Wide Delegation (DWD)**, impersonating each mailbox for read/quarantine/capture.

### 2.1 Create the Google Cloud project & service account

1. Go to **[console.cloud.google.com](https://console.cloud.google.com)** &rarr; create a project (e.g. `himaya-helios`).
2. **APIs & Services** &rarr; **Enable APIs**: enable **Gmail API** and **Admin SDK API**.
3. **IAM & Admin** &rarr; **Service Accounts** &rarr; **Create service account** (e.g. `helios-service`).
4. Open the service account &rarr; **Keys** &rarr; **Add key** &rarr; **JSON**. Download the key file.
5. On the service account **Details** page, note the **Unique ID** (the numeric **Client ID**, e.g. `114733393163502940734`) — you need it for the DWD grant.

### 2.2 Authorize Domain-Wide Delegation (Admin console)

1. Go to **[admin.google.com](https://admin.google.com)** &rarr; **Security** &rarr; **Access and data control** &rarr; **API controls** &rarr; **Manage Domain-Wide Delegation**.
2. **Add new** &rarr; enter the service account **Client ID** from step 2.1.
3. Paste the **comma-separated** scope list:

   ```
   https://mail.google.com/,
   https://www.googleapis.com/auth/gmail.modify,
   https://www.googleapis.com/auth/gmail.settings.basic,
   https://www.googleapis.com/auth/admin.directory.user.readonly,
   https://www.googleapis.com/auth/admin.directory.user.security,
   https://www.googleapis.com/auth/admin.directory.group.readonly
   ```
4. Click **Authorize**.

> **`https://mail.google.com/` is required for hard-capture** (permanent delete). Without it, Gmail quarantine falls back to a hidden label the user can un-hide — the message is never fully removed.

> **DWD is all-or-nothing.** The scopes the sensor requests at runtime must *all* be present in this grant. If you add a scope in the sensor but not in the Admin grant (or vice-versa), **every** Gmail token request fails with `unauthorized_client`. Always update the Admin grant **before** enabling a new scope in the sensor.

### 2.3 Configure the sensor

Base64-encode the downloaded JSON key and provide it to Himaya:

```bash
base64 -i service-account.json | tr -d '\n'
```

```
GOOGLE_SERVICE_ACCOUNT_B64=<base64 of the service-account JSON key>
```

### 2.4 Validate

- In the Himaya dashboard, the Google connector shows **Connected** and the synced mailbox count.
- In backend logs you should see healthy delta polling with **no** `unauthorized_client` / `invalid_scope` errors, e.g.:
  ```
  Google delta: stamped mailbox_count=N for org ...
  Gmail delta: 0 messages for user@yourdomain.com (since epoch ...)
  ```
- **Hidden label check (as the mailbox owner):** the `Himaya-Quarantine` label does **not** appear in the Gmail sidebar; in **Settings &rarr; Labels** it shows **Hide / Hide**. Search `label:Himaya-Quarantine` to view held mail.
- **Hard-capture check:** after a high-risk message is quarantined, it is gone from **All Mail** entirely (nothing left to un-hide), and Himaya retains an encrypted capture for release.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| All Gmail calls return `unauthorized_client` / `invalid_scope` | Sensor requests a scope not in the DWD grant (all-or-nothing) | Add the exact scope in **Admin &rarr; Domain-Wide Delegation**, then retry |
| Gmail `429 Too Many Requests` | Per-user Gmail API quota from concurrent calls | Transient — the sensor retries next cycle; reduce concurrent posture scans if persistent |
| M365 `ErrorAccessDenied` on delete but move works | Application Access Policy scoping excludes the mailbox | Add the mailbox to the policy group, or verify with `Test-ApplicationAccessPolicy` |
| Malicious test email never scanned | Provider spam filter routed it to **Junk/Spam** (not scanned by default) | Use a well-authenticated (SPF/DKIM) sender for tests, or enable Spam/Junk scanning |
| Quarantined mail not visible in Himaya UI | Filter/state mismatch | Ensure the **Quarantine** tab **Unresolved** view is selected and refresh |

---

## Security notes

- **Encryption at rest:** all OAuth tokens and hard-captured MIME are encrypted with **Fernet** before storage. Set a persistent `ENCRYPTION_KEY` in production (generate with `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`).
- **Least privilege:** prefer an **Application Access Policy** (M365) and only the scopes you need (Gmail). Add `https://mail.google.com/` / rely on `Mail.ReadWrite` **only** if hard-capture is required.
- **Reversibility:** quarantine (hidden folder/label) and hard-capture are both **recoverable** — release reinjects the original message into the user's inbox.
