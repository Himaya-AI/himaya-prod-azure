# Helios Gmail Add-on — GCP Deployment Guide

This covers deploying the Helios Phish Reporter as a private Gmail Add-on via Google Cloud Platform for production use within your Google Workspace org.

---

## Private vs. Public — Which to Use?

| | Private (Domain-Restricted) | Public (Marketplace) |
|---|---|---|
| **Who can install** | Only your Google Workspace org | Anyone |
| **Review required** | ❌ No Google review | ✅ Google reviews (weeks) |
| **Setup time** | ~15 minutes | Days to weeks |
| **Best for** | **Production use within your org** | Selling to external customers |
| **Admin install** | ✅ Push to all users silently | ✅ |

**Recommendation: Use Private deployment for your own org (ajazlaw.com / himaya.ai). Use Public only when selling to external customers.**

---

## 1. Prerequisites

- Google Workspace admin account
- Google Cloud project (create one at console.cloud.google.com)
- Access to Google Apps Script

---

## 2. Create the Apps Script Project

1. Go to [script.google.com](https://script.google.com)
2. Click **New project**
3. Name it `Helios Phish Reporter`

### Paste the Code

In the script editor, replace the default `Code.gs` with:

```javascript
var HELIOS_API = 'https://app.himaya.ai';
var PHISH_REPORT_KEY = 'YOUR_PHISH_KEY_HERE';  // Get from Helios onboarding page

function onGmailMessageOpen(e) {
  var messageId = e.gmail.messageId;
  var accessToken = e.gmail.accessToken;
  GmailApp.setCurrentMessageAccessToken(accessToken);
  var card = CardService.newCardBuilder()
    .setName('Helios Phish Reporter')
    .setHeader(CardService.newCardHeader()
      .setTitle('Helios Security')
      .setSubtitle('AI-Powered Email Protection'))
    .addSection(CardService.newCardSection()
      .setHeader('Report this email')
      .addWidget(CardService.newTextParagraph()
        .setText('If this email looks suspicious, report it to your security team.'))
      .addWidget(CardService.newTextButton()
        .setText('🚨 Report as Phishing')
        .setBackgroundColor('#ef4444')
        .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
        .setOnClickAction(CardService.newAction()
          .setFunctionName('reportPhishing')
          .setParameters({'messageId': messageId, 'accessToken': accessToken}))))
    .build();
  return [card];
}

function reportPhishing(e) {
  var messageId = e.parameters.messageId;
  GmailApp.setCurrentMessageAccessToken(e.parameters.accessToken);
  var message = GmailApp.getMessageById(messageId);
  if (!message) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText('Could not access email.')).build();
  }
  var payload = {
    reporter_email: Session.getActiveUser().getEmail(),
    subject: message.getSubject(),
    sender: message.getFrom(),
    sender_domain: message.getFrom().includes('@') 
      ? message.getFrom().split('@').pop().replace('>', '').trim() 
      : '',
    body_preview: message.getPlainBody().substring(0, 500),
    message_id: messageId,
    received_at: message.getDate().toISOString(),
    provider: 'gmail'
  };
  var response = UrlFetchApp.fetch(HELIOS_API + '/api/phish-report/submit', {
    method: 'post',
    contentType: 'application/json',
    headers: { 'X-Phish-Report-Key': PHISH_REPORT_KEY },
    payload: JSON.stringify(payload),
    muteHttpExceptions: true
  });
  if (response.getResponseCode() === 200) {
    message.moveToTrash();
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification()
        .setText('✅ Reported! Helios is investigating.'))
      .setStateChanged(true).build();
  }
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification()
      .setText('❌ Report failed. Try again.')).build();
}
```

> **Get your PHISH_REPORT_KEY** from Helios → Onboarding → Employee Phish Report → Your Phish Report Key

---

## 3. Configure the Manifest (appsscript.json)

In the script editor:
1. Click **Project Settings** (gear icon) → **Show "appsscript.json" manifest file in editor**
2. Replace the full contents of `appsscript.json` with:

```json
{
  "timeZone": "UTC",
  "exceptionLogging": "STACKDRIVER",
  "runtimeVersion": "V8",
  "oauthScopes": [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/userinfo.email"
  ],
  "urlFetchWhitelist": [
    "https://app.himaya.ai/"
  ],
  "gmail": {
    "name": "Helios Phish Reporter",
    "logoUrl": "https://app.himaya.ai/himaya-3.png",
    "primaryColor": "#1a2744",
    "secondaryColor": "#3b6ef6",
    "contextualTriggers": [
      {
        "unconditional": {},
        "onTriggerFunction": "onGmailMessageOpen"
      }
    ]
  }
}
```

---

## 4. Link to a GCP Project

1. In script editor → **Project Settings** → **Google Cloud Platform (GCP) Project**
2. Click **Change project**
3. Enter your GCP project number (find it at console.cloud.google.com → select project → Dashboard → Project number)
4. Click **Set project**

---

## 5. Deploy as a Private Add-on

### Option A: Admin Push (Recommended — users don't need to install anything)

1. In the script editor → **Deploy** → **New deployment**
2. Click the gear icon next to "Select type" → choose **Add-on**
3. Fill in:
   - Description: `Helios Phish Reporter v1.0`
4. Click **Deploy**
5. Copy the **Deployment ID**

Now push it to your org:

1. Go to [Google Workspace Admin Console](https://admin.google.com)
2. **Apps** → **Google Workspace Marketplace apps** → **Apps list** → **Add app** → **Add custom app**

   OR navigate to:  
   **Apps** → **Additional Google services** → **Google Workspace Add-ons** (if available)

   The direct path for domain-restricted add-ons:
3. Go to [admin.google.com/ac/owl/list?tab=addOnApps](https://admin.google.com/ac/owl/list?tab=addOnApps)
4. Click **+** → **Add by Script ID**
5. Paste your Apps Script **project ID** (from script.google.com → Project Settings → Script ID)
6. Assign to: **Everyone** (or specific OUs)
7. Click **Save**

The add-on will silently appear in Gmail for all assigned users within a few minutes — no user action needed.

### Option B: Self-install (for testing, not recommended for org rollout)

1. Deploy as above to get a deployment ID
2. Share the add-on install link with users:
   `https://script.google.com/macros/d/<DEPLOYMENT_ID>/exec`
3. Users click "Install"

---

## 6. Making It Private (Domain-Restricted)

The add-on is already private by default when deployed this way — it's not listed on the Marketplace and requires your Script ID to install. No additional config needed.

If you want to **explicitly restrict** it so only your domain can install even if someone gets the Script ID:

1. In Google Cloud Console → **APIs & Services** → **OAuth consent screen**
2. Set **User type** to **Internal**
3. This limits OAuth scopes to your Workspace domain only

---

## 7. Per-Tenant Deployment (for external customers)

For each new customer org:

1. Get their org's **phish report key** from their Helios account (or via API: `GET /api/phish-report/key`)
2. Create a new Apps Script project (or fork the existing one)
3. Set `PHISH_REPORT_KEY` to their key
4. Deploy and push to their Google Workspace admin

Or use the **keyless endpoint** (`/api/phish-report/submit-keyless`) which resolves the tenant automatically by the reporter's email domain — no per-org key needed. Update the script:

```javascript
// Keyless version — resolves org by reporter's email domain automatically
var response = UrlFetchApp.fetch(HELIOS_API + '/api/phish-report/submit-keyless', {
  method: 'post',
  contentType: 'application/json',
  payload: JSON.stringify(payload),
  muteHttpExceptions: true
});
```

---

## 8. Testing

After deployment, open Gmail and open any email. You should see the Helios card appear in the right sidebar. Click **Report as Phishing** and check:

1. The Helios dashboard → Threats — a new threat should appear
2. The email should move to Trash in Gmail
3. Auto-triage should pick it up within 2 minutes and produce a verdict

**Check logs in GCP:**
- Go to [console.cloud.google.com](https://console.cloud.google.com)
- **Logging** → filter for your Apps Script project
- Or in Apps Script editor → **Executions** (shows each trigger invocation + errors)

---

## 9. Updating the Add-on

When you need to update the code (e.g. new API endpoint, new phish key):

1. Make changes in the script editor
2. **Deploy** → **Manage deployments** → click edit on your deployment → **New version**
3. Admin-pushed installs update automatically within a few hours
4. To force immediate update: re-push from Admin Console

---

## 10. Troubleshooting

| Problem | Fix |
|---|---|
| Card doesn't appear in Gmail | Check Executions tab for errors; verify `contextualTriggers` in appsscript.json |
| "Access denied" error | OAuth scopes may not be approved — re-authorize via Admin Console |
| `UrlFetchApp` blocked | Add `https://app.himaya.ai/` to `urlFetchWhitelist` in appsscript.json |
| Report submits but no threat appears | Check phish key is correct; test `POST /api/phish-report/submit` directly |
| "Script ID not found" in Admin Console | Use the Script ID from Project Settings, not the Deployment ID |
