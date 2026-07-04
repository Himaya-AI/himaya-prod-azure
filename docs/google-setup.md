# Google Workspace Setup Guide

## Google Cloud Console Steps

1. Go to console.cloud.google.com → Create Project "Sentinel Mail"
2. Enable APIs: Gmail API, Admin SDK Directory API
3. Go to OAuth Consent Screen → External → Fill details
4. Go to Credentials → Create OAuth 2.0 Client ID
5. Application type: Web Application
6. Authorized redirect URIs: https://your-domain.com/api/onboarding/callback/google
7. Copy Client ID and Client Secret

## Environment Variables:
```
GOOGLE_CLIENT_ID=<Client ID>
GOOGLE_CLIENT_SECRET=<Client Secret>
GOOGLE_REDIRECT_URI=https://your-domain.com/api/onboarding/callback/google
```

## Required OAuth Scopes
- `https://www.googleapis.com/auth/gmail.readonly` — Read emails for threat analysis
- `https://www.googleapis.com/auth/admin.directory.user.readonly` — List org users
- `https://www.googleapis.com/auth/gmail.modify` — Apply labels/actions on threats

## Token Encryption
All tokens are encrypted using Fernet before storing in the database.
Set `ENCRYPTION_KEY` env var for persistent encryption across restarts.
