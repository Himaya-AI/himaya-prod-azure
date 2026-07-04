# Microsoft 365 Setup Guide

## Azure App Registration Steps

1. Go to portal.azure.com → Azure Active Directory → App Registrations → New Registration
2. Name: "Sentinel Mail"
3. Supported account types: "Accounts in any organizational directory"
4. Redirect URI: https://your-domain.com/api/onboarding/callback/m365
5. Go to API Permissions → Add permission → Microsoft Graph → Delegated:
   - Mail.Read
   - Mail.ReadWrite
   - MailboxSettings.Read
   - User.Read.All
   - Directory.Read.All
   - offline_access
6. Grant admin consent
7. Go to Certificates & Secrets → New client secret → copy value
8. Copy Application (client) ID and Directory (tenant) ID

## Environment Variables to set:
```
M365_CLIENT_ID=<Application ID>
M365_CLIENT_SECRET=<Client Secret>
M365_TENANT_ID=common (or specific tenant ID)
M365_REDIRECT_URI=https://your-domain.com/api/onboarding/callback/m365
```

## Token Encryption
Sentinel Mail encrypts all OAuth tokens at rest using Fernet symmetric encryption.
Set `ENCRYPTION_KEY` to a Fernet key (generate with `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`).
If not set, a key is auto-generated (tokens will be unreadable after restart — set a persistent key in production).
