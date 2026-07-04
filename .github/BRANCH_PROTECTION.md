# Branch Protection Setup

Configure these in GitHub → Settings → Branches.

## `main` branch (production)
- ✅ Require pull request before merging
- ✅ Required approvals: **2** (Adnan@himaya.ai + faraz@himaya.ai)
- ✅ Require status checks to pass: `backend-qa`, `frontend-qa`, `manifest-qa`, `production-readiness`
- ✅ Require branches to be up to date before merging
- ✅ Restrict who can push: only repo admins
- ✅ Do not allow bypassing the above settings

## `dev` branch (staging / dev work)
- ✅ Require pull request before merging
- ✅ Required approvals: **1**
- ✅ Require status checks to pass: `backend-qa`, `frontend-qa`, `manifest-qa`

## Secrets to add in GitHub → Settings → Secrets → Actions
```
AWS_ACCESS_KEY_ID         — IAM key for GitHub Actions deployer
AWS_SECRET_ACCESS_KEY     — IAM secret for GitHub Actions deployer
ANTHROPIC_API_KEY         — for CI tests that call Claude
OPENAI_API_KEY            — for CI tests with GPT-4o fallback
HELIOS_TEST_EMAIL         — test account email for production readiness tests
HELIOS_TEST_PASSWORD      — test account password
HELIOS_PHISH_KEY          — org phish key for manifest tests
```

## Workflow
1. All feature work → branch off `dev`
2. PR into `dev` → 1 approver + CI passes
3. PR from `dev` → `main` → 2 approvers (Adnan + Faraz) + all CI including production readiness tests
4. Merge to `main` → auto-deploy fires via deploy.yml
