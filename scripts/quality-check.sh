#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Helios Deployment Quality Check
# Run after every deploy to catch regressions before the user does.
# Usage: ./scripts/quality-check.sh
# Exit code 0 = all green, 1 = failures found
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

API="https://app.himaya.ai"
PASS=0
FAIL=0
WARNS=0

green() { echo "  ✅ $1"; }
red()   { echo "  ❌ $1"; FAIL=$((FAIL+1)); }
warn()  { echo "  ⚠️  $1"; WARNS=$((WARNS+1)); }

echo ""
echo "━━━ Helios Quality Check ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── 1. API health ─────────────────────────────────────────────────────────────
echo "1. API Health"
STATUS=$(curl -so /dev/null -w "%{http_code}" --max-time 10 "$API/health" 2>/dev/null || echo "000")
if [ "$STATUS" = "200" ]; then green "API reachable ($API)"; PASS=$((PASS+1))
else red "API health check failed (HTTP $STATUS)"; fi

# ── 2. Auth ───────────────────────────────────────────────────────────────────
echo ""
echo "2. Authentication"
LOGIN=$(curl -s --max-time 10 -X POST "$API/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"${ADMIN_EMAIL:-adnan@himaya.ai}\",\"password\":\"${ADMIN_PASSWORD:?Set ADMIN_PASSWORD}\"}" 2>/dev/null)
TOKEN=$(echo "$LOGIN" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || echo "")
if [ -n "$TOKEN" ] && [ "$TOKEN" != "None" ]; then
  green "Login OK — JWT issued"
  PASS=$((PASS+1))
else
  red "Login failed — no token returned"
  echo "  Aborting remaining checks (no auth token)"
  echo ""
  echo "━━━ Result: $FAIL failure(s), $WARNS warning(s) ━━━━━━━━━━━━━━━━━━━━━━━"
  exit 1
fi

# Helper
api_get() { curl -s --max-time 10 "$API$1" -H "Authorization: Bearer $TOKEN" 2>/dev/null; }
api_status() { curl -so /dev/null -w "%{http_code}" --max-time 10 "$API$1" -H "Authorization: Bearer $TOKEN" 2>/dev/null; }

# ── 3. Core API endpoints ─────────────────────────────────────────────────────
echo ""
echo "3. Core Endpoints"

endpoints=(
  "/api/dashboard/summary"
  "/api/threats?limit=5"
  "/api/threats/auto-triage/status"
  "/api/policies"
  "/api/quarantine"
  "/api/people"
  "/api/compliance/overview"
  "/api/settings/org"
  "/api/phish-report/key"
  "/api/message-trace?limit=5"
)

for ep in "${endpoints[@]}"; do
  s=$(api_status "$ep")
  if [ "$s" = "200" ]; then green "$ep"; PASS=$((PASS+1))
  else red "$ep (HTTP $s)"; fi
done

# ── 4. Auto-triage state ──────────────────────────────────────────────────────
echo ""
echo "4. Auto-Triage"
AT=$(api_get "/api/threats/auto-triage/status")
AT_ENABLED=$(echo "$AT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('enabled','?'))" 2>/dev/null)
AT_RUNNING=$(echo "$AT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('running','?'))" 2>/dev/null)

if [ "$AT_ENABLED" = "True" ] && [ "$AT_RUNNING" = "True" ]; then
  green "Auto-triage enabled=True running=True"
  PASS=$((PASS+1))
elif [ "$AT_ENABLED" = "True" ] && [ "$AT_RUNNING" = "False" ]; then
  red "Auto-triage ENABLED but NOT RUNNING — loop died"
elif [ "$AT_ENABLED" = "False" ]; then
  warn "Auto-triage disabled (user may have turned it off)"
else
  warn "Auto-triage state unknown: enabled=$AT_ENABLED running=$AT_RUNNING"
fi

# ── 5. Outlook add-in ─────────────────────────────────────────────────────────
echo ""
echo "5. Outlook Add-in"

PHISH_KEY=$(api_get "/api/phish-report/key" | python3 -c "import sys,json; print(json.load(sys.stdin).get('key',''))" 2>/dev/null)

# Taskpane HTML served from API domain
TP_STATUS=$(curl -so /dev/null -w "%{http_code}" --max-time 10 "$API/addons/outlook/taskpane.html" 2>/dev/null)
if [ "$TP_STATUS" = "200" ]; then green "Taskpane HTML reachable ($API/addons/outlook/taskpane.html)"; PASS=$((PASS+1))
else red "Taskpane HTML not reachable (HTTP $TP_STATUS)"; fi

# Manifest XML
if [ -n "$PHISH_KEY" ]; then
  MF_STATUS=$(curl -so /dev/null -w "%{http_code}" --max-time 10 "$API/api/phish-report/manifest.xml?key=$PHISH_KEY" 2>/dev/null)
  if [ "$MF_STATUS" = "200" ]; then
    # Validate manifest has correct elements
    MF_XML=$(curl -s --max-time 10 "$API/api/phish-report/manifest.xml?key=$PHISH_KEY" 2>/dev/null)
    HAS_TASKPANE=$(echo "$MF_XML" | grep -c "taskpane.html" || true)
    HAS_SIZE=$(echo "$MF_XML" | grep -c 'size="' || true)
    if [ "$HAS_TASKPANE" -ge 1 ] && [ "$HAS_SIZE" -ge 1 ]; then
      green "Manifest XML valid (taskpane URL present, icon sizes present)"; PASS=$((PASS+1))
    else
      red "Manifest XML missing taskpane URL or icon sizes"
    fi
  else
    red "Manifest XML not reachable (HTTP $MF_STATUS)"
  fi
  # Icon URLs
  for icon in himaya-3-16.png himaya-3-32.png himaya-3-80.png; do
    IS=$(curl -so /dev/null -w "%{http_code}" --max-time 5 "$API/$icon" 2>/dev/null)
    if [ "$IS" = "200" ]; then green "Icon $icon OK"; PASS=$((PASS+1))
    else red "Icon $icon missing (HTTP $IS)"; fi
  done
else
  warn "No phish report key found — skipping manifest checks"
fi

# ── 6. Dashboard summary sanity ───────────────────────────────────────────────
echo ""
echo "6. Data Sanity"
SUMMARY=$(api_get "/api/dashboard/summary")
SCANNED=$(echo "$SUMMARY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('emails_scanned',0))" 2>/dev/null)
if [ "${SCANNED:-0}" -gt 0 ] 2>/dev/null; then
  green "emails_scanned=$SCANNED (data is live)"
  PASS=$((PASS+1))
else
  warn "emails_scanned=0 — no data or DB issue"
fi

# ── 7. Neo4j graph scoring ────────────────────────────────────────────────────
echo ""
echo "7. Neo4j / Graph Scoring"
THREATS=$(api_get "/api/threats?limit=20")
HAS_REAL_GRAPH=$(echo "$THREATS" | python3 -c "
import sys,json
data=json.load(sys.stdin)
threats = data if isinstance(data,list) else data.get('threats', data.get('items',[]))
non_fallback = [t for t in threats if t.get('graph_score') not in (None, 35)]
print(len(non_fallback))
" 2>/dev/null || echo "0")
if [ "${HAS_REAL_GRAPH:-0}" -gt 0 ] 2>/dev/null; then
  green "Neo4j live — $HAS_REAL_GRAPH recent threats have real graph scores"
  PASS=$((PASS+1))
else
  warn "All recent graph scores are 35 (fallback) or None — Neo4j may be down"
fi

# ── 8. M365 delta-sync (inbox-only check) ────────────────────────────────────
echo ""
echo "8. M365 Delta-Sync"
ONBOARDING=$(api_get "/api/onboarding/status")
M365_CONNECTED=$(echo "$ONBOARDING" | python3 -c "
import sys,json
d=json.load(sys.stdin)
steps = d.get('steps',[]) if isinstance(d,dict) else []
email_step = next((s for s in steps if s.get('id')=='connect_email'), None)
print('yes' if email_step and email_step.get('complete') else 'no')
" 2>/dev/null || echo "unknown")
if [ "$M365_CONNECTED" = "yes" ]; then
  green "M365 integration connected"
  PASS=$((PASS+1))
else
  warn "M365 integration status unknown or not connected"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
TOTAL=$((PASS+FAIL))
echo "  Passed:   $PASS / $TOTAL"
echo "  Failed:   $FAIL"
echo "  Warnings: $WARNS"
echo ""

if [ "$FAIL" -gt 0 ]; then
  echo "  🔴 QUALITY CHECK FAILED — $FAIL issue(s) need attention"
  echo ""
  exit 1
else
  echo "  🟢 ALL CHECKS PASSED"
  echo ""
  exit 0
fi
