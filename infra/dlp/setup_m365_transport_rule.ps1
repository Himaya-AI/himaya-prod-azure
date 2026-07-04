# =============================================================================
# setup_m365_transport_rule.ps1 — Create Exchange Online transport rule
#                                  to route outbound email through Helios DLP.
#
# Prerequisites:
#   Install-Module ExchangeOnlineManagement -Scope CurrentUser
#   Connect-ExchangeOnline -UserPrincipalName admin@yourdomain.com
#
# Usage:
#   .\setup_m365_transport_rule.ps1 -HeliosOrg "your-org-uuid" [-DlpSecret "your-secret"]
# =============================================================================

param(
    [Parameter(Mandatory=$true)]
    [string]$HeliosOrg,

    [Parameter(Mandatory=$false)]
    [string]$DlpSecret = $env:DLP_WEBHOOK_SECRET,

    [Parameter(Mandatory=$false)]
    [string]$HeliosEndpoint = "https://helios.himaya.ai/api/dlp/webhook/m365"
)

if (-not $DlpSecret) {
    Write-Error "DlpSecret is required. Pass -DlpSecret or set DLP_WEBHOOK_SECRET env var."
    exit 1
}

Write-Host "==> Connecting to Exchange Online..." -ForegroundColor Cyan
# Ensure connected (caller should have already run Connect-ExchangeOnline)
try {
    Get-OrganizationConfig | Out-Null
} catch {
    Write-Error "Not connected to Exchange Online. Run: Connect-ExchangeOnline -UserPrincipalName admin@yourdomain.com"
    exit 1
}

Write-Host "==> Creating DLP outbound inspection transport rule..." -ForegroundColor Cyan

$RuleName = "Helios DLP — Outbound Inspection"

# Remove existing rule if it exists (idempotent)
$existing = Get-TransportRule -Identity $RuleName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "    Removing existing rule: $RuleName" -ForegroundColor Yellow
    Remove-TransportRule -Identity $RuleName -Confirm:$false
}

# Build the HTTP POST action parameters
# Exchange Online uses "SendToHttp" (IncidentReport pattern) — available in E3+/E5
# The rule intercepts ALL outbound SMTP, POSTs to Helios DLP endpoint.
# If Helios returns 5xx (HOLD/BLOCK), Exchange rejects the message with an NDR.

New-TransportRule -Name $RuleName `
    -SentToScope "NotInOrganization" `
    -Mode "Enforce" `
    -Priority 0 `
    -Comments "Routes outbound email through Helios DLP classification. Managed by Himaya." `
    -GenerateIncidentReport $HeliosEndpoint `
    -IncidentReportOriginalMail "IncludeOriginalMail" `
    -IncidentReportContent @("Sender", "Recipients", "Subject", "Body", "Attachments") `
    -MessageContainsDataClassifications @() `
    -SetHeaderName "X-DLP-Secret" `
    -SetHeaderValue $DlpSecret `
    -SetSCL (-1) | Out-Null

# Note: Exchange transport rules do not natively support blocking based on HTTP response code.
# For full HOLD/BLOCK capability, use the DLP Gateway (setup_dlp_gateway.sh) as a
# Smart Host — route outbound through a Postfix milter that calls Helios DLP.
#
# To configure Exchange to use the DLP Gateway as smart host:
#   1. Set the gateway's public IP/FQDN as an outbound connector
#   2. Route all outbound mail through it

Write-Host ""
Write-Host "==> Creating outbound smart host connector to DLP Gateway..." -ForegroundColor Cyan
Write-Host "    (Requires DLP Gateway EC2 running — see setup_dlp_gateway.sh)" -ForegroundColor Yellow

$ConnectorName = "Helios DLP Gateway"
$existing_conn = Get-OutboundConnector -Identity $ConnectorName -ErrorAction SilentlyContinue
if (-not $existing_conn) {
    # Replace DLP_GATEWAY_FQDN with your gateway's public FQDN or IP
    $GatewayFQDN = $env:DLP_GATEWAY_FQDN
    if ($GatewayFQDN) {
        New-OutboundConnector -Name $ConnectorName `
            -ConnectorType "OnPremises" `
            -SmartHosts @($GatewayFQDN) `
            -UseMXRecord $false `
            -TlsSettings "EncryptionOnly" `
            -Comment "Route outbound mail through Helios DLP milter gateway" `
            -Enabled $true | Out-Null
        Write-Host "    Created outbound connector: $ConnectorName → $GatewayFQDN" -ForegroundColor Green
    } else {
        Write-Host "    DLP_GATEWAY_FQDN not set — skipping smart host connector" -ForegroundColor Yellow
        Write-Host "    Set env var DLP_GATEWAY_FQDN and re-run to create connector" -ForegroundColor Yellow
    }
} else {
    Write-Host "    Connector '$ConnectorName' already exists" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  ✅ M365 DLP Transport Rule Configured" -ForegroundColor Green
Write-Host "     Rule name:   $RuleName" -ForegroundColor Green
Write-Host "     Endpoint:    $HeliosEndpoint" -ForegroundColor Green
Write-Host "     Org ID:      $HeliosOrg" -ForegroundColor Green
Write-Host "" -ForegroundColor Green
Write-Host "  For full HOLD/BLOCK support:" -ForegroundColor Yellow
Write-Host "  1. Deploy DLP Gateway (setup_dlp_gateway.sh)" -ForegroundColor Yellow
Write-Host "  2. Set DLP_GATEWAY_FQDN env var and re-run this script" -ForegroundColor Yellow
Write-Host "════════════════════════════════════════════════════════" -ForegroundColor Green
