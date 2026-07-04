# Teams & SharePoint Security Features

## Current Features (Implemented)

### Teams Security
| Feature | Description | Graph API |
|---------|-------------|-----------|
| **Phishing URL Detection** | Scans Teams chat messages for phishing URLs with homograph detection | `/chats/{id}/messages` |
| **Guest Owner Detection** | Alerts when external users have Team owner privileges | `/groups/{id}/owners` |
| **External in Private Channel** | Detects external users in private channels | `/teams/{id}/channels/{id}/members` |
| **Webhook/Connector Abuse** | Monitors connector additions via audit logs | `/auditLogs/directoryAudits` |
| **File Scanning (via Teams)** | DLP classification of files shared in Teams | `/drives/{id}/items` |
| **Message Content Analysis** | Scans message content for sensitive data patterns | `/chats/{id}/messages` |

### SharePoint/OneDrive Security
| Feature | Description | Graph API |
|---------|-------------|-----------|
| **Anonymous Link Detection** | Alerts on anyone-with-link shares | `/auditLogs/directoryAudits` |
| **Site Admin Changes** | Monitors site collection admin modifications | `/auditLogs/directoryAudits` |
| **Competitor Domain Sharing** | Detects shares to competitor domains (configurable) | Database analysis |
| **Bulk File Access** | Detects data exfil patterns (30+ file accesses) | `/auditLogs/directoryAudits` |
| **Large File External Share** | Alerts on 100MB+ files in external folders | Database analysis |
| **Ransomware Patterns** | Detects mass encryption file extensions | `/auditLogs/directoryAudits` |
| **File Classification (DLP)** | AI-powered sensitive content detection | `/drives/{id}/items/{id}/content` |
| **Sensitivity Label Changes** | (Partial) Downgrade detection | Database analysis |

### Cross-Platform Security
| Feature | Description |
|---------|-------------|
| **Impossible Travel** | Detects logins from geographically impossible locations |
| **After-Hours Activity** | Flags activity outside business hours |
| **Suspicious Sign-ins** | Password spray, risky IP detection |
| **Shadow IT Detection** | Third-party app consent monitoring |
| **Entra Risky Users** | Identity Protection risk score integration |

---

## Proposed Enterprise Features (To Build)

### 🔥 High Priority (High Value + Leverages Existing Graph API)

#### 1. **Data Loss Prevention (DLP) Policy Enforcement**
- **What**: Create/enforce sensitivity labels, auto-classify documents, block external sharing of confidential files
- **Graph API**: `POST /informationProtection/sensitivityLabels/evaluate`, `PATCH /sites/{id}/permissions`
- **Value**: Core CISO requirement, direct competitor feature

#### 2. **Conditional Access Policy Monitoring**
- **What**: Real-time monitoring of CA policy triggers, blocked sign-ins, policy gaps
- **Graph API**: `/identity/conditionalAccess/policies`, `/auditLogs/signIns?$filter=conditionalAccessStatus`
- **Value**: Identity is #1 attack vector, CA visibility is table stakes

#### 3. **External User Lifecycle Management**
- **What**: Track all external users, last activity, access expiration, automated offboarding
- **Graph API**: `/users?$filter=userType eq 'Guest'`, `/auditLogs/signIns`
- **Value**: Guest sprawl is a major compliance risk

#### 4. **Meeting Security Intelligence**
- **What**: Detect anonymous join, lobby bypass, recording without consent, external presenter
- **Graph API**: `/communications/onlineMeetings`, `/communications/callRecords`
- **Value**: Zoom-bombing prevention, compliance recording

#### 5. **Teams App Governance**
- **What**: Inventory all Teams apps, permission review, block risky apps, consent alerts
- **Graph API**: `/appCatalogs/teamsApps`, `/teams/{id}/installedApps`, `/servicePrincipals`
- **Value**: Shadow IT prevention for Teams ecosystem

### 🟡 Medium Priority

#### 6. **Document Fingerprinting**
- **What**: Create fingerprints of sensitive docs, detect copies/derivatives across tenant
- **Graph API**: `/drives/{id}/items/{id}/content` + ML similarity
- **Value**: IP theft prevention

#### 7. **Communication Compliance Integration**
- **What**: Integrate with M365 Communication Compliance policies for Teams/Exchange
- **Graph API**: `/compliance/ediscovery/cases`, `/compliance/alerts`
- **Value**: Regulatory requirement (FINRA, HIPAA)

#### 8. **Site Classification Automation**
- **What**: Auto-classify SharePoint sites based on content, enforce governance policies
- **Graph API**: `/sites`, `/sites/{id}/permissions`, sensitivity labels
- **Value**: Governance at scale

#### 9. **Version History Analysis**
- **What**: Detect unusual version patterns (ransomware recovery, data manipulation)
- **Graph API**: `/drives/{id}/items/{id}/versions`
- **Value**: Forensics, ransomware recovery

#### 10. **Real-Time Alerts via Webhooks**
- **What**: Subscribe to Graph change notifications for immediate alerting
- **Graph API**: `POST /subscriptions` (resources: `/users`, `/groups`, `/drives/root`)
- **Value**: Reduce detection latency from minutes to seconds

### 🟢 Nice to Have

#### 11. **Teams Attendance/Engagement Analytics**
- **What**: Track meeting attendance, active vs passive participants, engagement scores
- **Graph API**: `/communications/callRecords/{id}/sessions`
- **Value**: HR/management reporting

#### 12. **OneDrive Known Folder Move Monitoring**
- **What**: Track Desktop/Documents backup status, detect sensitive local files
- **Graph API**: `/users/{id}/drive/special/approot`
- **Value**: Data protection compliance

#### 13. **Loop Components Security**
- **What**: Track Microsoft Loop usage, sharing, content classification
- **Graph API**: (Limited - requires beta APIs)
- **Value**: Emerging collaboration surface

---

## Implementation Priorities

### Phase 1 (Next Sprint)
1. **External User Lifecycle** - Quick win, high visibility
2. **CA Policy Monitoring** - Security posture must-have
3. **Teams App Governance** - Shadow IT risk

### Phase 2
4. **DLP Policy Enforcement** - Core enterprise feature
5. **Meeting Security** - Differentiation
6. **Real-Time Webhooks** - Detection speed

### Phase 3
7. **Communication Compliance** - Regulated industries
8. **Document Fingerprinting** - IP protection
9. **Version History Analysis** - Forensics

---

## Graph API Permissions Required

### Current (Already Granted)
- `User.Read.All`
- `Group.Read.All`
- `Mail.Read`
- `Sites.Read.All`
- `AuditLog.Read.All`
- `Directory.Read.All`

### Additional Needed for New Features
- `Policy.Read.All` - CA policies
- `ConditionalAccessPolicy.Read.All` - CA details
- `InformationProtectionPolicy.Read` - Sensitivity labels
- `TeamsAppInstallation.ReadForTeam.All` - Teams apps
- `OnlineMeetings.Read.All` - Meeting security
- `CallRecords.Read.All` - Call analytics
