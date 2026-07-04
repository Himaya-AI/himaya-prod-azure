# Workspace Security - Connectors & Detection Specification

## Overview

Workspace Security (formerly SaaS Security) monitors and protects data across cloud productivity platforms. This document outlines additional connectors beyond Teams/SharePoint and the security/sovereignty detections for each.

---

## Current Connectors (M365)

### Microsoft Teams
- **Status:** Implemented
- **Capabilities:** Message scanning, file sharing detection, channel monitoring
- **Detections:** Sensitive data in messages, external sharing, DLP violations

### SharePoint
- **Status:** Implemented
- **Capabilities:** File classification, sharing scope analysis, site enumeration
- **Detections:** Sensitive files, external links, permission anomalies

---

## Proposed Additional Connectors

### 1. Google Workspace (Gmail + Drive)
**Priority:** High  
**Integration Method:** OAuth 2.0 + Service Account with Domain-Wide Delegation

**Capabilities:**
- Gmail: Email content scanning, attachment analysis, label management
- Drive: File classification, sharing permissions, activity audit
- Admin Console: User activity, audit logs, security alerts

**Detections:**
| Detection Type | Description | Severity |
|----------------|-------------|----------|
| Sensitive File External Share | Confidential/HC files shared outside org | Critical |
| Drive Public Links | Files with "Anyone with link" | High |
| External Forwarding Rules | Inbox rules forwarding to external | High |
| Suspicious Login | Login from unusual location/device | Medium |
| OAuth App Consent | Third-party app with sensitive permissions | Medium |
| Large File Download | Bulk download activity (>1GB) | Medium |
| Drive File Delete Spike | Unusual deletion activity | High |

**Data Sovereignty:**
- Data residency: Track where files are stored (US, EU, MENA regions)
- Compliance labels: Auto-apply retention/sensitivity labels
- Cross-border transfer alerts: Flag data leaving specified regions

---

### 2. Slack
**Priority:** High  
**Integration Method:** OAuth 2.0 + Slack API (Enterprise Grid preferred)

**Capabilities:**
- Message scanning across public/private channels
- File sharing monitoring
- App/bot installation tracking
- User activity and access patterns

**Detections:**
| Detection Type | Description | Severity |
|----------------|-------------|----------|
| Sensitive Data in Messages | PII, credentials, financial data | Critical |
| External Channel Guests | Guest users with sensitive access | High |
| Risky App Installations | Apps with broad permissions | Medium |
| Data Exfiltration via DMs | Bulk sharing to external users | High |
| Unusual Activity Hours | Messages sent outside work hours | Low |
| Channel Proliferation | Uncontrolled channel creation | Low |

**Data Sovereignty:**
- Enterprise Key Management (EKM) status
- Data export compliance tracking
- Message retention enforcement

---

### 3. Zoom
**Priority:** Medium  
**Integration Method:** OAuth 2.0 + Zoom API

**Capabilities:**
- Meeting security settings audit
- Recording access monitoring
- Chat message scanning
- Webinar attendee tracking

**Detections:**
| Detection Type | Description | Severity |
|----------------|-------------|----------|
| Recording External Access | Cloud recordings shared externally | High |
| Meeting Without Password | Scheduled meetings without passwords | Medium |
| Waiting Room Disabled | Meetings without waiting room | Medium |
| Unauthorized Attendees | Unknown participants in sensitive meetings | High |
| Sensitive Content in Transcripts | PII/confidential in AI transcriptions | Critical |
| Screen Share Data Leak | Sensitive screens shared to external | High |

---

### 4. Box
**Priority:** Medium  
**Integration Method:** OAuth 2.0 + Box API

**Capabilities:**
- File classification and metadata
- Collaboration and sharing audit
- Access pattern analysis
- Retention policy enforcement

**Detections:**
| Detection Type | Description | Severity |
|----------------|-------------|----------|
| Sensitive File Classification | Auto-classify files by content | Varies |
| External Collaboration | Files shared with external users | High |
| Excessive Downloads | Bulk download anomaly | High |
| Stale External Links | Old shared links still active | Medium |
| Folder Permission Sprawl | Overly broad folder access | Medium |
| Metadata Stripping | Files missing required metadata | Low |

---

### 5. Dropbox Business
**Priority:** Medium  
**Integration Method:** OAuth 2.0 + Dropbox Business API

**Capabilities:**
- File scanning and classification
- Sharing and link management
- Team activity monitoring
- Paper docs analysis

**Detections:**
| Detection Type | Description | Severity |
|----------------|-------------|----------|
| Public Link Sensitive File | Public links to sensitive content | Critical |
| External Folder Sharing | Shared folders with external users | High |
| Device Linking | Unmanaged device linked to account | Medium |
| Permanent Delete | Bypassing retention via permanent delete | High |
| Third-Party App Access | Apps with file read access | Medium |

---

### 6. Salesforce
**Priority:** Medium  
**Integration Method:** OAuth 2.0 + Salesforce REST API

**Capabilities:**
- Record access monitoring
- Report export tracking
- Field-level security audit
- Integration/Connected App monitoring

**Detections:**
| Detection Type | Description | Severity |
|----------------|-------------|----------|
| PII Export | Customer data exported to reports | High |
| Mass Data Export | Large record exports | High |
| Admin Permission Changes | Privilege escalation | Critical |
| Integration Data Access | Third-party pulling customer data | High |
| Field History Tracking | Sensitive fields without audit | Medium |
| Login Anomaly | Unusual login patterns | Medium |

---

### 7. Jira / Confluence (Atlassian)
**Priority:** Low  
**Integration Method:** OAuth 2.0 + Atlassian API

**Capabilities:**
- Page/document classification
- Space access audit
- Attachment scanning
- User permission analysis

**Detections:**
| Detection Type | Description | Severity |
|----------------|-------------|----------|
| Sensitive Page Public | Internal docs made public | Critical |
| External Space Access | Guests with space access | High |
| Attachment Classification | Sensitive attachments | Varies |
| Anonymous Access Enabled | Spaces allowing anonymous views | High |
| Bulk Page Export | Large export activity | Medium |

---

### 8. GitHub / GitLab (Enterprise)
**Priority:** Low  
**Integration Method:** OAuth 2.0 / Personal Access Token

**Capabilities:**
- Repository access audit
- Secret scanning
- Code content analysis
- Collaboration patterns

**Detections:**
| Detection Type | Description | Severity |
|----------------|-------------|----------|
| Exposed Secrets | API keys, passwords in code | Critical |
| Public Repository | Sensitive repo made public | Critical |
| External Collaborator | Outside contributor to private repo | High |
| Force Push to Main | Direct push to protected branch | High |
| Large Binary Commit | Data exfil via git | Medium |
| Vulnerability in Dependency | Known CVE in dependencies | Varies |

---

## Data Sovereignty Detections (Cross-Platform)

These detections apply across all connected platforms:

### Geographic Data Residency
| Detection | Description | Severity |
|-----------|-------------|----------|
| Data Outside Permitted Region | Files/data stored outside allowed jurisdictions | Critical |
| Cross-Border Transfer | Data transferred between regions | High |
| Processing Location Change | Backend processing moved to new region | Medium |

### Compliance & Retention
| Detection | Description | Severity |
|-----------|-------------|----------|
| Retention Policy Violation | Data deleted before retention period | High |
| Legal Hold Bypass | Attempt to delete held data | Critical |
| Audit Log Gap | Missing audit entries for period | High |
| Encryption Not Enforced | Data at rest without encryption | High |

### Access & Authentication
| Detection | Description | Severity |
|-----------|-------------|----------|
| Privileged Access Anomaly | Admin action outside normal patterns | High |
| Shared Account Usage | Multiple users on single account | Medium |
| MFA Bypass | Access without MFA requirement | High |
| Expired User Active | Terminated employee still has access | Critical |

---

## Implementation Priority Matrix

| Connector | Business Value | Implementation Effort | Priority Score |
|-----------|----------------|----------------------|----------------|
| Google Workspace | High | Medium | **P1** |
| Slack | High | Medium | **P1** |
| Zoom | Medium | Low | **P2** |
| Box | Medium | Medium | **P2** |
| Dropbox | Medium | Medium | **P2** |
| Salesforce | High | High | **P2** |
| Atlassian | Low | Medium | **P3** |
| GitHub/GitLab | Low | Medium | **P3** |

---

## DLP One-Click Setup (Revised Approach)

### Problem
External transport rules and SMTP routing are complex and often fail:
- M365: Connector not identifying properly
- Gmail: Can't add SMTP routes

### Solution: API-Based Inline DLP

Instead of routing email through external gateways, implement DLP that:

1. **Hooks into Delta Sync** - When emails are ingested via existing Gmail/M365 integrations
2. **Pre-Send Analysis** - For orgs that enable "hold outbound" mode
3. **Post-Send Classification** - Scan sent items folder and flag violations
4. **Policy Actions via API** - Move to quarantine, notify admin, apply labels

### One-Click Setup Flow

```
┌─────────────────────────────────────────────────────────┐
│           Workspace Security → DLP Tab                   │
│                                                          │
│  ┌──────────────────────────────────────────────────┐   │
│  │ 🛡️ Enable Email DLP                              │   │
│  │                                                   │   │
│  │ Helios will automatically scan outbound emails   │   │
│  │ for sensitive data using your existing M365/Gmail│   │
│  │ integration. No additional setup required.       │   │
│  │                                                   │   │
│  │ [x] Block emails with PII to external recipients │   │
│  │ [x] Alert on financial data exposure             │   │
│  │ [ ] Hold emails for review (requires approval)   │   │
│  │                                                   │   │
│  │         [ Enable DLP Protection ]                │   │
│  └──────────────────────────────────────────────────┘   │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### Technical Implementation

1. **Enable DLP Flag** on Organization record
2. **Background Worker** scans sent items folder every 5 minutes
3. **Classification** runs on new outbound emails
4. **Actions**:
   - WARN: Apply warning label, notify sender
   - HOLD: Move to "DLP Review" folder, notify admin
   - BLOCK: Delete from sent, generate NDR, log incident

This approach works with existing OAuth permissions and doesn't require:
- Transport rule creation
- SMTP connector configuration
- Admin consent for mail flow

---

## Bluebird Agent Capabilities

The Bluebird Agent chat interface connects to:

### Data Sources
- **SageMaker** - AI/ML models for threat prediction and classification
- **AWS RDS** - Historical threat data, user behavior analytics
- **Neo4j** - Graph intelligence for sender reputation
- **Redis** - Real-time signals and cached metrics
- **S3** - Evidence artifacts and report storage

### Query Types
1. **Threat Intelligence** - "What are the top threats this week?"
2. **Risk Analysis** - "Show me users with highest risk scores"
3. **Compliance Status** - "What's our SAMA compliance score?"
4. **Data Exposure** - "Are there sensitive files shared externally?"
5. **Policy Recommendations** - "What policies should I enable?"

### Action Types
1. **Generate Reports** - Executive summaries, compliance reports, threat briefings
2. **Deploy Policies** - Enable recommended security policies
3. **Investigate Incidents** - Deep dive into specific threats
4. **Schedule Reviews** - Set up recurring security assessments

---

*Document Version: 1.0*  
*Last Updated: 2026-05-23*
