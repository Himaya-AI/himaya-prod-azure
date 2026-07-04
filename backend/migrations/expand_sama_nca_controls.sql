-- ============================================================================
-- Expand SAMA CSF and NCA ECC control libraries to workspace-security scope.
--
-- Scope: controls Helios can actually verify with live telemetry from
-- Microsoft 365 (Exchange Online, Teams, SharePoint, OneDrive, Entra ID),
-- Google Workspace, and the Helios policy/quarantine/DLP engine.
--
-- Source standards:
--   - SAMA Cyber Security Framework v1.0 (Saudi Arabia, May 2017)
--   - NCA Essential Cybersecurity Controls ECC-1:2018 (Saudi National
--     Cybersecurity Authority, 114 sub-controls across 5 domains)
--
-- We deliberately DO NOT seed controls outside Helios' verification scope
-- (e.g. physical security, HR security, business continuity) — auditors
-- expect those to be evidenced separately and we don't want false greens.
-- ============================================================================

-- gen_random_uuid() is provided by the pgcrypto extension which is already
-- enabled (other tables in this DB rely on it). The SQLAlchemy model has a
-- Python-side `default=uuid.uuid4` but the DB column itself has no DEFAULT,
-- so a raw SQL INSERT must supply `id` explicitly.
INSERT INTO compliance_controls
    (id, framework, control_id, control_name_en, control_name_ar, description_en, description_ar, evidence_type)
VALUES
-- ---------------------------------------------------------------------------
-- SAMA CSF — Domain 3: Cyber Security Operations and Technology
-- ---------------------------------------------------------------------------
(gen_random_uuid(), 'SAMA_CSF', '3.1.1',
 'Cyber Security Governance',
 'حوكمة الأمن السيبراني',
 'Documented cyber security strategy, policies and operating model approved by the Board.',
 'استراتيجية الأمن السيبراني وسياساته ونموذج تشغيله الموثقة والمعتمدة من مجلس الإدارة.',
 'governance'),

(gen_random_uuid(), 'SAMA_CSF', '3.2.1',
 'Identity and Access Management',
 'إدارة الهوية والوصول',
 'User accounts, privileged access and authentication for all corporate systems including email and collaboration platforms.',
 'حسابات المستخدمين والوصول المتميز والمصادقة لجميع أنظمة المؤسسة بما في ذلك البريد الإلكتروني ومنصات التعاون.',
 'authentication'),

(gen_random_uuid(), 'SAMA_CSF', '3.2.2',
 'Privileged Access Management',
 'إدارة الوصول المتميز',
 'Inventory and continuous review of administrative roles (Global Admin, Exchange Admin, SharePoint Admin, Teams Admin).',
 'جرد ومراجعة مستمرة لأدوار الإدارة (المسؤول العام، مسؤول البريد، مسؤول شيربوينت، مسؤول تيمز).',
 'access_control'),

(gen_random_uuid(), 'SAMA_CSF', '3.3.1',
 'Application and System Hardening',
 'تقوية التطبيقات والأنظمة',
 'Secure baseline configuration for productivity and collaboration suites.',
 'تكوين أساسي آمن لمجموعات الإنتاجية والتعاون.',
 'governance'),

(gen_random_uuid(), 'SAMA_CSF', '3.3.3',
 'Email Security',
 'أمن البريد الإلكتروني',
 'Protection of inbound and outbound email against phishing, BEC, malware and impersonation; SPF/DKIM/DMARC enforcement.',
 'حماية البريد الإلكتروني الوارد والصادر من التصيد واختراق البريد الإلكتروني للأعمال والبرمجيات الخبيثة وانتحال الهوية؛ وتطبيق SPF و DKIM و DMARC.',
 'threat_detection'),

(gen_random_uuid(), 'SAMA_CSF', '3.3.4',
 'Web and Collaboration Security',
 'أمن الويب والتعاون',
 'Controls over external sharing, guest access, and anonymous links in Teams, SharePoint and OneDrive.',
 'ضوابط على المشاركة الخارجية ووصول الضيوف والروابط المجهولة في تيمز وشيربوينت ووان درايف.',
 'access_control'),

(gen_random_uuid(), 'SAMA_CSF', '3.3.5',
 'Malware Protection',
 'الحماية من البرمجيات الخبيثة',
 'Real-time detection of malicious attachments and links across email and SaaS file stores.',
 'الكشف في الوقت الفعلي عن المرفقات والروابط الخبيثة عبر البريد الإلكتروني ومخازن ملفات SaaS.',
 'threat_detection'),

(gen_random_uuid(), 'SAMA_CSF', '3.3.6',
 'Data Loss Prevention',
 'منع فقدان البيانات',
 'Detection and prevention of sensitive data exfiltration via email and file-sharing channels.',
 'الكشف عن تسرب البيانات الحساسة ومنعه عبر البريد الإلكتروني وقنوات مشاركة الملفات.',
 'data_protection'),

(gen_random_uuid(), 'SAMA_CSF', '3.3.7',
 'Cryptography in Transit',
 'التشفير أثناء النقل',
 'TLS for email, OAuth tokens encrypted at rest, secure session management.',
 'بروتوكول TLS للبريد الإلكتروني، وتشفير رموز OAuth أثناء التخزين، وإدارة الجلسات الآمنة.',
 'data_protection'),

(gen_random_uuid(), 'SAMA_CSF', '3.4.1',
 'Cyber Security Event Monitoring',
 'مراقبة أحداث الأمن السيبراني',
 'Continuous monitoring of authentication events, mailbox activity, file sharing events and admin actions.',
 'المراقبة المستمرة لأحداث المصادقة ونشاط صناديق البريد وأحداث مشاركة الملفات وإجراءات الإدارة.',
 'monitoring'),

(gen_random_uuid(), 'SAMA_CSF', '3.4.2',
 'Cyber Security Incident Management',
 'إدارة حوادث الأمن السيبراني',
 'Documented detection, triage, containment and response procedures with quarantine actions.',
 'إجراءات الكشف والفرز والاحتواء والاستجابة الموثقة مع إجراءات الحجر.',
 'incident_response'),

(gen_random_uuid(), 'SAMA_CSF', '3.4.3',
 'Threat Intelligence',
 'الاستخبارات السيبرانية',
 'Use of external threat feeds (IOCs, malicious domains, phishing URLs) to enrich detections.',
 'استخدام موجزات التهديدات الخارجية (مؤشرات الاختراق، النطاقات الخبيثة، روابط التصيد) لإثراء الاكتشافات.',
 'threat_detection'),

(gen_random_uuid(), 'SAMA_CSF', '3.4.4',
 'Vulnerability Management',
 'إدارة الثغرات',
 'Identification of risky third-party OAuth apps and overprivileged service principals.',
 'تحديد تطبيقات OAuth الخارجية الخطرة والكيانات الخدمية ذات الصلاحيات المفرطة.',
 'risk_management'),

(gen_random_uuid(), 'SAMA_CSF', '3.5.1',
 'Cyber Security Risk Management',
 'إدارة مخاطر الأمن السيبراني',
 'Risk-based policy engine that prioritises high-impact threats and continuous risk scoring.',
 'محرك سياسات قائم على المخاطر يعطي الأولوية للتهديدات عالية التأثير والتقييم المستمر للمخاطر.',
 'risk_management'),

(gen_random_uuid(), 'SAMA_CSF', '3.6.1',
 'Cyber Security Awareness',
 'الوعي بالأمن السيبراني',
 'End-user notification on quarantined threats and risky outbound messages (training platform sold separately).',
 'إخطار المستخدمين النهائيين بالتهديدات المحجورة والرسائل الصادرة الخطرة (يتم بيع منصة التدريب بشكل منفصل).',
 'training'),

-- ---------------------------------------------------------------------------
-- NCA ECC-1:2018 — Domain 1: Cybersecurity Governance
-- ---------------------------------------------------------------------------
(gen_random_uuid(), 'NCA_ECC', '1-1-1',
 'Cybersecurity Strategy',
 'استراتيجية الأمن السيبراني',
 'Documented strategy aligned with national framework and approved by executive leadership.',
 'استراتيجية موثقة متوافقة مع الإطار الوطني ومعتمدة من القيادة التنفيذية.',
 'governance'),

(gen_random_uuid(), 'NCA_ECC', '1-2-1',
 'Cybersecurity Policies and Procedures',
 'سياسات وإجراءات الأمن السيبراني',
 'Approved policies covering email, collaboration, data handling and incident response.',
 'سياسات معتمدة تغطي البريد الإلكتروني والتعاون ومعالجة البيانات والاستجابة للحوادث.',
 'governance'),

(gen_random_uuid(), 'NCA_ECC', '1-5-1',
 'Cybersecurity Risk Management',
 'إدارة مخاطر الأمن السيبراني',
 'Risk register and risk-based controls over corporate communications platforms.',
 'سجل المخاطر والضوابط القائمة على المخاطر على منصات الاتصال المؤسسية.',
 'risk_management'),

-- ---------------------------------------------------------------------------
-- NCA ECC-1:2018 — Domain 2: Cybersecurity Defence
-- ---------------------------------------------------------------------------
(gen_random_uuid(), 'NCA_ECC', '2-1-1',
 'Asset Management',
 'إدارة الأصول',
 'Inventory of mailboxes, shared mailboxes, Teams, SharePoint sites and connected SaaS apps.',
 'جرد صناديق البريد وصناديق البريد المشتركة وفرق العمل ومواقع شيربوينت وتطبيقات SaaS المتصلة.',
 'monitoring'),

(gen_random_uuid(), 'NCA_ECC', '2-2-1',
 'Identity and Access Management',
 'إدارة الهوية والوصول',
 'OAuth 2.0 with admin consent; tenant SSO/MFA managed at the identity provider layer.',
 'OAuth 2.0 مع موافقة المسؤول؛ تتم إدارة الدخول الموحد والمصادقة متعددة العوامل في طبقة موفر الهوية.',
 'authentication'),

(gen_random_uuid(), 'NCA_ECC', '2-2-3',
 'Privileged Access Management',
 'إدارة الوصول المتميز',
 'Inventory of privileged role holders (Global Admin, Exchange Admin, etc.) and just-in-time access where supported.',
 'جرد أصحاب الأدوار المتميزة (المسؤول العام، مسؤول البريد، إلخ) والوصول في الوقت المناسب حيثما كان مدعوماً.',
 'access_control'),

(gen_random_uuid(), 'NCA_ECC', '2-3-1',
 'Information System and Information Processing Facilities Protection',
 'حماية أنظمة المعلومات ومرافق معالجة المعلومات',
 'Hardening guidance and continuous monitoring for the M365/Google Workspace control plane.',
 'إرشادات التقوية والمراقبة المستمرة لطبقة التحكم في M365 و Google Workspace.',
 'monitoring'),

(gen_random_uuid(), 'NCA_ECC', '2-4-1',
 'Email Protection',
 'حماية البريد الإلكتروني',
 'Inbound/outbound mail filtering, anti-phishing, anti-malware and authentication enforcement (SPF/DKIM/DMARC).',
 'تصفية البريد الوارد والصادر، مكافحة التصيد، مكافحة البرمجيات الخبيثة، وفرض المصادقة (SPF/DKIM/DMARC).',
 'threat_detection'),

(gen_random_uuid(), 'NCA_ECC', '2-4-2',
 'Web Filtering and Browser Security',
 'تصفية الويب وأمن المتصفح',
 'Inspection of URLs in email and SaaS messages against threat-intel feeds (URLhaus, OpenPhish).',
 'فحص الروابط في البريد الإلكتروني ورسائل SaaS مقابل موجزات استخبارات التهديدات (URLhaus, OpenPhish).',
 'threat_detection'),

(gen_random_uuid(), 'NCA_ECC', '2-5-1',
 'Network Security Management',
 'إدارة أمن الشبكة',
 'API-only deployment; no agents required; TLS-only transport.',
 'النشر عبر الواجهات البرمجية فقط؛ لا حاجة لوكلاء؛ النقل عبر TLS فقط.',
 'data_protection'),

(gen_random_uuid(), 'NCA_ECC', '2-6-1',
 'Mobile Devices Security',
 'أمن الأجهزة المحمولة',
 'Coverage applies to email/Teams/SharePoint access from mobile devices (telemetry only; MDM remains tenant responsibility).',
 'تشمل التغطية الوصول إلى البريد/تيمز/شيربوينت من الأجهزة المحمولة (القياس فقط؛ تظل إدارة الأجهزة المحمولة من مسؤولية المؤسسة).',
 'access_control'),

(gen_random_uuid(), 'NCA_ECC', '2-7-1',
 'Data and Information Protection',
 'حماية البيانات والمعلومات',
 'Sensitivity classification of email content, SharePoint/OneDrive files and Teams attachments.',
 'تصنيف الحساسية لمحتوى البريد الإلكتروني وملفات شيربوينت/وان درايف ومرفقات تيمز.',
 'data_protection'),

(gen_random_uuid(), 'NCA_ECC', '2-7-2',
 'Data Loss Prevention',
 'منع فقدان البيانات',
 'Outbound email DLP, drafts review, external share monitoring for SharePoint/OneDrive.',
 'منع فقدان البيانات للبريد الصادر، ومراجعة المسودات، ومراقبة المشاركة الخارجية لشيربوينت/وان درايف.',
 'data_protection'),

(gen_random_uuid(), 'NCA_ECC', '2-7-3',
 'Cryptography',
 'التشفير',
 'TLS enforced for transport; OAuth tokens encrypted at rest with Fernet.',
 'تطبيق TLS للنقل؛ تشفير رموز OAuth أثناء التخزين باستخدام Fernet.',
 'data_protection'),

(gen_random_uuid(), 'NCA_ECC', '2-7-4',
 'Backup and Recovery Management',
 'إدارة النسخ الاحتياطي والاسترداد',
 'Audit/evidence retention (1 year default); compliance evidence is immutable.',
 'الاحتفاظ بالتدقيق/الأدلة (سنة واحدة افتراضياً)؛ أدلة الامتثال غير قابلة للتغيير.',
 'governance'),

(gen_random_uuid(), 'NCA_ECC', '2-8-1',
 'Cybersecurity Event Logs and Monitoring Management',
 'إدارة سجلات أحداث الأمن السيبراني والمراقبة',
 'Continuous monitoring of mail delivery, sign-ins, file access, admin changes; immutable audit log.',
 'المراقبة المستمرة لتسليم البريد، وعمليات تسجيل الدخول، والوصول إلى الملفات، وتغييرات الإدارة؛ سجل تدقيق غير قابل للتغيير.',
 'monitoring'),

(gen_random_uuid(), 'NCA_ECC', '2-9-1',
 'Cybersecurity Incident and Threat Management',
 'إدارة حوادث الأمن السيبراني والتهديدات',
 'Detection, quarantine, escalation and after-action evidence pack per incident.',
 'الكشف والحجر والتصعيد وحزمة الأدلة اللاحقة للحدث لكل حادث.',
 'incident_response'),

(gen_random_uuid(), 'NCA_ECC', '2-10-1',
 'Physical Security',
 'الأمن المادي',
 'Out of scope for Helios (cloud-only SaaS security) — evidence supplied by infrastructure provider.',
 'خارج نطاق هيليوس (أمن SaaS السحابي فقط) — يتم توفير الأدلة من قبل مزود البنية التحتية.',
 'governance'),

(gen_random_uuid(), 'NCA_ECC', '2-11-1',
 'Web Application Security',
 'أمن تطبيقات الويب',
 'OAuth app discovery and risk scoring across the tenant.',
 'اكتشاف تطبيقات OAuth وتقييم مخاطرها عبر المؤسسة.',
 'risk_management'),

(gen_random_uuid(), 'NCA_ECC', '2-12-1',
 'Cybersecurity in Human Resources',
 'الأمن السيبراني في الموارد البشرية',
 'External user lifecycle tracking (last sign-in, dormancy, offboarding risk).',
 'تتبع دورة حياة المستخدمين الخارجيين (آخر تسجيل دخول، الخمول، مخاطر الإنهاء).',
 'access_control'),

-- ---------------------------------------------------------------------------
-- NCA ECC-1:2018 — Domain 3: Cybersecurity Resilience
-- ---------------------------------------------------------------------------
(gen_random_uuid(), 'NCA_ECC', '3-1-1',
 'Cybersecurity Resilience Aspects of Business Continuity',
 'جوانب الصمود السيبراني في استمرارية الأعمال',
 'High-availability deployment; resilient delta sync; out-of-scope BCP supplied by tenant.',
 'نشر عالي التوفر؛ مزامنة مرنة للتدفقات؛ خطط استمرارية الأعمال خارج النطاق ومن مسؤولية المؤسسة.',
 'governance'),

-- ---------------------------------------------------------------------------
-- NCA ECC-1:2018 — Domain 4: Third-Party and Cloud Computing Cybersecurity
-- ---------------------------------------------------------------------------
(gen_random_uuid(), 'NCA_ECC', '4-1-1',
 'Third-Party Cybersecurity',
 'الأمن السيبراني للأطراف الثالثة',
 'Inventory and risk classification of third-party OAuth applications connected to the tenant.',
 'جرد وتصنيف مخاطر تطبيقات OAuth التابعة لجهات خارجية المتصلة بالمؤسسة.',
 'risk_management'),

(gen_random_uuid(), 'NCA_ECC', '4-2-1',
 'Cloud Computing and Hosting Cybersecurity',
 'الأمن السيبراني للحوسبة السحابية والاستضافة',
 'Data residency mapping (tenant region, user activity geography, AWS regions in use).',
 'تحديد موقع تخزين البيانات (منطقة المؤسسة، جغرافيا نشاط المستخدمين، مناطق AWS قيد الاستخدام).',
 'data_protection'),

-- ---------------------------------------------------------------------------
-- NCA ECC-1:2018 — Domain 5: ICS Cybersecurity (Out-of-scope for workspace tool)
-- ---------------------------------------------------------------------------
(gen_random_uuid(), 'NCA_ECC', '5-1-1',
 'Industrial Control Systems Protection',
 'حماية أنظمة التحكم الصناعي',
 'Out of scope — Helios secures workspace/SaaS, not ICS/OT environments.',
 'خارج النطاق — هيليوس يؤمن مساحة العمل/SaaS، وليس بيئات أنظمة التحكم الصناعي.',
 'governance')
ON CONFLICT (framework, control_id) DO UPDATE
SET
    control_name_en = EXCLUDED.control_name_en,
    control_name_ar = EXCLUDED.control_name_ar,
    description_en  = EXCLUDED.description_en,
    description_ar  = EXCLUDED.description_ar,
    evidence_type   = EXCLUDED.evidence_type;
