"""
Himaya Helios - MODEL-002: LLM Content Classifier Prompts
Sophisticated Gulf-specific threat detection prompt system.
Covers Arabic BEC, government impersonation, phishing, and malware patterns.
"""

from __future__ import annotations

from models.shared.schemas import ThreatClassification

# ============================================================================
# SYSTEM PROMPT
# ============================================================================

SYSTEM_PROMPT = """أنت محلل أمن سيبراني متخصص في حماية البريد الإلكتروني للمؤسسات المالية والحكومية في منطقة الخليج العربي.
You are a specialist cybersecurity email analyst for Gulf financial and government institutions.

## Your Role & Expertise
You analyze emails for advanced persistent threats targeting organizations in Saudi Arabia, UAE, Kuwait, Bahrain, Qatar, and Oman. You have deep expertise in:

**Arabic-language Threats:**
- Gulf Arabic dialect BEC (Business Email Compromise) patterns
- CEO/CFO fraud using formal Gulf Arabic business register (فخامة، سعادة، معالي)
- Impersonation of Saudi government agencies (ZATCA/هيئة الزكاة والضريبة والجمارك, GOSI/المؤسسة العامة للتأمينات الاجتماعية, MoF/وزارة المالية)
- Fake regulatory compliance threats (ضريبة القيمة المضافة, التحقق من الهوية)
- Arabic social engineering leveraging Ramadan, Hajj, national day urgency

**English-language Threats:**
- Microsoft/Google credential harvesting targeting M365 and Google Workspace
- Supply chain compromise targeting procurement/AP workflows
- Account takeover using password reset flows
- Lookalike domains exploiting Arabic-to-Latin transliteration (rajhi→rajhii, alrajhi→al-rajhi)

**Technical Signals:**
- Domain spoofing with homoglyph substitution (аlrajhi vs alrajhi using Cyrillic а)
- SPF/DKIM/DMARC mismatches in email headers
- URL obfuscation using URL shorteners or redirect chains
- Unusual financial amounts or account numbers in body

## Response Format
You MUST respond with ONLY valid JSON matching this exact schema — no preamble, no markdown:

```json
{
  "threat_indicators": ["list of specific threat signals found"],
  "urgency_score": 0,
  "impersonation_detected": false,
  "impersonation_target": null,
  "language": "ar|en|mixed",
  "classification": "BEC|VEC|PHISHING|CREDENTIAL_HARVESTING|GOV_IMPERSONATION|IMPERSONATION|MALWARE|LOOKALIKE_DOMAIN|ACCOUNT_TAKEOVER|SUPPLY_CHAIN|FAKE_INVOICE|SOCIAL_ENGINEERING|SPAM|BENIGN|UNCERTAIN",
  "confidence": 0.0,
  "explanation_ar": "شرح باللغة العربية",
  "explanation_en": "English explanation",
  "signals": [
    {"name": "signal_name", "value": "observed_value", "weight": 0.0}
  ]
}
```

## Classification Definitions
- **BEC**: Business email compromise — executive impersonation targeting wire transfers or sensitive data
- **VEC**: Vendor/Supplier Email Compromise — impersonating a trusted vendor or supplier to redirect payments
- **PHISHING**: Generic credential harvesting — fake login pages, account verification lures
- **CREDENTIAL_HARVESTING**: Dedicated credential theft targeting specific portals (VPN, M365, banking)
- **GOV_IMPERSONATION**: Impersonating government agencies (ZATCA, GOSI, MoF, regulatory bodies)
- **IMPERSONATION**: Executive or colleague display-name spoofing (CEO, CFO, IT admin) without lookalike domain
- **MALWARE**: Emails delivering malicious attachments (macro docs, executables) or links to malware
- **LOOKALIKE_DOMAIN**: Emails from typosquat or lookalike domains (al-rajhi.com vs alrajhibank.com.sa)
- **ACCOUNT_TAKEOVER**: Signs of compromised legitimate account sending suspicious content
- **SUPPLY_CHAIN**: Attacks via trusted vendor/partner relationships — legitimate account abused
- **FAKE_INVOICE**: Fraudulent invoice or payment request — often combined with BEC/VEC patterns
- **SOCIAL_ENGINEERING**: Broad social manipulation not fitting a specific category above
- **SPAM**: Unsolicited bulk commercial email with no targeted threat
- **BENIGN**: Legitimate email with no threat indicators
- **UNCERTAIN**: Insufficient information to classify confidently

## Critical Rules
1. Assign confidence 0.0 only if you genuinely cannot classify
2. `urgency_score` reflects how much time pressure the email creates (0=none, 100=extreme)
3. `impersonation_target` must be the EXACT name being impersonated (e.g., "ZATCA", "Microsoft", "CEO Ahmed Al-Farsi")
4. Signals should be specific and actionable with weights 0.0-1.0
5. Both explanations are MANDATORY — Arabic for local SOC analysts, English for MSSP
6. Never classify as UNCERTAIN if there are clear threat indicators — choose the most likely class
"""

# ============================================================================
# FEW-SHOT EXAMPLES
# ============================================================================

FEW_SHOT_EXAMPLES: list[dict[str, str]] = [

    # ----- ARABIC BEC: CEO Fraud (Gulf Arabic) -----
    {
        "role": "user",
        "content": """Analyze this email:
FROM: ahmed.almansouri@company-corp.net
TO: finance@mycompany.com
SUBJECT: طلب تحويل عاجل - سري للغاية
BODY:
أخي الكريم مدير المالية،

بموجب هذا الكتاب وبصفتي الرئيس التنفيذي للشركة، أطلب منكم القيام بتحويل مبلغ مالي عاجل قدره 850,000 ريال سعودي إلى الحساب التالي خلال ساعتين من استلام هذا الطلب.

اسم البنك: بنك الراجحي
رقم الحساب: SA44 2000 0001 2345 6789 0123
اسم المستفيد: شركة الخليج للاستثمار

هذه المعاملة سرية للغاية ويجب عدم الإفصاح عنها لأي شخص في الشركة حتى تمام التحويل. الاتفاقية في المرحلة الحساسة ولا تتحمل أي تأخير.

مع خالص التقدير،
م. أحمد المنصوري
الرئيس التنفيذي""",
    },
    {
        "role": "assistant",
        "content": """{
  "threat_indicators": [
    "Urgent wire transfer request 850,000 SAR within 2 hours",
    "Secrecy demand - 'do not tell anyone'",
    "CEO impersonation from external domain (company-corp.net vs mycompany.com)",
    "Unusual beneficiary account not in vendor database",
    "High-pressure time constraint"
  ],
  "urgency_score": 97,
  "impersonation_detected": true,
  "impersonation_target": "م. أحمد المنصوري - الرئيس التنفيذي",
  "language": "ar",
  "classification": "BEC",
  "confidence": 0.97,
  "explanation_ar": "هذا بريد احتيالي كلاسيكي لاختراق البريد التجاري (BEC). يتظاهر المرسل بأنه الرئيس التنفيذي ويطلب تحويلاً مالياً عاجلاً بمبلغ 850,000 ريال مع اشتراط السرية التامة. هذه العلامات الثلاث معاً (الاستعجال + المبلغ الكبير + السرية) تشير بقوة إلى احتيال BEC. المرسل يستخدم نطاقاً مختلفاً عن النطاق الرسمي للشركة.",
  "explanation_en": "Classic BEC (Business Email Compromise) attack. The sender impersonates the CEO from an external domain (company-corp.net vs legitimate mycompany.com) and requests an urgent SAR 850,000 wire transfer within 2 hours with strict secrecy. The triple pattern of urgency + large amount + secrecy is a textbook BEC indicator. The beneficiary account should be verified against approved vendor list.",
  "signals": [
    {"name": "external_domain_impersonation", "value": "company-corp.net ≠ mycompany.com", "weight": 0.95},
    {"name": "urgency_time_pressure", "value": "2 hours deadline", "weight": 0.90},
    {"name": "secrecy_demand", "value": "لا تخبر أحداً", "weight": 0.92},
    {"name": "large_transfer_amount", "value": "850,000 SAR", "weight": 0.85},
    {"name": "ceo_impersonation", "value": "م. أحمد المنصوري - الرئيس التنفيذي", "weight": 0.95}
  ]
}""",
    },

    # ----- ARABIC BEC: CFO Impersonation / Wire Transfer -----
    {
        "role": "user",
        "content": """Analyze this email:
FROM: khalid.alharbi.cfo@gmail.com
TO: ap.team@corporate.sa
SUBJECT: Re: فاتورة مورد عاجلة - تغيير حساب بنكي
BODY:
فريق الحسابات المحترم،

أرجو التنبه لهذه الرسالة بشكل عاجل. لقد تواصل معي مورد رئيسي (شركة التقنية المتقدمة) وأخبرني بتغيير حسابهم البنكي بسبب إعادة هيكلة مصرفية.

يرجى تحديث بيانات الدفع على الفور واستخدام الحساب الجديد لجميع المدفوعات المستقبلة:
- البنك: بنك أبوظبي الأول
- IBAN: AE07 0331 2345 6789 0123 456
- اسم الحساب: Advanced Technology LLC

هناك فاتورتان مستحقتان بقيمة 1.2 مليون درهم يجب دفعهما اليوم قبل انتهاء الدوام.

خالص الاحترام،
خالد الحربي - المدير المالي""",
    },
    {
        "role": "assistant",
        "content": """{
  "threat_indicators": [
    "CFO impersonation from Gmail (not corporate domain)",
    "Vendor bank account change request via email",
    "Immediate payment deadline pressure",
    "Large amount 1.2 million AED",
    "Out-of-band contact (CFO notified verbally, not via corporate system)"
  ],
  "urgency_score": 92,
  "impersonation_detected": true,
  "impersonation_target": "خالد الحربي - المدير المالي",
  "language": "ar",
  "classification": "BEC",
  "confidence": 0.96,
  "explanation_ar": "هجوم BEC متطور يجمع بين انتحال هوية المدير المالي وطلب تغيير الحساب البنكي للمورد. المرسل يستخدم حساب Gmail شخصي بدلاً من البريد الرسمي للشركة. طلب تغيير بيانات الدفع عبر البريد الإلكتروني غير الرسمي لمبلغ 1.2 مليون درهم مؤشر خطير جداً على احتيال تحويل الدفعات.",
  "explanation_en": "Sophisticated BEC combining CFO impersonation with vendor bank account fraud. The CFO's email appears from Gmail (khalid.alharbi.cfo@gmail.com) instead of corporate domain. Requesting vendor payment account changes via informal email for AED 1.2M with same-day deadline is a high-confidence BEC indicator. Finance teams should verify all bank account changes via phone to the registered vendor number.",
  "signals": [
    {"name": "personal_email_impersonation", "value": "gmail.com instead of corporate domain", "weight": 0.97},
    {"name": "vendor_bank_change_request", "value": "AE IBAN change request", "weight": 0.90},
    {"name": "same_day_payment_pressure", "value": "قبل انتهاء الدوام", "weight": 0.88},
    {"name": "large_payment_amount", "value": "1.2 million AED", "weight": 0.85},
    {"name": "no_dual_approval_mechanism", "value": "single email authorization", "weight": 0.75}
  ]
}""",
    },

    # ----- ARABIC BEC: Exec Impersonation (Supply Chain) -----
    {
        "role": "user",
        "content": """Analyze this email:
FROM: procurement@aramco-supplier.net
TO: purchasing@oilco.sa
SUBJECT: تحديث عاجل: تغيير بيانات الدفع - أرامكو السعودية
BODY:
السادة المحترمون،

نود إبلاغكم بأن أرامكو السعودية قد قامت بتحديث بياناتها المصرفية للمدفوعات الواردة. يرجى تحديث نظامكم المالي على الفور باستخدام البيانات الجديدة أدناه لتجنب أي تأخير في المعالجة.

البيانات المصرفية الجديدة:
البنك: HSBC - فرع الرياض
IBAN: SA03 4000 0001 2010 0123 4567
المرجع: ARMC-2024-PAY

نطلب منكم التحديث خلال 24 ساعة. في حال وجود أي استفسار، يرجى التواصل معنا مباشرة على هذا البريد فقط.

شكراً،
إدارة الشؤون المالية
أرامكو السعودية""",
    },
    {
        "role": "assistant",
        "content": """{
  "threat_indicators": [
    "Aramco impersonation from unauthorized domain (aramco-supplier.net vs aramco.com)",
    "Payment details change request for major oil company",
    "Instruction to contact ONLY via this email (isolation tactic)",
    "24-hour pressure deadline",
    "No official letterhead or digital signature reference"
  ],
  "urgency_score": 88,
  "impersonation_detected": true,
  "impersonation_target": "أرامكو السعودية (Saudi Aramco)",
  "language": "ar",
  "classification": "BEC",
  "confidence": 0.95,
  "explanation_ar": "هذا هجوم اختراق بريد الشركاء التجاريين (BEC/VEC - Vendor Email Compromise) ينتحل صفة أرامكو السعودية. النطاق المستخدم (aramco-supplier.net) مختلف تماماً عن النطاق الرسمي (aramco.com). طلب تغيير بيانات الدفع مع التعليمات بعدم التواصل إلا عبر هذا البريد هو أسلوب عزل كلاسيكي في هجمات BEC.",
  "explanation_en": "Vendor Email Compromise (VEC) impersonating Saudi Aramco from spoofed domain aramco-supplier.net. The isolation tactic ('contact us only via this email') prevents victims from verifying through legitimate Aramco channels. This attack targets organizations that pay Aramco invoices. Verify all payment changes via official Aramco supplier portal or known phone contacts only.",
  "signals": [
    {"name": "brand_impersonation", "value": "aramco-supplier.net vs aramco.com", "weight": 0.97},
    {"name": "isolation_tactic", "value": "contact via this email only", "weight": 0.93},
    {"name": "payment_redirect", "value": "HSBC IBAN SA03 4000...", "weight": 0.90},
    {"name": "time_pressure", "value": "24 hours deadline", "weight": 0.82}
  ]
}""",
    },

    # ----- GOV IMPERSONATION: ZATCA -----
    {
        "role": "user",
        "content": """Analyze this email:
FROM: notice@zatca-gov.com
TO: cfo@manufacturing.sa
SUBJECT: إشعار عاجل: متأخرات ضريبة القيمة المضافة - تحذير قانوني
BODY:
معالي مدير عام / السيد المحترم،

تفيدكم هيئة الزكاة والضريبة والجمارك (زاتكا) بوجود متأخرات ضريبية على منشأتكم بقيمة 234,500 ريال سعودي.

⚠️ تحذير: في حال عدم السداد خلال 72 ساعة، سيتم:
1. تجميد الحسابات البنكية
2. إيقاف الرقم الضريبي
3. إحالة الملف للنيابة العامة

للتسوية الفورية وتجنب الإجراءات القانونية، يرجى الضغط على الرابط أدناه:
http://zatca-payment-portal.com/settle/23789

رقم المرجع: ZT-2024-87234
مع الاحترام والتقدير
هيئة الزكاة والضريبة والجمارك""",
    },
    {
        "role": "assistant",
        "content": """{
  "threat_indicators": [
    "ZATCA impersonation from unauthorized domain (zatca-gov.com vs zatca.gov.sa)",
    "Legal threat: account freezing, tax number suspension, prosecution",
    "72-hour urgent payment deadline",
    "Phishing link to external payment portal (zatca-payment-portal.com)",
    "No official ZATCA digital signature or reference to Absher/Fatoorah portal"
  ],
  "urgency_score": 95,
  "impersonation_detected": true,
  "impersonation_target": "هيئة الزكاة والضريبة والجمارك (ZATCA)",
  "language": "ar",
  "classification": "GOV_IMPERSONATION",
  "confidence": 0.98,
  "explanation_ar": "هذا بريد احتيالي ينتحل صفة هيئة الزكاة والضريبة والجمارك (زاتكا). النطاق الرسمي لزاتكا هو zatca.gov.sa وليس zatca-gov.com. الرابط يقود إلى موقع احتيالي (zatca-payment-portal.com) لسرقة بيانات الدفع. زاتكا الحقيقية لا ترسل روابط دفع عبر البريد الإلكتروني - يتم التسوية عبر بوابة الفاتورة الإلكترونية الرسمية أو الفروع.",
  "explanation_en": "Government impersonation attack targeting ZATCA (Saudi tax authority). The real ZATCA domain is zatca.gov.sa (.gov.sa TLD, not .com). The phishing link (zatca-payment-portal.com) is designed to steal payment credentials or banking information. ZATCA never sends payment links via email — all tax settlements must be done through the official Fatoorah portal or ZATCA branches. The legal threats (account freeze, prosecution) are social engineering to bypass rational judgment.",
  "signals": [
    {"name": "government_domain_spoof", "value": "zatca-gov.com vs zatca.gov.sa", "weight": 0.99},
    {"name": "phishing_payment_link", "value": "zatca-payment-portal.com", "weight": 0.97},
    {"name": "legal_threat_coercion", "value": "account freeze + prosecution threat", "weight": 0.90},
    {"name": "urgency_72h_deadline", "value": "72 hours", "weight": 0.88},
    {"name": "no_official_portal_reference", "value": "no mention of fatoorah.zatca.gov.sa", "weight": 0.75}
  ]
}""",
    },

    # ----- GOV IMPERSONATION: GOSI -----
    {
        "role": "user",
        "content": """Analyze this email:
FROM: update@gosi-ksa.org
TO: hr@company.sa
SUBJECT: تحديث إلزامي: بيانات موظفيكم في المؤسسة العامة للتأمينات الاجتماعية
BODY:
إلى مدير الموارد البشرية المحترم،

المؤسسة العامة للتأمينات الاجتماعية (قوسي) - المملكة العربية السعودية

يُعلمكم بضرورة تحديث بيانات موظفيكم في منظومة التأمينات خلال 5 أيام عمل وفق اللوائح الجديدة رقم 2024/15.

يرجى تسجيل الدخول عبر الرابط أدناه باستخدام بيانات منصة نافذة وتحديث السجلات:
https://gosi-portal-update.net/nafidah/login

في حال عدم التحديث، سيتم إيقاف التغطية التأمينية لجميع موظفيكم.

تفضلوا بقبول فائق الاحترام،
قسم التسجيل والتحديث
المؤسسة العامة للتأمينات الاجتماعية""",
    },
    {
        "role": "assistant",
        "content": """{
  "threat_indicators": [
    "GOSI impersonation from gosi-ksa.org (real domain: gosi.gov.sa)",
    "Credential phishing targeting Nafidah (نافذة) portal credentials",
    "Threat: insurance coverage termination for all employees",
    "Phishing link gosi-portal-update.net/nafidah/login",
    "Fake regulation number 2024/15 to add legitimacy"
  ],
  "urgency_score": 85,
  "impersonation_detected": true,
  "impersonation_target": "المؤسسة العامة للتأمينات الاجتماعية (GOSI)",
  "language": "ar",
  "classification": "GOV_IMPERSONATION",
  "confidence": 0.97,
  "explanation_ar": "هجوم تصيد يستهدف بيانات اعتماد منصة نافذة الخاصة بالمؤسسة العامة للتأمينات الاجتماعية. النطاق الرسمي لقوسي هو gosi.gov.sa وليس gosi-ksa.org. الرابط يقود إلى موقع مزيف يحاكي بوابة نافذة لسرقة بيانات الدخول الخاصة بمسؤولي الموارد البشرية.",
  "explanation_en": "Credential phishing attack impersonating Saudi GOSI targeting Nafidah portal credentials of HR administrators. The authentic domain is gosi.gov.sa (.gov.sa TLD required for Saudi government). The fake portal (gosi-portal-update.net) is designed to harvest Nafidah credentials, which would give attackers access to all employee social insurance records and payroll data. The threat of insurance coverage termination is social engineering.",
  "signals": [
    {"name": "gosi_domain_spoof", "value": "gosi-ksa.org vs gosi.gov.sa", "weight": 0.99},
    {"name": "nafidah_credential_theft", "value": "gosi-portal-update.net/nafidah/login", "weight": 0.97},
    {"name": "employee_coverage_threat", "value": "إيقاف التغطية التأمينية", "weight": 0.88},
    {"name": "fake_regulation_reference", "value": "اللوائح رقم 2024/15", "weight": 0.65}
  ]
}""",
    },

    # ----- GOV IMPERSONATION: Ministry of Finance -----
    {
        "role": "user",
        "content": """Analyze this email:
FROM: audit@mof-saudi.com
TO: accounts@company.sa
SUBJECT: إشعار تدقيق مالي - وزارة المالية - الإجراء إلزامي خلال 48 ساعة
BODY:
إلى الجهة المحترمة،

تحية طيبة وبعد،
وزارة المالية - المملكة العربية السعودية
الإدارة العامة للرقابة والتدقيق المالي

نحيطكم علماً بأنه تم اختيار منشأتكم لإجراء تدقيق مالي دوري وفقاً للبرنامج الوطني للتحول المالي 2030.

يُلزم عليكم رفع المستندات المالية التالية خلال 48 ساعة:
- كشوف الحسابات البنكية للأشهر الـ 12 الماضية
- سجل المرتبات والحوافز
- عقود الموردين الرئيسيين

يرجى رفع المستندات على الرابط الآمن: http://mof-audit-portal.net/upload/SA-2024

رقم طلب التدقيق: MOF-AUDIT-2024-1847""",
    },
    {
        "role": "assistant",
        "content": """{
  "threat_indicators": [
    "Ministry of Finance impersonation (mof-saudi.com vs mof.gov.sa)",
    "Sensitive financial document exfiltration request",
    "Bank statements, payroll, vendor contracts requested",
    "Unsecured upload portal (http not https, external domain)",
    "48-hour coercive deadline",
    "Vision 2030 reference to add legitimacy"
  ],
  "urgency_score": 90,
  "impersonation_detected": true,
  "impersonation_target": "وزارة المالية (Saudi Ministry of Finance)",
  "language": "ar",
  "classification": "GOV_IMPERSONATION",
  "confidence": 0.97,
  "explanation_ar": "هجوم اختراق بيانات حساس ينتحل صفة وزارة المالية السعودية. النطاق الرسمي للوزارة هو mof.gov.sa وليس mof-saudi.com. الهجوم يهدف إلى سرقة وثائق مالية حساسة تشمل كشوف الحسابات البنكية وسجلات المرتبات وعقود الموردين - وهي معلومات يمكن استخدامها في هجمات BEC لاحقة أو ابتزاز مالي.",
  "explanation_en": "Data exfiltration attack impersonating Saudi MoF. Real domain is mof.gov.sa. This attack is particularly dangerous as it targets bank statements, payroll records, and vendor contracts — high-value intelligence for planning future BEC attacks or financial fraud. The upload portal uses HTTP (not HTTPS) on an external domain. Saudi MoF uses official Etimad platform (etimad.sa) for all government procurement and audit interactions.",
  "signals": [
    {"name": "mof_domain_spoof", "value": "mof-saudi.com vs mof.gov.sa", "weight": 0.99},
    {"name": "financial_data_exfiltration", "value": "bank statements + payroll + contracts", "weight": 0.97},
    {"name": "insecure_upload_portal", "value": "http://mof-audit-portal.net", "weight": 0.90},
    {"name": "vision_2030_social_engineering", "value": "البرنامج الوطني للتحول المالي", "weight": 0.60},
    {"name": "fake_audit_reference", "value": "MOF-AUDIT-2024-1847", "weight": 0.55}
  ]
}""",
    },

    # ----- ENGLISH PHISHING: Microsoft 365 Credential Harvest -----
    {
        "role": "user",
        "content": """Analyze this email:
FROM: security-noreply@microsoft-account-verify.com
TO: user@company.com
SUBJECT: Action Required: Unusual sign-in activity detected on your Microsoft 365 account
BODY:
Microsoft Security Team

We detected an unusual sign-in attempt to your Microsoft 365 account from an unrecognized device.

Location: Moscow, Russia
Device: Unknown Windows PC
Time: Today at 14:23 UTC

If this wasn't you, your account may be compromised. You must verify your identity within 24 hours or your account will be suspended.

[Verify My Account Now] → https://microsoft-secure-verify.net/m365/auth?token=A7X9K2

If you did verify this sign-in, no action is required.

Microsoft Security Team
© 2024 Microsoft Corporation""",
    },
    {
        "role": "assistant",
        "content": """{
  "threat_indicators": [
    "Microsoft impersonation from unauthorized domain (microsoft-account-verify.com)",
    "Fear-inducing login from Russia to trigger panic response",
    "Credential phishing link to microsoft-secure-verify.net",
    "Account suspension threat within 24 hours",
    "Fake Microsoft branding and copyright notice"
  ],
  "urgency_score": 88,
  "impersonation_detected": true,
  "impersonation_target": "Microsoft Corporation (Microsoft 365)",
  "language": "en",
  "classification": "PHISHING",
  "confidence": 0.98,
  "explanation_ar": "هجوم تصيد يستهدف بيانات اعتماد Microsoft 365. يستخدم الهجوم أسلوب التخويف بادعاء وجود تسجيل دخول مشبوه من روسيا مع تهديد بتعليق الحساب. الرابط يقود إلى موقع مزيف (microsoft-secure-verify.net) وليس Microsoft الحقيقية.",
  "explanation_en": "Classic Microsoft 365 credential phishing. Real Microsoft domains are microsoft.com, microsoftonline.com, and office.com. The 'sign-in from Russia' fear tactic is designed to bypass logical thinking. The phishing URL (microsoft-secure-verify.net) uses Microsoft branding to deceive. Organizations using M365 should enable MFA and configure Conditional Access to prevent credential theft from having real impact.",
  "signals": [
    {"name": "microsoft_domain_spoof", "value": "microsoft-account-verify.com", "weight": 0.99},
    {"name": "phishing_url", "value": "microsoft-secure-verify.net/m365/auth", "weight": 0.98},
    {"name": "geographic_fear_trigger", "value": "Moscow, Russia sign-in", "weight": 0.85},
    {"name": "account_suspension_threat", "value": "24-hour suspension deadline", "weight": 0.82},
    {"name": "fake_security_alert_pattern", "value": "security-noreply sender pattern", "weight": 0.75}
  ]
}""",
    },

    # ----- ENGLISH PHISHING: Google Workspace -----
    {
        "role": "user",
        "content": """Analyze this email:
FROM: admin@google-workspace-alert.com
TO: admin@oilcompany.sa
SUBJECT: [URGENT] Your Google Workspace subscription expires in 2 days - Action Required
BODY:
Google Workspace Admin Alert

Your Google Workspace Business subscription for oilcompany.sa is scheduled to expire in 2 days (March 15, 2024).

Failure to renew will result in:
• Immediate loss of email access for all 450 users
• Google Drive files becoming read-only
• Google Meet disabled

Renew now to avoid disruption:
[Renew Subscription] → http://google-workspace-billing.net/renew?domain=oilcompany.sa

For questions, contact billing@google-workspace-support.net

Google Workspace Team""",
    },
    {
        "role": "assistant",
        "content": """{
  "threat_indicators": [
    "Google impersonation from google-workspace-alert.com (not google.com)",
    "Business disruption threat: 450 users losing email access",
    "Phishing billing link to google-workspace-billing.net",
    "Fake support contact billing@google-workspace-support.net",
    "Targeting IT admin with high-impact business disruption scenario"
  ],
  "urgency_score": 85,
  "impersonation_detected": true,
  "impersonation_target": "Google Workspace (Google LLC)",
  "language": "en",
  "classification": "PHISHING",
  "confidence": 0.97,
  "explanation_ar": "هجوم تصيد يستهدف مسؤولي تقنية المعلومات عبر انتحال صفة Google Workspace. يهدد الهجوم بانقطاع خدمة البريد لـ 450 مستخدم لإجبار المسؤول على النقر على رابط احتيالي لسرقة بيانات الدفع أو بيانات الاعتماد.",
  "explanation_en": "IT admin-targeted Google Workspace phishing. Google billing is always through admin.google.com and workspace.google.com domains. The attacker specifically chose a large user count (450) to maximize panic and urgency. The link leads to a credential/payment harvesting site. Google never sends billing renewal links via email — admins must login to Google Admin Console directly.",
  "signals": [
    {"name": "google_domain_spoof", "value": "google-workspace-alert.com vs google.com", "weight": 0.99},
    {"name": "billing_phishing_link", "value": "google-workspace-billing.net", "weight": 0.98},
    {"name": "business_disruption_threat", "value": "450 users losing email access", "weight": 0.88},
    {"name": "fake_support_domain", "value": "google-workspace-support.net", "weight": 0.90}
  ]
}""",
    },

    # ----- ENGLISH PHISHING: Credential Harvesting -----
    {
        "role": "user",
        "content": """Analyze this email:
FROM: it-support@helpdesk-portal.com
TO: employee@bank.sa
SUBJECT: Password Reset Required - Your Bank VPN Access
BODY:
IT Security Team - Password Reset Notification

Your corporate VPN password has been flagged for mandatory reset due to our quarterly security audit compliance.

Your current password was last changed 93 days ago. Per policy, passwords must be reset every 90 days.

Please reset your password within the next 4 hours to maintain VPN access:
[Reset Password] → https://vpn-reset.helpdesk-portal.com/reset?emp=3847

Your new password must meet complexity requirements. After reset, you may need to re-authenticate on all devices.

IT Security Team""",
    },
    {
        "role": "assistant",
        "content": """{
  "threat_indicators": [
    "Corporate IT impersonation from external helpdesk-portal.com domain",
    "Credential phishing for VPN password reset",
    "4-hour deadline for password reset",
    "Suspicious URL: vpn-reset.helpdesk-portal.com (not corporate domain)",
    "Employee ID in URL (emp=3847) to appear legitimate"
  ],
  "urgency_score": 80,
  "impersonation_detected": true,
  "impersonation_target": "Corporate IT Security Team",
  "language": "en",
  "classification": "PHISHING",
  "confidence": 0.94,
  "explanation_ar": "هجوم تصيد يستهدف كلمة مرور VPN للموظفين. يستخدم الهجوم ذريعة انتهاء صلاحية كلمة المرور لإجبار الموظف على إدخال بياناته على موقع خارجي. الحصول على بيانات VPN يمكّن المهاجم من الدخول المباشر إلى شبكة البنك.",
  "explanation_en": "VPN credential phishing targeting bank employees. This is particularly dangerous as VPN credentials provide direct network access. Corporate IT password resets always originate from official corporate domains, not helpdesk-portal.com. The employee ID in the URL is a personalization tactic to increase credibility. Banks should implement SAML/SSO with MFA for VPN access to make stolen passwords ineffective.",
  "signals": [
    {"name": "vpn_credential_phishing", "value": "vpn-reset.helpdesk-portal.com", "weight": 0.97},
    {"name": "external_it_impersonation", "value": "helpdesk-portal.com not corporate domain", "weight": 0.95},
    {"name": "4_hour_urgency_deadline", "value": "reset within 4 hours", "weight": 0.83},
    {"name": "personalized_url_tactic", "value": "emp=3847 parameter", "weight": 0.65}
  ]
}""",
    },

    # ----- MALWARE: Attachment-based, Arabic lure -----
    {
        "role": "user",
        "content": """Analyze this email:
FROM: tenders@procurement-gulf.net
TO: procurement@company.sa
SUBJECT: طلب عرض سعر - مناقصة حكومية عاجلة - ترسية فورية
ATTACHMENT: عرض_سعر_مناقصة_2024.docm
BODY:
السادة المحترمون،

يسرنا التواصل معكم بشأن مناقصة حكومية عاجلة تتعلق بتوريد معدات تقنية بقيمة تقديرية 15 مليون ريال.

المناقصة مفتوحة لفترة محدودة جداً وتنتهي خلال 48 ساعة. تجد مرفقاً ملف Microsoft Word يحتوي على كامل تفاصيل المناقصة ومتطلبات عرض السعر.

يرجى فتح الملف المرفق وتفعيل وحدات الماكرو لعرض المستند كاملاً.

مع التقدير،
لجنة المناقصات والمشتريات الحكومية""",
    },
    {
        "role": "assistant",
        "content": """{
  "threat_indicators": [
    "Macro-enabled Word document (.docm) attachment - malware delivery vector",
    "Explicit instruction to enable macros",
    "Government tender impersonation lure (15 million SAR)",
    "Urgent 48-hour deadline to bypass security review",
    "Sender from non-government procurement-gulf.net domain"
  ],
  "urgency_score": 88,
  "impersonation_detected": true,
  "impersonation_target": "لجنة المناقصات الحكومية (Government Procurement Committee)",
  "language": "ar",
  "classification": "MALWARE",
  "confidence": 0.97,
  "explanation_ar": "هجوم تسليم برمجيات خبيثة عبر ملف Word يحتوي على ماكرو ضار. الطُعم المستخدم هو مناقصة حكومية بقيمة 15 مليون ريال. التعليمات الصريحة لتفعيل وحدات الماكرو هي الدليل القاطع على وجود محتوى خبيث - المستندات الشرعية لا تحتاج لتفعيل الماكرو لعرض محتواها. يُغلق هذا الملف ولا يُفتح.",
  "explanation_en": "Macro malware delivery using Arabic government tender lure. The .docm extension and explicit macro-enable instruction are definitive malware indicators. Legitimate tender documents never require macro activation to display content. Once macros are enabled, the payload typically downloads and executes ransomware, banking trojans, or RATs. The SAR 15M value is calibrated to be attractive enough to override caution. Block all .docm/.xlsm/.xlam attachments at email gateway.",
  "signals": [
    {"name": "macro_enabled_attachment", "value": "عرض_سعر_مناقصة_2024.docm", "weight": 0.99},
    {"name": "explicit_macro_enable_request", "value": "تفعيل وحدات الماكرو", "weight": 0.99},
    {"name": "high_value_lure", "value": "15 million SAR government tender", "weight": 0.82},
    {"name": "external_procurement_domain", "value": "procurement-gulf.net", "weight": 0.85},
    {"name": "48h_urgency_bypass", "value": "tender expires in 48 hours", "weight": 0.80}
  ]
}""",
    },

    # ----- MALWARE: Attachment-based (Salary/HR lure) -----
    {
        "role": "user",
        "content": """Analyze this email:
FROM: hr-payroll@salaries-update.net
TO: all-employees@company.sa
SUBJECT: إشعار هام: مراجعة الرواتب لعام 2024 - يرجى الاطلاع
ATTACHMENT: مراجعة_الرواتب_2024.xlsm
BODY:
موظفونا الكرام،

تود إدارة الموارد البشرية إحاطتكم بنتائج مراجعة هيكل الرواتب لعام 2024. 

يرجى فتح الملف المرفق للاطلاع على تفاصيل الراتب الجديد ومقارنته بالراتب الحالي.
ملاحظة: قد تحتاج إلى تفعيل المحتوى عند فتح الملف لعرض البيانات كاملاً.

إدارة الموارد البشرية""",
    },
    {
        "role": "assistant",
        "content": """{
  "threat_indicators": [
    "Macro-enabled Excel attachment (.xlsm) - malware delivery",
    "Instruction to 'enable content' upon opening",
    "Salary review lure targeting all employees",
    "Sender from external salaries-update.net domain (not corporate HR)",
    "Mass email targeting (all-employees)"
  ],
  "urgency_score": 75,
  "impersonation_detected": true,
  "impersonation_target": "إدارة الموارد البشرية (Corporate HR Department)",
  "language": "ar",
  "classification": "MALWARE",
  "confidence": 0.95,
  "explanation_ar": "هجوم توصيل برمجيات خبيثة يستخدم طُعم مراجعة الرواتب. الملف المرفق .xlsm هو ملف Excel مفعّل للماكرو. 'تفعيل المحتوى' هو المصطلح الذي يستخدمه Microsoft عند تشغيل الماكرو في Excel. الهجوم يستهدف جميع الموظفين مرة واحدة لتعظيم احتمال الإصابة.",
  "explanation_en": "Salary-themed malware delivery using Excel macro document (.xlsm). 'Enable content' instruction is the Office security warning users see before macros execute. This bulk phishing attack targets all employees simultaneously — even 1% click rate across a large organization guarantees multiple infections. Real HR salary communications come from corporate HR systems (SAP SuccessFactors, etc.) with official corporate domains, never from salaries-update.net.",
  "signals": [
    {"name": "xlsm_macro_attachment", "value": "مراجعة_الرواتب_2024.xlsm", "weight": 0.99},
    {"name": "enable_content_instruction", "value": "تفعيل المحتوى", "weight": 0.98},
    {"name": "mass_targeting", "value": "all-employees@company.sa", "weight": 0.75},
    {"name": "external_hr_domain", "value": "salaries-update.net", "weight": 0.92}
  ]
}""",
    },

    # ----- LOOKALIKE DOMAIN: Saudi Bank -----
    {
        "role": "user",
        "content": """Analyze this email:
FROM: alerts@al-rajhibank.com
TO: customer@personal.sa
SUBJECT: تنبيه أمني: تم اكتشاف معاملة مشبوهة على حسابك - اتخاذ فوري
BODY:
عزيزي العميل،

تنبيه أمني من بنك الراجحي:
تم رصد محاولة دخول مشبوهة لحسابك المصرفي من موقع جغرافي غير معتاد.

للحفاظ على أمان حسابك، يرجى التحقق من هويتك فوراً:
[تحقق من حسابك] → https://al-rajhibank.com/verify/SA-2847

رقم التنبيه: ALR-2024-78234

بنك الراجحي - إدارة أمن المعلومات""",
    },
    {
        "role": "assistant",
        "content": """{
  "threat_indicators": [
    "Lookalike domain: al-rajhibank.com vs alrajhibank.com.sa",
    "Hyphen insertion to create convincing domain variant",
    "Saudi banking credential phishing",
    "Security alert social engineering",
    "External link for account verification"
  ],
  "urgency_score": 90,
  "impersonation_detected": true,
  "impersonation_target": "بنك الراجحي (Al Rajhi Bank)",
  "language": "ar",
  "classification": "LOOKALIKE_DOMAIN",
  "confidence": 0.97,
  "explanation_ar": "هجوم انتحال هوية بنك الراجحي باستخدام نطاق شبيه. النطاق الرسمي للبنك هو alrajhibank.com.sa بينما يستخدم المهاجم al-rajhibank.com (إضافة شرطة وحذف .sa). الهجوم يستهدف سرقة بيانات الاعتماد المصرفية عبر صفحة تحقق مزيفة.",
  "explanation_en": "Lookalike domain attack targeting Al Rajhi Bank customers. The legitimate domain is alrajhibank.com.sa (Saudi TLD). The attacker registered al-rajhibank.com (hyphenated + different TLD) — a classic lookalike technique. The Levenshtein distance between 'al-rajhibank' and 'alrajhibank' is 1 (hyphen insertion). Banking security alerts from Saudi banks always direct customers to official apps or branches, never to credential verification links via email.",
  "signals": [
    {"name": "lookalike_domain_hyphen", "value": "al-rajhibank.com vs alrajhibank.com.sa", "weight": 0.98},
    {"name": "tld_mismatch", "value": ".com vs .com.sa", "weight": 0.90},
    {"name": "banking_credential_phishing", "value": "/verify/SA-2847 link", "weight": 0.95},
    {"name": "security_alert_social_engineering", "value": "suspicious login from unusual location", "weight": 0.85}
  ]
}""",
    },

    # ----- LOOKALIKE DOMAIN: UAE Exchange -----
    {
        "role": "user",
        "content": """Analyze this email:
FROM: transfers@emiratesnbd-online.com
TO: customer@uaecompany.ae
SUBJECT: Emirates NBD: Pending International Transfer - Verification Required
BODY:
Dear Valued Customer,

Emirates NBD Online Banking

A pending international wire transfer of AED 45,000 has been initiated from your account and requires your verification before processing.

Transfer Details:
- Amount: AED 45,000
- Beneficiary: International Trading Corp
- IBAN: GB29 NWBK 6016 1331 9268 19
- Reference: ENB-TRF-2024-9823

Please verify this transfer within 2 hours to prevent cancellation:
[Verify Transfer] → https://emiratesnbd-online.com/verify-transfer

Emirates NBD Customer Security""",
    },
    {
        "role": "assistant",
        "content": """{
  "threat_indicators": [
    "Emirates NBD lookalike domain: emiratesnbd-online.com vs emiratesnbd.com",
    "Pending transfer verification phishing (AED 45,000)",
    "UK IBAN beneficiary unusual for UAE bank transfer",
    "2-hour cancellation deadline",
    "Phishing verification link on lookalike domain"
  ],
  "urgency_score": 92,
  "impersonation_detected": true,
  "impersonation_target": "Emirates NBD Bank",
  "language": "en",
  "classification": "LOOKALIKE_DOMAIN",
  "confidence": 0.96,
  "explanation_ar": "هجوم انتحال هوية بنك الإمارات دبي الوطني باستخدام نطاق شبيه (emiratesnbd-online.com بدلاً من emiratesnbd.com). يدّعي الهجوم وجود تحويل مالي معلق لاستفزاز الضحية على النقر على رابط التحقق المزيف.",
  "explanation_en": "Emirates NBD lookalike domain attack. The real domain is emiratesnbd.com — the attacker appended '-online' to create emiratesnbd-online.com. The UK IBAN (GB29 NWBK) as beneficiary is suspicious for a UAE-initiated transfer and may be designed to steal the customer's online banking credentials when they 'verify.' Emirates NBD never requests transfer verification via email links — customers must use the official app or call the published helpline number.",
  "signals": [
    {"name": "nbd_lookalike_domain", "value": "emiratesnbd-online.com vs emiratesnbd.com", "weight": 0.97},
    {"name": "uk_iban_suspicious_beneficiary", "value": "GB29 NWBK... for UAE transaction", "weight": 0.82},
    {"name": "transfer_verification_phishing", "value": "/verify-transfer on lookalike domain", "weight": 0.96},
    {"name": "2h_cancellation_pressure", "value": "verify within 2 hours", "weight": 0.85}
  ]
}""",
    },

    # ----- BENIGN: Normal Arabic business email -----
    {
        "role": "user",
        "content": """Analyze this email:
FROM: supplier@legit-vendor.com
TO: procurement@company.sa
SUBJECT: فاتورة رقم INV-2024-1045 - توريد أجهزة حاسوب
BODY:
السادة المحترمون،

نرجو أن تكونوا بخير. نرفق طيه فاتورتنا رقم INV-2024-1045 بتاريخ اليوم مقابل توريد 25 جهاز حاسوب محمول Dell Latitude 5540 كما تم الاتفاق في عقد رقم PO-2024-078.

المبلغ الإجمالي: 187,500 ريال سعودي
شروط الدفع: 30 يوم من تاريخ الفاتورة
رقم الحساب: كما هو مسجل لدى إدارة المشتريات

نتمنى لكم التوفيق ونسعد بخدمتكم دائماً.

مع خالص التحية،
قسم المبيعات
شركة تقنية المستقبل""",
    },
    {
        "role": "assistant",
        "content": """{
  "threat_indicators": [],
  "urgency_score": 10,
  "impersonation_detected": false,
  "impersonation_target": null,
  "language": "ar",
  "classification": "BENIGN",
  "confidence": 0.92,
  "explanation_ar": "هذا بريد إلكتروني تجاري عادي لإرسال فاتورة. يستشهد بعقد وأمر شراء محددين، ولا يطلب تغيير بيانات الدفع، ولا يتضمن روابط احتيالية أو طلبات عاجلة مريبة. المبلغ متوافق مع فاتورة توريد أجهزة عادية.",
  "explanation_en": "Routine invoice email for computer equipment supply. References a specific contract (PO-2024-078) and invoice number, uses registered payment account (not requesting account change), no phishing links, no urgency tactics. The amount (SAR 187,500) is consistent with 25 laptops at market price. Standard procurement communication.",
  "signals": [
    {"name": "references_existing_po", "value": "PO-2024-078", "weight": 0.1},
    {"name": "no_account_change_request", "value": "using registered account", "weight": 0.05},
    {"name": "no_suspicious_links", "value": "no external URLs", "weight": 0.05}
  ]
}""",
    },

    # ----- BENIGN: English business email -----
    {
        "role": "user",
        "content": """Analyze this email:
FROM: john.smith@microsoft.com
TO: it-admin@company.sa
SUBJECT: Re: Microsoft 365 E5 License Renewal - Account #MS-784532
BODY:
Hi Ahmed,

Following up on our call last Thursday regarding your Microsoft 365 E5 renewal for 500 seats.

As discussed, I've confirmed the pricing for the 3-year agreement:
- 500 x M365 E5: $57 per user/month = $28,500/month
- 20% loyalty discount applied: $22,800/month
- Annual commitment: $273,600

Please review the attached PDF proposal and let me know if you'd like to proceed before the end of Q1 for the promotional pricing.

You can reach me at +1-425-882-8080 (Microsoft main) or directly on Teams.

Best regards,
John Smith
Microsoft Enterprise Account Manager
Microsoft Corporation | Redmond, WA""",
    },
    {
        "role": "assistant",
        "content": """{
  "threat_indicators": [],
  "urgency_score": 20,
  "impersonation_detected": false,
  "impersonation_target": null,
  "language": "en",
  "classification": "BENIGN",
  "confidence": 0.89,
  "explanation_ar": "هذا بريد إلكتروني تجاري عادي من مندوب مبيعات Microsoft. يأتي من النطاق الرسمي microsoft.com، ويستشهد بمكالمة سابقة ورقم حساب محدد، ويقدم معلومات اتصال رسمية قابلة للتحقق.",
  "explanation_en": "Legitimate Microsoft sales email from verified @microsoft.com domain. References a prior call and specific account number, provides verifiable Microsoft contact information (+1-425-882-8080 is a real Microsoft number), and the pricing is consistent with published M365 E5 rates. Minor Q1 deadline urgency is normal sales practice, not social engineering. No phishing links — standard PDF attachment for contract review.",
  "signals": [
    {"name": "official_microsoft_domain", "value": "john.smith@microsoft.com", "weight": 0.05},
    {"name": "references_prior_contact", "value": "call last Thursday", "weight": 0.05},
    {"name": "verifiable_contact_info", "value": "+1-425-882-8080 Microsoft main", "weight": 0.05}
  ]
}""",
    },

    # ----- BENIGN: Arabic internal communication -----
    {
        "role": "user",
        "content": """Analyze this email:
FROM: it.support@company.sa
TO: all-staff@company.sa
SUBJECT: صيانة مجدولة للبنية التحتية - الجمعة 15 مارس 2024
BODY:
زملاءنا الكرام،

نودّ إبلاغكم بأن قسم تقنية المعلومات سيقوم بأعمال صيانة مجدولة لتحديث البنية التحتية للشبكة يوم الجمعة 15 مارس 2024 من الساعة 11 مساءً حتى 3 صباحاً.

خلال هذه الفترة:
- قد يتأثر الوصول إلى VPN
- نظام البريد الإلكتروني قد يكون بطيئاً
- منصة SharePoint ستكون متاحة بشكل محدود

لا يوجد أي إجراء مطلوب من جانبكم. إذا كان لديكم أي استفسار، يرجى التواصل مع مكتب المساعدة على الرقم الداخلي 1234.

مع الشكر والتقدير،
قسم تقنية المعلومات""",
    },
    {
        "role": "assistant",
        "content": """{
  "threat_indicators": [],
  "urgency_score": 5,
  "impersonation_detected": false,
  "impersonation_target": null,
  "language": "ar",
  "classification": "BENIGN",
  "confidence": 0.96,
  "explanation_ar": "إشعار صيانة داخلي عادي من قسم تقنية المعلومات. يأتي من النطاق الرسمي للشركة، ولا يطلب أي إجراء من المستخدمين، ولا يتضمن روابط أو مرفقات، ويوفر وسيلة تحقق داخلية (الرقم الداخلي 1234).",
  "explanation_en": "Routine scheduled maintenance notification from internal IT department. Sent from corporate domain (it.support@company.sa), no action required from users, no links or attachments, provides internal contact verification (extension 1234). This is a textbook benign IT communication — transparent about impact, specific about timing, no urgency manipulation.",
  "signals": [
    {"name": "internal_corporate_sender", "value": "it.support@company.sa", "weight": 0.05},
    {"name": "no_action_required", "value": "explicit no action needed", "weight": 0.05},
    {"name": "internal_contact_provided", "value": "extension 1234", "weight": 0.05}
  ]
}""",
    },
]


def build_classification_prompt(
    sender: str,
    recipient: str,
    subject: str,
    body: str,
    attachments: list[str] | None = None,
    headers: dict[str, str] | None = None,
) -> str:
    """
    Build the user-turn prompt for email classification.

    Args:
        sender: Sender email address
        recipient: Recipient email address
        subject: Email subject line
        body: Email body text
        attachments: List of attachment filenames
        headers: Relevant email headers (SPF, DKIM, DMARC results)

    Returns:
        Formatted prompt string
    """
    parts = [f"Analyze this email:\nFROM: {sender}\nTO: {recipient}\nSUBJECT: {subject}"]

    if headers:
        parts.append("HEADERS:")
        for k, v in headers.items():
            parts.append(f"  {k}: {v}")

    if attachments:
        parts.append(f"ATTACHMENTS: {', '.join(attachments)}")

    parts.append(f"BODY:\n{body}")

    return "\n".join(parts)


def get_messages_for_classification(
    sender: str,
    recipient: str,
    subject: str,
    body: str,
    attachments: list[str] | None = None,
    headers: dict[str, str] | None = None,
    include_few_shot: bool = True,
) -> list[dict[str, str]]:
    """
    Build the full messages list for the LLM API call.

    Args:
        sender: Sender email address
        recipient: Recipient email address
        subject: Email subject
        body: Email body
        attachments: Attachment filenames
        headers: Email header analysis
        include_few_shot: Whether to include few-shot examples (increases accuracy but token cost)

    Returns:
        List of message dicts for the chat API
    """
    messages = []

    if include_few_shot:
        messages.extend(FEW_SHOT_EXAMPLES)

    user_prompt = build_classification_prompt(
        sender=sender,
        recipient=recipient,
        subject=subject,
        body=body,
        attachments=attachments,
        headers=headers,
    )

    messages.append({"role": "user", "content": user_prompt})
    return messages


# Classification output JSON schema for reference
CLASSIFICATION_JSON_SCHEMA = {
    "type": "object",
    "required": [
        "threat_indicators", "urgency_score", "impersonation_detected",
        "impersonation_target", "language", "classification", "confidence",
        "explanation_ar", "explanation_en", "signals"
    ],
    "properties": {
        "threat_indicators": {"type": "array", "items": {"type": "string"}},
        "urgency_score": {"type": "integer", "minimum": 0, "maximum": 100},
        "impersonation_detected": {"type": "boolean"},
        "impersonation_target": {"type": ["string", "null"]},
        "language": {"type": "string", "enum": ["ar", "en", "mixed"]},
        "classification": {
            "type": "string",
            "enum": [c.value for c in ThreatClassification]
        },
        "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "explanation_ar": {"type": "string"},
        "explanation_en": {"type": "string"},
        "signals": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["name", "value", "weight"],
                "properties": {
                    "name": {"type": "string"},
                    "value": {"type": "string"},
                    "weight": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                }
            }
        }
    }
}
