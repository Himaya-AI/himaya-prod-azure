-- Migration: add US compliance controls (NIST CSF, HIPAA, SOC 2, CCPA)
-- Run once on existing databases

INSERT INTO compliance_controls (framework, control_id, control_name_en, control_name_ar, evidence_type) VALUES
-- NIST CSF
('NIST_CSF', 'PR.AC-1',  'Identity Management & Authentication', 'Identity Management & Authentication', 'authentication'),
('NIST_CSF', 'PR.AC-3',  'Remote Access Management',             'Remote Access Management',             'access_control'),
('NIST_CSF', 'PR.DS-1',  'Data-at-Rest Protection',              'Data-at-Rest Protection',              'data_protection'),
('NIST_CSF', 'PR.DS-2',  'Data-in-Transit Protection',           'Data-in-Transit Protection',           'data_protection'),
('NIST_CSF', 'DE.AE-1',  'Baseline Network Operations',          'Baseline Network Operations',          'threat_detection'),
('NIST_CSF', 'DE.AE-2',  'Anomaly & Event Detection',            'Anomaly & Event Detection',            'threat_detection'),
('NIST_CSF', 'DE.CM-1',  'Network Continuous Monitoring',        'Network Continuous Monitoring',        'monitoring'),
('NIST_CSF', 'DE.CM-7',  'Unauthorized Activity Monitoring',     'Unauthorized Activity Monitoring',     'monitoring'),
('NIST_CSF', 'RS.RP-1',  'Response Plan Execution',              'Response Plan Execution',              'incident_response'),
('NIST_CSF', 'RS.CO-3',  'Information Sharing',                  'Information Sharing',                  'incident_response'),
-- HIPAA
('HIPAA', '164.312(a)(1)',   'Access Control — Unique User Identification', 'Access Control — Unique User Identification', 'authentication'),
('HIPAA', '164.312(a)(2)(i)','Emergency Access Procedure',                 'Emergency Access Procedure',                 'access_control'),
('HIPAA', '164.312(b)',      'Audit Controls',                             'Audit Controls',                             'monitoring'),
('HIPAA', '164.312(c)(1)',   'Integrity — ePHI Protection',                'Integrity — ePHI Protection',                'data_protection'),
('HIPAA', '164.312(d)',      'Person or Entity Authentication',             'Person or Entity Authentication',             'authentication'),
('HIPAA', '164.312(e)(1)',   'Transmission Security — Encryption',          'Transmission Security — Encryption',          'data_protection'),
('HIPAA', '164.308(a)(1)',   'Risk Analysis & Management',                  'Risk Analysis & Management',                  'risk_management'),
('HIPAA', '164.308(a)(5)',   'Security Awareness Training',                 'Security Awareness Training',                 'training'),
('HIPAA', '164.308(a)(6)',   'Security Incident Procedures',                'Security Incident Procedures',                'incident_response'),
('HIPAA', '164.308(a)(7)',   'Contingency Plan',                            'Contingency Plan',                            'incident_response'),
-- SOC 2
('SOC2', 'CC1.1', 'COSO — Board Oversight of Controls',       'COSO — Board Oversight of Controls',       'governance'),
('SOC2', 'CC2.1', 'Communication of Internal Control Info',   'Communication of Internal Control Info',   'governance'),
('SOC2', 'CC3.1', 'Risk Assessment — Specify Objectives',     'Risk Assessment — Specify Objectives',     'risk_management'),
('SOC2', 'CC3.2', 'Risk Identification & Analysis',           'Risk Identification & Analysis',           'risk_management'),
('SOC2', 'CC6.1', 'Logical & Physical Access Controls',       'Logical & Physical Access Controls',       'access_control'),
('SOC2', 'CC6.6', 'Security Against Threats — External',      'Security Against Threats — External',      'threat_detection'),
('SOC2', 'CC6.7', 'Data Transmission & Movement Controls',    'Data Transmission & Movement Controls',    'data_protection'),
('SOC2', 'CC7.1', 'Threat Detection & Monitoring',            'Threat Detection & Monitoring',            'monitoring'),
('SOC2', 'CC7.2', 'Monitoring for Anomalies',                 'Monitoring for Anomalies',                 'monitoring'),
('SOC2', 'CC7.3', 'Incident Identification & Response',       'Incident Identification & Response',       'incident_response'),
('SOC2', 'CC7.4', 'Incident Response & Recovery',             'Incident Response & Recovery',             'incident_response'),
('SOC2', 'CC8.1', 'Change Management Controls',               'Change Management Controls',               'governance'),
-- CCPA
('CCPA', '1798.100', 'Right to Know — Data Access',              'Right to Know — Data Access',              'data_protection'),
('CCPA', '1798.105', 'Right to Delete Personal Information',     'Right to Delete Personal Information',     'data_protection'),
('CCPA', '1798.110', 'Right to Know — Categories Collected',     'Right to Know — Categories Collected',     'data_protection'),
('CCPA', '1798.115', 'Right to Know — Data Sharing',             'Right to Know — Data Sharing',             'governance'),
('CCPA', '1798.120', 'Right to Opt-Out of Sale',                 'Right to Opt-Out of Sale',                 'governance'),
('CCPA', '1798.135', 'Methods for Submitting Opt-Out',           'Methods for Submitting Opt-Out',           'governance'),
('CCPA', '1798.150', 'Private Right of Action — Data Breach',    'Private Right of Action — Data Breach',    'incident_response'),
('CCPA', '1798.155', 'AG Enforcement & Civil Penalties',         'AG Enforcement & Civil Penalties',         'governance')
ON CONFLICT (framework, control_id) DO NOTHING;
