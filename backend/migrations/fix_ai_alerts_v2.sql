-- Fix any remaining AI-prefixed alerts
UPDATE saas_alerts 
SET alert_type = REPLACE(alert_type, 'ai_', '')
WHERE alert_type LIKE 'ai_%';

UPDATE saas_alerts 
SET title = REPLACE(title, 'AI Risk: ', '')
WHERE title LIKE 'AI Risk:%';

UPDATE saas_alerts 
SET title = REPLACE(title, 'AI-Risk: ', '')
WHERE title LIKE 'AI-Risk:%';

UPDATE saas_alerts 
SET title = REPLACE(title, 'AI ', '')
WHERE title LIKE 'AI %';

UPDATE aws_findings
SET category = 'dlp'
WHERE category = 'ai_dlp';
