-- Fix alerts that have "AI" prefix in title or alert_type
-- Remove "AI DLP" and "AI-risk" style alerts that were created by older code versions

-- Update alert_type: replace 'ai_risk' and 'dlp_classification' with proper category names
UPDATE saas_alerts
SET alert_type = 'sensitive_data'
WHERE alert_type IN ('ai_risk', 'dlp_classification', 'AI_risk', 'AI-risk');

-- Update titles: strip "AI DLP:" prefix from alert titles
UPDATE saas_alerts
SET title = REGEXP_REPLACE(title, '^AI[-\s]?DLP[:]\s*', 'DLP: ', 'i')
WHERE title ~* '^AI[-\s]?DLP:';

-- Update titles: strip "AI risk:" prefix from alert titles
UPDATE saas_alerts
SET title = REGEXP_REPLACE(title, '^AI[-\s]?risk[:]\s*', '', 'i')
WHERE title ~* '^AI[-\s]?risk:';

-- Update descriptions: clean up "AI DLP classification flagged" to "DLP classification flagged"
UPDATE saas_alerts
SET description = REPLACE(description, 'AI DLP classification flagged', 'DLP classification flagged')
WHERE description LIKE '%AI DLP classification flagged%';

-- Also fix aws_findings with AI in description
UPDATE aws_findings
SET description = REPLACE(description, 'AI DLP classification flagged', 'DLP classification flagged')
WHERE description LIKE '%AI DLP classification flagged%';
