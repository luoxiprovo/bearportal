-- Stable request labeling survives retries; invoice problems block new installation.
ALTER TABLE billing_subscriptions ADD COLUMN checkout_integration_identifier text;
ALTER TABLE billing_subscriptions ADD COLUMN invoice_issue_code text;
