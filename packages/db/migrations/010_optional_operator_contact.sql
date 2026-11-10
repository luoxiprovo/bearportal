-- Server ownership contact is informational and can be omitted.
ALTER TABLE servers ALTER COLUMN operator_contact DROP NOT NULL;
