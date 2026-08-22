-- Migration v2: organization-scoped roles and session active resource IAM FK.

-- Org-scoped roles (NULL organization_id = global/system role).
ALTER TABLE roles ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES iam_resources(id) ON DELETE CASCADE;

ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_name_key;

CREATE UNIQUE INDEX IF NOT EXISTS uq_roles_system_name
    ON roles (name) WHERE organization_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_roles_org_name
    ON roles (organization_id, name) WHERE organization_id IS NOT NULL;

-- Migrate session active_resource_id from business UUID to iam_resources.id when needed.
UPDATE user_sessions s
SET active_resource_id = ir.id
FROM iam_resources ir
WHERE s.active_resource_id IS NOT NULL
  AND s.active_resource_id = ir.resource_id
  AND NOT EXISTS (
      SELECT 1 FROM iam_resources ir2 WHERE ir2.id = s.active_resource_id
  );

-- Clear orphaned active resources that cannot be resolved.
UPDATE user_sessions s
SET active_resource_id = NULL
WHERE s.active_resource_id IS NOT NULL
  AND NOT EXISTS (
      SELECT 1 FROM iam_resources ir WHERE ir.id = s.active_resource_id
  );

ALTER TABLE user_sessions DROP CONSTRAINT IF EXISTS fk_session_active_resource;

ALTER TABLE user_sessions
    ADD CONSTRAINT fk_session_active_resource
    FOREIGN KEY (active_resource_id) REFERENCES iam_resources(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_role_assignments_active
    ON role_assignments (membership_id, resource_id)
    WHERE expires_at IS NULL;
