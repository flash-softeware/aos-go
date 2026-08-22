package schema

import _ "embed"

// SQL is the canonical database DDL (aos.sql).
//
//go:embed aos.sql
var SQL string

// MigrationV2SQL upgrades v1 installs to organization-aware IAM.
//
//go:embed migration_v2.sql
var MigrationV2SQL string
