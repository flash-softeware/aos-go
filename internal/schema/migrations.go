package schema

import (
	schemasql "github.com/Esubalew-Sintie/aos-auth-go/schema"
)

// Migrations applies the canonical schema in one step.
var Migrations = []Migration{
	{
		Version: 1,
		Name:    "canonical",
		Up:      schemasql.SQL,
	},
	{
		Version: 2,
		Name:    "organization_iam",
		Up:      schemasql.MigrationV2SQL,
	},
}
