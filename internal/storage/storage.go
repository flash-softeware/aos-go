package storage

import (
	"context"
	"time"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/dto/response"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/entities"
)

// Storage composes repository interfaces — the only persistence dependency for Auth/AuthZ.
type Storage interface {
	Users() UserRepository
	Sessions() SessionRepository
	AuthAccounts() AuthAccountRepository

	Roles() RoleRepository
	Permissions() PermissionRepository
	Resources() ResourceRepository
	Memberships() MembershipRepository
	Invitations() InvitationRepository

	Authorization() AuthorizationRepository
	Audit() AuditRepository
	Mfa() MfaRepository
	Passkeys() PasskeyRepository
	Tokens() TokenRepository

	Transaction(ctx context.Context, fn func(tx Storage) error) error
	Migrate(ctx context.Context) error
	Close(ctx context.Context) error
}

type UserRepository interface {
	Create(ctx context.Context, user *entities.User) error
	GetByID(ctx context.Context, id string) (*entities.User, error)
	GetByEmail(ctx context.Context, email string) (*entities.User, error)
	Update(ctx context.Context, user *entities.User) error
	Delete(ctx context.Context, id string) error
	Activate(ctx context.Context, userID string) error
	CompleteInvitation(ctx context.Context, userID, firstName, lastName string) error
}

type SessionRepository interface {
	Create(ctx context.Context, session *entities.Session) error
	GetByTokenHash(ctx context.Context, tokenHash string) (*entities.Session, error)
	Delete(ctx context.Context, tokenHash string) error
	DeleteUserSessions(ctx context.Context, userID, exceptTokenHash string) error
	SetActiveResource(ctx context.Context, tokenHash, resourceID string) error
	ListByUser(ctx context.Context, userID string) ([]response.UserSession, error)
	RevokeByID(ctx context.Context, userID, sessionID string) error
}

type AuthAccountRepository interface {
	Create(ctx context.Context, account *entities.AuthAccount) error
	GetByProvider(ctx context.Context, provider, providerUserID string) (*entities.AuthAccount, error)
	GetLocalByUserID(ctx context.Context, userID string) (*entities.AuthAccount, error)
	UpdatePassword(ctx context.Context, userID, passwordHash string) error
}

type RoleRepository interface {
	Create(ctx context.Context, role *entities.Role) error
	GetByID(ctx context.Context, id string) (*entities.Role, error)
	GetByName(ctx context.Context, name string) (*entities.Role, error)
	GetSystemByName(ctx context.Context, name string) (*entities.Role, error)
	GetByNameForOrg(ctx context.Context, orgIAMID, name string) (*entities.Role, error)
	List(ctx context.Context) ([]*entities.Role, error)
	Delete(ctx context.Context, id string) error
	GrantPermission(ctx context.Context, roleID, permissionCode string) (*entities.Permission, error)
	RevokePermission(ctx context.Context, roleID, permissionCode string) (*entities.Permission, error)
}

type PermissionRepository interface {
	Create(ctx context.Context, permission *entities.Permission) error
	GetByCode(ctx context.Context, code string) (*entities.Permission, error)
	List(ctx context.Context) ([]*entities.Permission, error)
}

type ResourceRepository interface {
	Create(ctx context.Context, resource *entities.Resource) error
	GetByID(ctx context.Context, id string) (*entities.Resource, error)
	GetByBusinessID(ctx context.Context, resourceType, businessID string) (*entities.Resource, error)
	GetByType(ctx context.Context, resourceType string) (*entities.Resource, error)
	GetAncestorChain(ctx context.Context, iamResourceID string) ([]*entities.Resource, error)
	Delete(ctx context.Context, id string) error
}

type MembershipRepository interface {
	Create(ctx context.Context, membership *entities.Membership) error
	Get(ctx context.Context, userID, resourceType, resourceID string) (*entities.Membership, error)
	ListByUser(ctx context.Context, userID string) ([]*entities.Membership, error)
	AssignRole(ctx context.Context, membershipID, iamResourceID, roleID string) error
	Remove(ctx context.Context, id string) error
	HasOnResource(ctx context.Context, userID, resourceID string) (bool, error)
	ListOrganizationsForUser(ctx context.Context, userID string) ([]response.UserOrganization, error)
	ListMembers(ctx context.Context, resourceType, resourceID string) ([]response.OrgMember, error)
}

type InvitationRepository interface {
	Create(ctx context.Context, invitation *entities.Invitation) error
	GetPending(ctx context.Context, email, resourceType, resourceID string) (*entities.Invitation, error)
	UpdateStatus(ctx context.Context, id, status string) error
}

type AuthorizationRepository interface {
	Can(ctx context.Context, userID, resourceID, permission string) (bool, error)
	PermissionCodes(ctx context.Context, userID, resourceID string) ([]string, error)
}

type AuditRepository interface {
	Insert(ctx context.Context, tenantID, userID, action, resourceType, resourceID, result string, details map[string]interface{}, ipAddress string) error
	List(ctx context.Context, tenantID, action string, limit, offset int) ([]response.AuditLog, error)
}

type MfaRepository interface {
	Status(ctx context.Context, userID string) (enabled, verified bool, err error)
	// UpsertSecret stores an encrypted TOTP secret (enc:v1:…).
	UpsertSecret(ctx context.Context, userID, secret string) error
	// GetSecret returns the encrypted TOTP secret as stored.
	GetSecret(ctx context.Context, userID string) (string, error)
	// Enable persists bcrypt-hashed recovery codes in recovery_codes JSONB.
	Enable(ctx context.Context, userID string, recoveryCodeHashes []string) error
	GetWithRecovery(ctx context.Context, userID string) (secret string, recoveryCodeHashes []string, err error)
	UpdateRecoveryCodes(ctx context.Context, userID string, recoveryCodeHashes []string) error
	Disable(ctx context.Context, userID string) error
	InsertChallenge(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error
	ConsumeChallenge(ctx context.Context, tokenHash string) (userID string, err error)
}

type PasskeyRepository interface {
	InsertChallenge(ctx context.Context, userID, challenge string, expiresAt time.Time) error
	GetChallenge(ctx context.Context, userID string) (string, error)
	DeleteChallenge(ctx context.Context, userID string) error
	Insert(ctx context.Context, userID, credentialID, publicKey string, signCount int64, deviceName string, backupEligible, backedUp bool) error
	List(ctx context.Context, userID string) ([]response.Passkey, error)
	ListRecords(ctx context.Context, userID string) ([]response.PasskeyRecord, error)
	UpdateSignCount(ctx context.Context, userID, credentialID string, signCount int64) error
}

type TokenRepository interface {
	Insert(ctx context.Context, userID, tokenType, plainToken string, metadata []byte, expiresAt time.Time) error
	Consume(ctx context.Context, tokenHash, tokenType string) (userID string, err error)
	ConsumeWithMetadata(ctx context.Context, tokenHash, tokenType string) (userID string, metadata []byte, err error)
}

type Store = Storage
