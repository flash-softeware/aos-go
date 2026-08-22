package errors

import (
	"errors"
	"net/http"
)

// ErrorType classifies errors for clients and logging.
type ErrorType string

const (
	ErrorTypeValidation   ErrorType = "validation"
	ErrorTypeNotFound     ErrorType = "not_found"
	ErrorTypeConflict     ErrorType = "conflict"
	ErrorTypeUnauthorized ErrorType = "unauthorized"
	ErrorTypeForbidden    ErrorType = "forbidden"
	ErrorTypeInternal     ErrorType = "internal"
	ErrorTypeRateLimit    ErrorType = "rate_limit"
	ErrorTypeUnknown      ErrorType = "unknown"
)

// ── Generic / HTTP ────────────────────────────────────────────────────────────

var (
	ErrUnexpected          = errors.New("unexpected error. please try again")
	ErrInternalServerError = errors.New("something went wrong. please try again later")
	ErrBadRequest          = errors.New("bad request")
	ErrUnauthorized        = errors.New("unauthorized")
	ErrForbidden           = errors.New("forbidden")
	ErrNotFound            = errors.New("not found")
	ErrConflict            = errors.New("conflict")
	ErrValidation          = errors.New("validation error")
	ErrTooManyRequests     = errors.New("too many requests")
)

// ── Validation ──────────────────────────────────────────────────────────────

var (
	ErrRequiredField   = errors.New("required field is missing")
	ErrInvalidEmail    = errors.New("invalid email address")
	ErrInvalidPassword = errors.New("invalid password")
	ErrPasswordTooShort = errors.New("password must be at least 8 characters")
	ErrInvalidUUID     = errors.New("invalid id")
	ErrInvalidJSON     = errors.New("invalid json payload")
	ErrInvalidInput    = errors.New("invalid input")

	ErrUserIDRequired     = errors.New("user id is required")
	ErrResourceIDRequired = errors.New("resource id is required")
	ErrPermissionRequired = errors.New("permission is required")
	ErrOrgIDRequired      = errors.New("organization id is required")
	ErrTenantIDRequired   = errors.New("tenant id is required")
	ErrEmailRequired      = errors.New("email is required")
	ErrPasswordRequired   = errors.New("password is required")
)

// ── Authentication ────────────────────────────────────────────────────────────

var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrSessionInvalid     = errors.New("invalid or expired session")
	ErrSessionExpired     = errors.New("session has expired")
	ErrSessionRevoked     = errors.New("session has been revoked")
	ErrTokenInvalid       = errors.New("invalid or expired token")
	ErrTokenExpired       = errors.New("token has expired")
	ErrTokenConsumed      = errors.New("token has already been used")
)

// ── User ──────────────────────────────────────────────────────────────────────

var (
	ErrUserNotFound        = errors.New("user not found")
	ErrEmailAlreadyExists  = errors.New("this email address is already registered")
	ErrUsernameAlreadyExists = errors.New("this username is already taken")
	ErrUserLocked          = errors.New("account is locked")
	ErrUserSuspended       = errors.New("account is suspended")
	ErrUserPending         = errors.New("account is pending activation")
	ErrUserDeleted         = errors.New("account has been deleted")
	ErrEmailAlreadyVerified = errors.New("email is already verified")
)

// ── Auth lifecycle (password, email, invitation tokens) ───────────────────────

var (
	ErrPasswordResetTokenInvalid      = errors.New("invalid or expired reset token")
	ErrEmailVerificationTokenInvalid  = errors.New("invalid or expired verification token")
	ErrInvitationInvalid              = errors.New("invalid or expired invitation")
	ErrInvitationExpired              = errors.New("invitation has expired")
	ErrInvitationAlreadyAccepted      = errors.New("invitation has already been accepted")
	ErrInvitationAlreadyExists        = errors.New("invitation already exists")
	ErrInvitationNotFound             = errors.New("invitation not found")
	ErrInvitationRevoked              = errors.New("invitation has been revoked")
)

// ── MFA ───────────────────────────────────────────────────────────────────────

var (
	ErrMfaRequired              = errors.New("mfa required")
	ErrMfaNotEnabled             = errors.New("mfa is not enabled")
	ErrMfaAlreadyEnabled         = errors.New("mfa is already enabled")
	ErrMfaEnrollmentNotStarted   = errors.New("mfa enrollment not started")
	ErrMfaInvalidCode            = errors.New("invalid mfa code")
	ErrMfaInvalidVerificationCode = errors.New("invalid verification code")
	ErrMfaChallengeInvalid       = errors.New("invalid or expired mfa challenge")
	ErrMfaChallengeExpired       = errors.New("mfa challenge has expired")
	ErrMfaNotConfigured          = errors.New("mfa not configured")
)

// ── Passkeys / WebAuthn ───────────────────────────────────────────────────────

var (
	ErrWebAuthnNotConfigured       = errors.New("webauthn is not configured")
	ErrPasskeyNotFound             = errors.New("passkey not found")
	ErrPasskeyChallengeExpired     = errors.New("challenge expired or not found")
	ErrPasskeySessionExpired       = errors.New("passkey session expired, please start registration again")
	ErrPasskeyAuthenticationFailed = errors.New("passkey authentication failed")
	ErrNoPasskeysRegistered        = errors.New("no passkeys registered for this account")
)

// ── OAuth / social login ──────────────────────────────────────────────────────

var (
	ErrOAuthProviderNotConfigured = errors.New("oauth provider not configured")
	ErrOAuthStateInvalid          = errors.New("invalid oauth state")
	ErrOAuthAuthenticationFailed  = errors.New("oauth authentication failed")
	ErrOAuthCodeExchangeFailed    = errors.New("failed to exchange oauth code")
	ErrOAuthEmailMissing          = errors.New("oauth account has no email")
	ErrOAuthEmailNotVerified      = errors.New("oauth account has no verified email")
)

// ── Authorization (IAM) ───────────────────────────────────────────────────────

var (
	ErrPermissionDenied        = errors.New("permission denied")
	ErrPermissionNotFound      = errors.New("permission not found")
	ErrPermissionAlreadyExists = errors.New("permission already exists")
	ErrRoleNotFound            = errors.New("role not found")
	ErrRoleAlreadyExists       = errors.New("role already exists")
	ErrResourceNotFound        = errors.New("resource not found")
	ErrResourceAlreadyExists   = errors.New("resource already exists")
	ErrMembershipNotFound      = errors.New("membership not found")
	ErrMembershipAlreadyExists = errors.New("membership already exists")
	ErrNotMemberOfResource     = errors.New("not a member of this resource")
	ErrRoleAssignmentFailed    = errors.New("role assignment failed")
)

// ── Organization / resource context (app-defined resources) ───────────────────

var (
	ErrOrganizationNotFound    = errors.New("organization not found")
	ErrNotMemberOfOrganization = errors.New("not a member of this organization")
	ErrAlreadyMember           = errors.New("already a member")
	ErrNoActiveOrganization    = errors.New("no active organization")
	ErrOrganizationsDisabled   = errors.New("organizations not enabled")
	ErrOrganizationIDRequired  = errors.New("organization_id is required when organizations are enabled")
	ErrOrganizationScopeNotAllowed = errors.New("organization_id is not allowed when organizations are disabled")
	ErrOrganizationUpdateNotSupported = errors.New("organization update is not supported")
)

// ── Configuration / feature flags ─────────────────────────────────────────────

var (
	ErrPasswordAuthNotEnabled   = errors.New("password authentication is not enabled")
	ErrOAuthAuthNotEnabled      = errors.New("oauth authentication is not enabled")
	ErrDatabaseURLRequired      = errors.New("database URL or storage is required")
	ErrMfaEncryptionKeyRequired = errors.New("MFA encryption key is required when MFA is enabled")
	ErrNotSupported             = errors.New("not supported in v0.2 storage")
)

// ── Additional validation ─────────────────────────────────────────────────────

var (
	ErrNameRequired                     = errors.New("name is required")
	ErrUserAndOrgIDRequired             = errors.New("user id and organization id are required")
	ErrUserAndResourceIDRequired        = errors.New("user id and resource id are required")
	ErrSystemRoleCreateForbidden        = errors.New("system roles cannot be created via API when organizations are enabled")
	ErrRoleNameRequired                 = errors.New("role name is required")
	ErrRoleAlreadyExistsForOrganization = errors.New("role already exists for organization")
	ErrSystemRoleAlreadyExists          = errors.New("system role already exists")
	ErrResourceUnknown                  = errors.New("unknown resource")
	ErrMembershipAlreadyOnResource      = errors.New("user already has membership on resource")
)

// ── Crypto (MFA secrets) ──────────────────────────────────────────────────────

var (
	ErrEncryptionKeyEmpty   = errors.New("encryption key is required")
	ErrEncryptionKeyInvalid = errors.New("encryption key must decode to 32 bytes")
	ErrPlaintextEmpty     = errors.New("plaintext is required")
	ErrSecretEmpty        = errors.New("stored secret is empty")
	ErrCiphertextInvalid  = errors.New("ciphertext is invalid")
)

// ── Admin / enterprise plugins ────────────────────────────────────────────────

var (
	ErrPlatformAlreadyInitialized = errors.New("platform already initialized")
	ErrOwnerCredentialsRequired   = errors.New("owner email and password are required")

	ErrApiKeyNotFound  = errors.New("api key not found")
	ErrApiKeyRevoked   = errors.New("api key has been revoked")
	ErrWebhookNotFound = errors.New("webhook not found")
	ErrDomainNotFound  = errors.New("domain not found")
	ErrDomainNotVerified = errors.New("domain is not verified")
	ErrSsoConnectionNotFound  = errors.New("sso connection not found")
	ErrScimConnectionNotFound = errors.New("scim connection not found")
	ErrSecurityPolicyNotFound = errors.New("security policy not found")
	ErrNetworkRuleNotFound    = errors.New("network rule not found")
)

// ── Storage / infrastructure ──────────────────────────────────────────────────

var (
	ErrDatabaseUnavailable = errors.New("database unavailable")
	ErrMigrationFailed     = errors.New("database migration failed")
	ErrStorageNotFound     = errors.New("record not found")
	ErrStorageAlreadyExists = errors.New("record already exists")
	ErrStorageConflict     = errors.New("storage conflict")
)

// ErrorMap maps sentinel errors to HTTP status codes.
var ErrorMap map[error]int

// ErrorTypeMap maps sentinel errors to ErrorType values.
var ErrorTypeMap map[error]ErrorType

func init() {
	ErrorMap = make(map[error]int)
	ErrorTypeMap = make(map[error]ErrorType)

	// Generic
	register(ErrUnexpected, http.StatusInternalServerError, ErrorTypeInternal)
	register(ErrInternalServerError, http.StatusInternalServerError, ErrorTypeInternal)
	register(ErrBadRequest, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrUnauthorized, http.StatusUnauthorized, ErrorTypeUnauthorized)
	register(ErrForbidden, http.StatusForbidden, ErrorTypeForbidden)
	register(ErrNotFound, http.StatusNotFound, ErrorTypeNotFound)
	register(ErrConflict, http.StatusConflict, ErrorTypeConflict)
	register(ErrValidation, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrTooManyRequests, http.StatusTooManyRequests, ErrorTypeRateLimit)

	// Validation
	register(ErrRequiredField, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrInvalidEmail, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrInvalidPassword, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrPasswordTooShort, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrInvalidUUID, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrInvalidJSON, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrInvalidInput, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrUserIDRequired, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrResourceIDRequired, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrPermissionRequired, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrOrgIDRequired, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrTenantIDRequired, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrEmailRequired, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrPasswordRequired, http.StatusBadRequest, ErrorTypeValidation)

	// Authentication
	register(ErrInvalidCredentials, http.StatusUnauthorized, ErrorTypeUnauthorized)
	register(ErrSessionInvalid, http.StatusUnauthorized, ErrorTypeUnauthorized)
	register(ErrSessionExpired, http.StatusUnauthorized, ErrorTypeUnauthorized)
	register(ErrSessionRevoked, http.StatusUnauthorized, ErrorTypeUnauthorized)
	register(ErrTokenInvalid, http.StatusUnauthorized, ErrorTypeUnauthorized)
	register(ErrTokenExpired, http.StatusUnauthorized, ErrorTypeUnauthorized)
	register(ErrTokenConsumed, http.StatusConflict, ErrorTypeConflict)

	// User
	register(ErrUserNotFound, http.StatusNotFound, ErrorTypeNotFound)
	register(ErrEmailAlreadyExists, http.StatusConflict, ErrorTypeConflict)
	register(ErrUsernameAlreadyExists, http.StatusConflict, ErrorTypeConflict)
	register(ErrUserLocked, http.StatusForbidden, ErrorTypeForbidden)
	register(ErrUserSuspended, http.StatusForbidden, ErrorTypeForbidden)
	register(ErrUserPending, http.StatusForbidden, ErrorTypeForbidden)
	register(ErrUserDeleted, http.StatusNotFound, ErrorTypeNotFound)
	register(ErrEmailAlreadyVerified, http.StatusConflict, ErrorTypeConflict)

	// Auth lifecycle
	register(ErrPasswordResetTokenInvalid, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrEmailVerificationTokenInvalid, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrInvitationInvalid, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrInvitationExpired, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrInvitationAlreadyAccepted, http.StatusConflict, ErrorTypeConflict)
	register(ErrInvitationAlreadyExists, http.StatusConflict, ErrorTypeConflict)
	register(ErrInvitationNotFound, http.StatusNotFound, ErrorTypeNotFound)
	register(ErrInvitationRevoked, http.StatusConflict, ErrorTypeConflict)

	// MFA
	register(ErrMfaRequired, http.StatusUnauthorized, ErrorTypeUnauthorized)
	register(ErrMfaNotEnabled, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrMfaAlreadyEnabled, http.StatusConflict, ErrorTypeConflict)
	register(ErrMfaEnrollmentNotStarted, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrMfaInvalidCode, http.StatusUnauthorized, ErrorTypeUnauthorized)
	register(ErrMfaInvalidVerificationCode, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrMfaChallengeInvalid, http.StatusUnauthorized, ErrorTypeUnauthorized)
	register(ErrMfaChallengeExpired, http.StatusUnauthorized, ErrorTypeUnauthorized)
	register(ErrMfaNotConfigured, http.StatusBadRequest, ErrorTypeValidation)

	// Passkeys
	register(ErrWebAuthnNotConfigured, http.StatusServiceUnavailable, ErrorTypeInternal)
	register(ErrPasskeyNotFound, http.StatusNotFound, ErrorTypeNotFound)
	register(ErrPasskeyChallengeExpired, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrPasskeySessionExpired, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrPasskeyAuthenticationFailed, http.StatusUnauthorized, ErrorTypeUnauthorized)
	register(ErrNoPasskeysRegistered, http.StatusNotFound, ErrorTypeNotFound)

	// OAuth
	register(ErrOAuthProviderNotConfigured, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrOAuthStateInvalid, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrOAuthAuthenticationFailed, http.StatusUnauthorized, ErrorTypeUnauthorized)
	register(ErrOAuthCodeExchangeFailed, http.StatusBadGateway, ErrorTypeInternal)
	register(ErrOAuthEmailMissing, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrOAuthEmailNotVerified, http.StatusBadRequest, ErrorTypeValidation)

	// IAM
	register(ErrPermissionDenied, http.StatusForbidden, ErrorTypeForbidden)
	register(ErrPermissionNotFound, http.StatusNotFound, ErrorTypeNotFound)
	register(ErrPermissionAlreadyExists, http.StatusConflict, ErrorTypeConflict)
	register(ErrRoleNotFound, http.StatusNotFound, ErrorTypeNotFound)
	register(ErrRoleAlreadyExists, http.StatusConflict, ErrorTypeConflict)
	register(ErrResourceNotFound, http.StatusNotFound, ErrorTypeNotFound)
	register(ErrResourceAlreadyExists, http.StatusConflict, ErrorTypeConflict)
	register(ErrMembershipNotFound, http.StatusNotFound, ErrorTypeNotFound)
	register(ErrMembershipAlreadyExists, http.StatusConflict, ErrorTypeConflict)
	register(ErrNotMemberOfResource, http.StatusForbidden, ErrorTypeForbidden)
	register(ErrRoleAssignmentFailed, http.StatusInternalServerError, ErrorTypeInternal)

	// Organization
	register(ErrOrganizationNotFound, http.StatusNotFound, ErrorTypeNotFound)
	register(ErrNotMemberOfOrganization, http.StatusForbidden, ErrorTypeForbidden)
	register(ErrAlreadyMember, http.StatusConflict, ErrorTypeConflict)
	register(ErrNoActiveOrganization, http.StatusForbidden, ErrorTypeForbidden)
	register(ErrOrganizationsDisabled, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrOrganizationIDRequired, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrOrganizationScopeNotAllowed, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrOrganizationUpdateNotSupported, http.StatusBadRequest, ErrorTypeValidation)

	// Configuration
	register(ErrPasswordAuthNotEnabled, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrOAuthAuthNotEnabled, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrDatabaseURLRequired, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrMfaEncryptionKeyRequired, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrNotSupported, http.StatusNotImplemented, ErrorTypeValidation)

	// Additional validation
	register(ErrNameRequired, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrUserAndOrgIDRequired, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrUserAndResourceIDRequired, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrSystemRoleCreateForbidden, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrRoleNameRequired, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrRoleAlreadyExistsForOrganization, http.StatusConflict, ErrorTypeConflict)
	register(ErrSystemRoleAlreadyExists, http.StatusConflict, ErrorTypeConflict)
	register(ErrResourceUnknown, http.StatusNotFound, ErrorTypeNotFound)
	register(ErrMembershipAlreadyOnResource, http.StatusConflict, ErrorTypeConflict)

	// Crypto
	register(ErrEncryptionKeyEmpty, http.StatusInternalServerError, ErrorTypeInternal)
	register(ErrEncryptionKeyInvalid, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrPlaintextEmpty, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrSecretEmpty, http.StatusInternalServerError, ErrorTypeInternal)
	register(ErrCiphertextInvalid, http.StatusBadRequest, ErrorTypeValidation)

	// Admin / enterprise
	register(ErrPlatformAlreadyInitialized, http.StatusConflict, ErrorTypeConflict)
	register(ErrOwnerCredentialsRequired, http.StatusBadRequest, ErrorTypeValidation)
	register(ErrApiKeyNotFound, http.StatusNotFound, ErrorTypeNotFound)
	register(ErrApiKeyRevoked, http.StatusForbidden, ErrorTypeForbidden)
	register(ErrWebhookNotFound, http.StatusNotFound, ErrorTypeNotFound)
	register(ErrDomainNotFound, http.StatusNotFound, ErrorTypeNotFound)
	register(ErrDomainNotVerified, http.StatusForbidden, ErrorTypeForbidden)
	register(ErrSsoConnectionNotFound, http.StatusNotFound, ErrorTypeNotFound)
	register(ErrScimConnectionNotFound, http.StatusNotFound, ErrorTypeNotFound)
	register(ErrSecurityPolicyNotFound, http.StatusNotFound, ErrorTypeNotFound)
	register(ErrNetworkRuleNotFound, http.StatusNotFound, ErrorTypeNotFound)

	// Storage / infrastructure
	register(ErrDatabaseUnavailable, http.StatusServiceUnavailable, ErrorTypeInternal)
	register(ErrMigrationFailed, http.StatusInternalServerError, ErrorTypeInternal)
	register(ErrStorageNotFound, http.StatusNotFound, ErrorTypeNotFound)
	register(ErrStorageAlreadyExists, http.StatusConflict, ErrorTypeConflict)
	register(ErrStorageConflict, http.StatusConflict, ErrorTypeConflict)
}

func register(err error, status int, typ ErrorType) {
	ErrorMap[err] = status
	ErrorTypeMap[err] = typ
}

// HTTPStatus returns the HTTP status code for err, or 500 if unknown.
func HTTPStatus(err error) int {
	if err == nil {
		return http.StatusOK
	}
	for e, code := range ErrorMap {
		if errors.Is(err, e) {
			return code
		}
	}
	return http.StatusInternalServerError
}

// TypeOf returns the ErrorType for err, or ErrorTypeUnknown.
func TypeOf(err error) ErrorType {
	if err == nil {
		return ""
	}
	for e, typ := range ErrorTypeMap {
		if errors.Is(err, e) {
			return typ
		}
	}
	return ErrorTypeUnknown
}

func IsNotFound(err error) bool      { return errors.Is(err, ErrNotFound) || errors.Is(err, ErrStorageNotFound) || errors.Is(err, ErrUserNotFound) }
func IsConflict(err error) bool      { return errors.Is(err, ErrConflict) || errors.Is(err, ErrStorageConflict) || errors.Is(err, ErrStorageAlreadyExists) }
func IsUnauthorized(err error) bool  { return TypeOf(err) == ErrorTypeUnauthorized }
func IsForbidden(err error) bool     { return errors.Is(err, ErrForbidden) || errors.Is(err, ErrPermissionDenied) }
func IsValidation(err error) bool    { return TypeOf(err) == ErrorTypeValidation }
