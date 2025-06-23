package config

import (
	"github.com/conductorone/baton-sdk/pkg/field"
)

var (
	domain             = field.StringField("domain", field.WithRequired(true), field.WithDescription("The URL for the Okta organization"))
	apiToken           = field.StringField("api-token", field.WithDescription("The API token for the service account"))
	syncInactivateApps = field.BoolField("sync-inactive-apps", field.WithDescription("Whether to sync inactive apps or not"), field.WithDefaultValue(true))
	oktaProvisioning   = field.BoolField("okta-provisioning")
	ciamEmailDomains   = field.StringSliceField("ciam-email-domains",
		field.WithDescription("The email domains to use for CIAM mode. Any users that don't have an email address with one of the provided domains will be ignored, unless explicitly granted a role"))
	cache               = field.BoolField("cache", field.WithDescription("Enable response cache"), field.WithDefaultValue(true))
	cacheTTI            = field.IntField("cache-tti", field.WithDescription("Response cache cleanup interval in seconds"), field.WithDefaultValue(60))
	cacheTTL            = field.IntField("cache-ttl", field.WithDescription("Response cache time to live in seconds"), field.WithDefaultValue(300))
	syncCustomRoles     = field.BoolField("sync-custom-roles", field.WithDescription("Enable syncing custom roles"), field.WithDefaultValue(false))
	skipSecondaryEmails = field.BoolField("skip-secondary-emails", field.WithDescription("Skip syncing secondary emails"), field.WithDefaultValue(false))
)

var relationships = []field.SchemaFieldRelationship{}

//go:generate go run ./gen
var Config = field.NewConfiguration([]field.SchemaField{
	domain,
	apiToken,
	syncInactivateApps,
	oktaProvisioning,
	ciamEmailDomains,
	cache,
	cacheTTI,
	cacheTTL,
	syncCustomRoles,
	skipSecondaryEmails,
}, field.WithConstraints(relationships...))
