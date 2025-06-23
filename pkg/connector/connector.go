package connector

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	oktav5 "github.com/conductorone/okta-sdk-golang/v5/okta"
	"github.com/okta/okta-sdk-golang/v2/okta"
)

// TODO: use isNotFoundError() since E0000008 is also a not found error
const ResourceNotFoundExceptionErrorCode = "E0000007"
const AccessDeniedErrorCode = "E0000006"

type Okta struct {
	client              *okta.Client
	clientV5            *oktav5.APIClient
	domain              string
	apiToken            string
	ciamConfig          *ciamConfig
	skipSecondaryEmails bool
	userRoleCache       sync.Map
}

type ciamConfig struct {
	EmailDomains []string
}

type Config struct {
	Domain           string
	ApiToken         string
	CiamEmailDomains []string

	OktaProvisioning    bool
	Cache               bool
	CacheTTI            int32
	CacheTTL            int32
	SkipSecondaryEmails bool
}

func v1AnnotationsForResourceType(resourceTypeID string, skipEntitlementsAndGrants bool) annotations.Annotations {
	annos := annotations.Annotations{}
	annos.Update(&v2.V1Identifier{
		Id: resourceTypeID,
	})

	if skipEntitlementsAndGrants {
		annos.Update(&v2.SkipEntitlementsAndGrants{})
	}

	return annos
}

var (
	resourceTypeRole = &v2.ResourceType{
		Id:          "role",
		DisplayName: "Role",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_ROLE},
		Annotations: v1AnnotationsForResourceType("role", false),
	}
	resourceTypeUser = &v2.ResourceType{
		Id:          "user",
		DisplayName: "User",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_USER},
		Annotations: v1AnnotationsForResourceType("user", true),
	}
	resourceTypeGroup = &v2.ResourceType{
		Id:          "group",
		DisplayName: "Group",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_GROUP},
		Annotations: v1AnnotationsForResourceType("group", false),
	}
)

func (o *Okta) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncer {
	return []connectorbuilder.ResourceSyncer{
		ciamUserBuilder(o),
		ciamBuilder(o.client, o.skipSecondaryEmails),
	}
}

func (c *Okta) ListResourceTypes(ctx context.Context, request *v2.ResourceTypesServiceListResourceTypesRequest) (*v2.ResourceTypesServiceListResourceTypesResponse, error) {
	resourceTypes := []*v2.ResourceType{
		resourceTypeUser,
		resourceTypeGroup,
	}

	return &v2.ResourceTypesServiceListResourceTypesResponse{
		List: resourceTypes,
	}, nil
}

func (c *Okta) Metadata(ctx context.Context) (*v2.ConnectorMetadata, error) {
	_, err := c.Validate(ctx)
	if err != nil {
		return nil, err
	}

	var annos annotations.Annotations
	annos.Update(&v2.ExternalLink{
		Url: c.domain,
	})

	return &v2.ConnectorMetadata{
		DisplayName: "Okta",
		Description: "The Okta connector syncs user, group, role, and app data from Okta",
		Annotations: annos,
		AccountCreationSchema: &v2.ConnectorAccountCreationSchema{
			FieldMap: map[string]*v2.ConnectorAccountCreationSchema_Field{
				"first_name": {
					DisplayName: "First Name",
					Required:    true,
					Description: "This first name will be used for the user.",
					Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
						StringField: &v2.ConnectorAccountCreationSchema_StringField{},
					},
					Placeholder: "First name",
					Order:       1,
				},
				"last_name": {
					DisplayName: "Last Name",
					Required:    true,
					Description: "This last name will be used for the user.",
					Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
						StringField: &v2.ConnectorAccountCreationSchema_StringField{},
					},
					Placeholder: "Last name",
					Order:       2,
				},
				"email": {
					DisplayName: "Email",
					Required:    true,
					Description: "This will be the email of the user. If login is unset this is also the login.",
					Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
						StringField: &v2.ConnectorAccountCreationSchema_StringField{},
					},
					Placeholder: "Email",
					Order:       3,
				},
				"login": {
					DisplayName: "Login",
					Required:    false,
					Description: "This login will be used as the login for the user. Email will be used if login is not present.",
					Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
						StringField: &v2.ConnectorAccountCreationSchema_StringField{},
					},
					Placeholder: "Login",
					Order:       4,
				},
				"password_change_on_login_required": {
					DisplayName: "Password Change Required on Login",
					Required:    false,
					Description: "When creating accounts with a random password setting this to 'true' will require the user to change their password on first login.",
					Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
						StringField: &v2.ConnectorAccountCreationSchema_StringField{},
					},
					Placeholder: "True/False",
					Order:       5,
				},
			},
		},
	}, nil
}

func (c *Okta) Validate(ctx context.Context) (annotations.Annotations, error) {
	if c.apiToken == "" {
		return nil, nil
	}

	token := newPaginationToken(defaultLimit, "")

	_, respCtx, err := getOrgSettings(ctx, c.client, token)
	if err != nil {
		return nil, fmt.Errorf("okta-connector: verify failed to fetch org: %w", err)
	}

	_, _, err = parseResp(respCtx.OktaResponse)
	if err != nil {
		return nil, fmt.Errorf("okta-connector: verify failed to parse response: %w", err)
	}

	if respCtx.OktaResponse.StatusCode != http.StatusOK {
		err := fmt.Errorf("okta-connector: verify returned non-200: '%d'", respCtx.OktaResponse.StatusCode)
		return nil, err
	}

	return nil, nil
}

func (c *Okta) Asset(ctx context.Context, asset *v2.AssetRef) (string, io.ReadCloser, error) {
	return "", nil, fmt.Errorf("not implemented")
}

func New(ctx context.Context, cfg *Config) (*Okta, error) {
	var (
		oktaClient *okta.Client
	)
	client, err := uhttp.NewClient(ctx, uhttp.WithLogger(true, nil))
	if err != nil {
		return nil, err
	}

	var oktaClientV5 *oktav5.APIClient

	if cfg.ApiToken != "" && cfg.Domain != "" {
		_, oktaClient, err = okta.NewClient(ctx,
			okta.WithOrgUrl(fmt.Sprintf("https://%s", cfg.Domain)),
			okta.WithToken(cfg.ApiToken),
			okta.WithHttpClientPtr(client),
			okta.WithCache(cfg.Cache),
			okta.WithCacheTti(cfg.CacheTTI),
			okta.WithCacheTtl(cfg.CacheTTL),
		)
		if err != nil {
			return nil, err
		}

		config, err := oktav5.NewConfiguration(
			oktav5.WithOrgUrl(fmt.Sprintf("https://%s", cfg.Domain)),
			oktav5.WithToken(cfg.ApiToken),
			oktav5.WithHttpClientPtr(client),
			oktav5.WithCache(cfg.Cache),
			oktav5.WithCacheTti(cfg.CacheTTI),
			oktav5.WithCacheTtl(cfg.CacheTTL),
		)
		if err != nil {
			return nil, err
		}
		oktaClientV5 = oktav5.NewAPIClient(config)
	}

	return &Okta{
		client:              oktaClient,
		clientV5:            oktaClientV5,
		domain:              cfg.Domain,
		apiToken:            cfg.ApiToken,
		skipSecondaryEmails: cfg.SkipSecondaryEmails,
		ciamConfig: &ciamConfig{
			EmailDomains: cfg.CiamEmailDomains,
		},
	}, nil
}

type AppUserSchema struct {
	Definitions struct {
		Base struct {
			Properties struct {
				SamlRoles struct {
					Union string `json:"union,omitempty"`
				} `json:"samlRoles,omitempty"`
			} `json:"properties"`
		} `json:"base"`
	} `json:"definitions"`
}
