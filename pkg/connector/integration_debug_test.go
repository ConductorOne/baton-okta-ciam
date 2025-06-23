package connector

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/stretchr/testify/require"
)

var (
	batonApiToken = os.Getenv("BATON_API_TOKEN")
	batonDomain   = os.Getenv("BATON_DOMAIN")
	ctxTest       = context.Background()
)

func TestUserResourceTypeList(t *testing.T) {
	if batonApiToken == "" && batonDomain == "" {
		t.Skip()
	}

	cliTest, err := getClietForTesting(ctxTest, &Config{
		Domain:   batonDomain,
		ApiToken: batonApiToken,
	})
	require.Nil(t, err)

	o := &userResourceType{
		resourceType: resourceTypeUser,
		connector:    cliTest,
	}
	res, _, _, err := o.List(ctxTest, &v2.ResourceId{}, &pagination.Token{})
	require.Nil(t, err)
	require.NotNil(t, res)

	oktaUsers, resp, err := o.connector.client.User.ListAssignedRolesForUser(ctxTest, "00ujp5a9z0rMTsPRW697", nil)
	require.Nil(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, oktaUsers)
}

func parseEntitlementID(id string) (*v2.ResourceId, []string, error) {
	parts := strings.Split(id, ":")
	// Need to be at least 3 parts type:entitlement_id:slug
	if len(parts) < 3 || len(parts) > 3 {
		return nil, nil, fmt.Errorf("okta-connector: invalid resource id")
	}

	resourceId := &v2.ResourceId{
		ResourceType: parts[0],
		Resource:     strings.Join(parts[1:len(parts)-1], ":"),
	}

	return resourceId, parts, nil
}

func parseBindingEntitlementID(id string) (*v2.ResourceId, []string, error) {
	parts := strings.Split(id, ":")
	// Need to be at least 3 parts type:entitlement_id:slug
	if len(parts) < 4 || len(parts) > 4 {
		return nil, nil, fmt.Errorf("okta-connector: invalid resource id")
	}

	resourceId := &v2.ResourceId{
		ResourceType: parts[0],
		Resource:     strings.Join(parts[1:len(parts)-1], ":"),
	}

	return resourceId, parts, nil
}

func getRoleResourceForTesting(ctxTest context.Context, id, label, ctype string) (*v2.Resource, error) {
	return roleResource(ctxTest, &okta.Role{
		Id:    id,
		Label: label,
		Type:  ctype,
	}, resourceTypeRole)
}

func getEntitlementForTesting(resource *v2.Resource, resourceDisplayName, entitlement string) *v2.Entitlement {
	options := []ent.EntitlementOption{
		ent.WithGrantableTo(resourceTypeRole),
		ent.WithDisplayName(fmt.Sprintf("%s resource %s", resourceDisplayName, entitlement)),
		ent.WithDescription(fmt.Sprintf("%s of %s okta", entitlement, resourceDisplayName)),
	}

	return ent.NewAssignmentEntitlement(resource, entitlement, options...)
}

func getClietForTesting(ctx context.Context, cfg *Config) (*Okta, error) {
	var oktaClient *okta.Client
	client, err := uhttp.NewClient(ctx, uhttp.WithLogger(true, nil))
	if err != nil {
		return nil, err
	}

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
	}

	return &Okta{
		client:   oktaClient,
		domain:   cfg.Domain,
		apiToken: cfg.ApiToken,
		ciamConfig: &ciamConfig{
			EmailDomains: cfg.CiamEmailDomains,
		},
	}, nil
}
