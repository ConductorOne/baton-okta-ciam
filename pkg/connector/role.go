package connector

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	sdkGrant "github.com/conductorone/baton-sdk/pkg/types/grant"
	sdkResource "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/okta/okta-sdk-golang/v2/okta"
)

var errMissingRolePermissions = errors.New("okta-connectorv2: missing role permissions")
var alreadyAssignedRole = "E0000090"

// Roles that can only be assigned at the org-wide scope.
// For full list of roles see: https://developer.okta.com/docs/reference/api/roles/#role-types
var standardRoleTypes = []*okta.Role{
	{Type: "API_ACCESS_MANAGEMENT_ADMIN", Label: "API Access Management Administrator"},
	{Type: "MOBILE_ADMIN", Label: "Mobile Administrator"},
	{Type: "ORG_ADMIN", Label: "Organizational Administrator"},
	{Type: "READ_ONLY_ADMIN", Label: "Read-Only Administrator"},
	{Type: "REPORT_ADMIN", Label: "Report Administrator"},
	{Type: "SUPER_ADMIN", Label: "Super Administrator"},
	// The type name is strange, but it is what Okta uses for the Group Administrator standard role
	{Type: "USER_ADMIN", Label: "Group Administrator"},
	{Type: "HELP_DESK_ADMIN", Label: "Help Desk Administrator"},
	{Type: "APP_ADMIN", Label: "Application Administrator"},
	{Type: "GROUP_MEMBERSHIP_ADMIN", Label: "Group Membership Administrator"},
}

const (
	apiPathListAdministrators              = "/api/internal/administrators"
	apiPathListIamCustomRoles              = "/api/v1/iam/roles"
	apiPathListAllUsersWithRoleAssignments = "/api/v1/iam/assignees/users"
	ContentType                            = "application/json"
	NF                                     = -1
)

func userHasRoleAccess(administratorRoleFlags *administratorRoleFlags, resource *v2.Resource) bool {
	roleName := strings.ReplaceAll(strings.ToLower(resource.Id.GetResource()), "_", "")
	for _, role := range administratorRoleFlags.RolesFromIndividualAssignments {
		if strings.ToLower(role) == roleName {
			return true
		}
	}

	for _, role := range administratorRoleFlags.RolesFromGroup {
		if strings.ToLower(role) == roleName {
			return true
		}
	}

	return false
}

func getOrgSettings(ctx context.Context, client *okta.Client, token *pagination.Token) (*okta.OrgSetting, *responseContext, error) {
	orgSettings, resp, err := client.OrgSetting.GetOrgSettings(ctx)
	if err != nil {
		return nil, nil, handleOktaResponseError(resp, err)
	}

	respCtx, err := responseToContext(token, resp)
	if err != nil {
		return nil, nil, err
	}

	return orgSettings, respCtx, nil
}

type administratorRoleFlags struct {
	UserId                           string   `json:"userId"`
	SuperAdmin                       bool     `json:"superAdmin"`
	OrgAdmin                         bool     `json:"orgAdmin"`
	ReadOnlyAdmin                    bool     `json:"readOnlyAdmin"`
	MobileAdmin                      bool     `json:"mobileAdmin"`
	AppAdmin                         bool     `json:"appAdmin"`
	HelpDeskAdmin                    bool     `json:"helpDeskAdmin"`
	GroupMembershipAdmin             bool     `json:"groupMembershipAdmin"`
	ApiAccessManagementAdmin         bool     `json:"apiAccessManagementAdmin"`
	UserAdmin                        bool     `json:"userAdmin"`
	ReportAdmin                      bool     `json:"reportAdmin"`
	ForAllApps                       bool     `json:"forAllApps"`
	ForAllUserAdminGroups            bool     `json:"forAllUserAdminGroups"`
	ForAllHelpDeskAdminGroups        bool     `json:"forAllHelpDeskAdminGroups"`
	ForAllGroupMembershipAdminGroups bool     `json:"forAllGroupMembershipAdminGroups"`
	RolesFromIndividualAssignments   []string `json:"rolesFromIndividualAssignments"`
	RolesFromGroup                   []string `json:"rolesFromGroup"`
}

func listAdministratorRoleFlags(
	ctx context.Context,
	client *okta.Client,
	token *pagination.Token,
	encodedQueryParams string,
) ([]*administratorRoleFlags, *responseContext, error) {
	reqUrl, err := url.Parse(apiPathListAdministrators)
	if err != nil {
		return nil, nil, err
	}

	if encodedQueryParams != "" {
		reqUrl.RawQuery = encodedQueryParams
	}

	rq := client.CloneRequestExecutor()
	req, err := rq.
		WithAccept(ContentType).
		WithContentType(ContentType).
		NewRequest(http.MethodGet, reqUrl.String(), nil)
	if err != nil {
		return nil, nil, err
	}

	var adminFlags []*administratorRoleFlags
	resp, err := rq.Do(ctx, req, &adminFlags)
	if err != nil {
		// If we don't have access to the role endpoint, we should just return nil
		if resp.StatusCode == http.StatusForbidden {
			return nil, nil, errMissingRolePermissions
		}

		return nil, nil, handleOktaResponseError(resp, err)
	}

	respCtx, err := responseToContext(token, resp)
	if err != nil {
		return nil, nil, err
	}

	return adminFlags, respCtx, nil
}

func standardRoleFromType(roleType string) *okta.Role {
	for _, standardRoleType := range standardRoleTypes {
		if standardRoleType.Type == roleType {
			return standardRoleType
		}
	}

	return nil
}

func StandardRoleTypeFromLabel(label string) *okta.Role {
	for _, role := range standardRoleTypes {
		if role.Label == label {
			return role
		}
	}
	return nil
}

func roleResource(ctx context.Context, role *okta.Role, ctype *v2.ResourceType) (*v2.Resource, error) {
	var objectID = role.Type
	if role.Type == "" && role.Id != "" {
		objectID = role.Id
	}

	profile := map[string]interface{}{
		"id":    role.Id,
		"label": role.Label,
		"type":  role.Type,
	}

	return sdkResource.NewRoleResource(
		role.Label,
		ctype,
		objectID,
		[]sdkResource.RoleTraitOption{sdkResource.WithRoleProfile(profile)},
		sdkResource.WithAnnotation(&v2.V1Identifier{
			Id: fmtResourceIdV1(objectID),
		}),
	)
}

func roleGrant(userID string, resource *v2.Resource) *v2.Grant {
	ur := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeUser.Id, Resource: userID}}

	return sdkGrant.NewGrant(resource, "assigned", ur,
		sdkGrant.WithAnnotation(&v2.V1Identifier{
			Id: fmtGrantIdV1(V1MembershipEntitlementID(resource.Id.Resource), userID),
		}),
	)
}
