package connector

import (
	"context"
	"fmt"
	"time"

	"github.com/conductorone/baton-sdk/pkg/ratelimit"
	sdkResource "github.com/conductorone/baton-sdk/pkg/types/resource"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/structpb"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	sdkEntitlement "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	sdkGrant "github.com/conductorone/baton-sdk/pkg/types/grant"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
)

const membershipUpdatedField = "lastMembershipUpdated"
const usersCountProfileKey = "users_count"

type groupResourceType struct {
	resourceType *v2.ResourceType
	connector    *Okta
}

func (o *groupResourceType) ResourceType(ctx context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *groupResourceType) List(
	ctx context.Context,
	resourceID *v2.ResourceId,
	token *pagination.Token,
) ([]*v2.Resource, string, annotations.Annotations, error) {
	bag, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeGroup.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	var rv []*v2.Resource
	var groups []*okta.Group
	var respCtx *responseContext

	qp := queryParamsExpand(token.Size, page, "stats")
	groups, respCtx, err = o.listGroups(ctx, token, qp)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list groups: %w", err)
	}

	nextPage, annos, err := parseResp(respCtx.OktaResponse)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
	}

	err = bag.Next(nextPage)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
	}

	for _, group := range groups {
		resource, err := o.groupResource(ctx, group)
		if err != nil {
			return nil, "", nil, err
		}

		rv = append(rv, resource)
	}

	pageToken, err := bag.Marshal()
	if err != nil {
		return nil, "", nil, err
	}

	return rv, pageToken, annos, nil
}

func (o *groupResourceType) Entitlements(
	ctx context.Context,
	resource *v2.Resource,
	token *pagination.Token,
) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var rv []*v2.Entitlement

	rv = append(rv, o.groupEntitlement(ctx, resource))

	return rv, "", nil, nil
}

func (o *groupResourceType) etagMd(group *okta.Group) (*v2.ETagMetadata, error) {
	if group.LastMembershipUpdated != nil {
		data, err := structpb.NewStruct(map[string]interface{}{
			membershipUpdatedField: group.LastMembershipUpdated.Format(time.RFC3339Nano),
		})
		if err != nil {
			return nil, err
		}
		return &v2.ETagMetadata{
			Metadata: data,
		}, nil
	}

	return nil, nil
}

func (o *groupResourceType) Grants(
	ctx context.Context,
	resource *v2.Resource,
	token *pagination.Token,
) ([]*v2.Grant, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	var rv []*v2.Grant
	bag := &pagination.Bag{}
	err := bag.Unmarshal(token.Token)
	if err != nil {
		return nil, "", nil, err
	}

	if bag.Current() == nil {
		bag.Push(pagination.PageState{
			ResourceTypeID: resourceTypeRole.Id,
		})
		bag.Push(pagination.PageState{
			ResourceTypeID: resourceTypeUser.Id,
		})
	}

	page := bag.PageToken()

	groupID := resource.Id.GetResource()

	switch bag.ResourceTypeID() {
	case resourceTypeUser.Id:
		groupTrait, err := sdkResource.GetGroupTrait(resource)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to get group trait: %w", err)
		}
		usersCount, ok := sdkResource.GetProfileInt64Value(groupTrait.Profile, usersCountProfileKey)

		var annos annotations.Annotations
		nextPage := ""
		if !ok || usersCount > 0 {
			if !ok {
				l.Debug("okta-connectorv2: making list group users call because users_count profile attribute was not present")
			}

			qp := queryParams(token.Size, page)

			users, respCtx, err := o.listGroupUsers(ctx, groupID, token, qp)
			if err != nil {
				return nil, "", nil, convertNotFoundError(err, "okta-connectorv2: failed to list group users")
			}

			nextPage, annos, err = parseResp(respCtx.OktaResponse)
			if err != nil {
				return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
			}

			for _, user := range users {
				rv = append(rv, groupGrant(resource, user))
			}
		} else {
			l.Debug("okta-connectorv2: skipping list group users")
		}

		err = bag.Next(nextPage)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
		}

		pageToken, err := bag.Marshal()
		if err != nil {
			return nil, "", nil, err
		}

		if pageToken == "" {
			etag := &v2.ETag{
				Value: time.Now().UTC().Format(time.RFC3339Nano),
			}
			annos.Update(etag)
		}

		return rv, pageToken, annos, nil
	case resourceTypeRole.Id:
		roles, resp, err := listGroupAssignedRoles(ctx, o.connector.client, groupID, nil)
		if err != nil {
			if resp == nil {
				return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list group roles: %w", err)
			}

			defer resp.Body.Close()
			errOkta, err := getError(resp)
			if err != nil {
				return nil, "", nil, err
			}
			if errOkta.ErrorCode == AccessDeniedErrorCode {
				err = bag.Next("")
				if err != nil {
					return nil, "", nil, err
				}
				pageToken, err := bag.Marshal()
				if err != nil {
					return nil, "", nil, err
				}
				return nil, pageToken, nil, nil
			} else {
				return nil, "", nil, convertNotFoundError(&errOkta, "okta-connectorv2: failed to list group roles")
			}
		}

		for _, role := range roles {
			if role.Status == roleStatusInactive || role.AssignmentType != "GROUP" {
				continue
			}

			// TODO(lauren) convert model helper
			var roleResourceVal *v2.Resource
			roleResourceVal, err = roleResource(ctx, &okta.Role{
				Id:    role.Role,
				Label: role.Label,
				Type:  role.Type,
			}, resourceTypeRole)
			if err != nil {
				return nil, "", nil, err
			}

			groupTrait, err := sdkResource.GetGroupTrait(resource)
			if err != nil {
				return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to get group trait: %w", err)
			}
			usersCount, ok := sdkResource.GetProfileInt64Value(groupTrait.Profile, usersCountProfileKey)
			shouldExpand := !ok || usersCount > 0
			if !shouldExpand {
				l.Debug("okta-connectorv2: skipping expand for role group grant since users_count is 0")
			}
			rv = append(rv, roleGroupGrant(groupID, roleResourceVal, shouldExpand))
		}

		// TODO(lauren) Move this to list method like other methods do
		respCtx, err := responseToContext(token, resp)
		if err != nil {
			return nil, "", nil, err
		}

		nextPage, annos, err := parseResp(respCtx.OktaResponse)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
		}

		err = bag.Next(nextPage)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
		}

		pageToken, err := bag.Marshal()
		if err != nil {
			return nil, "", nil, err
		}

		return rv, pageToken, annos, nil
	default:
		return nil, "", nil, fmt.Errorf("okta-connector: invalid grant resource type: %s", bag.ResourceTypeID())
	}
}

func (o *groupResourceType) listGroups(ctx context.Context, token *pagination.Token, qp *query.Params) ([]*okta.Group, *responseContext, error) {
	return listGroupsHelper(ctx, o.connector.client, token, qp)
}

func listGroupsHelper(ctx context.Context, client *okta.Client, token *pagination.Token, qp *query.Params) ([]*okta.Group, *responseContext, error) {
	groups, resp, err := client.Group.ListGroups(ctx, qp)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to fetch groups from okta: %w", handleOktaResponseError(resp, err))
	}
	reqCtx, err := responseToContext(token, resp)
	if err != nil {
		return nil, nil, err
	}
	return groups, reqCtx, nil
}

func (o *groupResourceType) listGroupUsers(ctx context.Context, groupID string, token *pagination.Token, qp *query.Params) ([]*okta.User, *responseContext, error) {
	users, resp, err := o.connector.client.Group.ListGroupUsers(ctx, groupID, qp)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to fetch group users from okta: %w", handleOktaResponseError(resp, err))
	}

	reqCtx, err := responseToContext(token, resp)
	if err != nil {
		return nil, nil, err
	}

	return users, reqCtx, nil
}

func (o *groupResourceType) groupResource(ctx context.Context, group *okta.Group) (*v2.Resource, error) {
	trait, err := o.groupTrait(ctx, group)
	if err != nil {
		return nil, err
	}

	var annos annotations.Annotations
	annos.Update(trait)
	annos.Update(&v2.V1Identifier{
		Id: fmtResourceIdV1(group.Id),
	})
	annos.Update(&v2.RawId{Id: group.Id})

	etagMd, err := o.etagMd(group)
	if err != nil {
		return nil, err
	}
	annos.Update(etagMd)

	return &v2.Resource{
		Id:          fmtResourceId(resourceTypeGroup.Id, group.Id),
		DisplayName: group.Profile.Name,
		Annotations: annos,
	}, nil
}

func (o *groupResourceType) groupTrait(ctx context.Context, group *okta.Group) (*v2.GroupTrait, error) {
	profileMap := map[string]interface{}{
		"description": group.Profile.Description,
		"name":        group.Profile.Name,
	}

	if userCount, exists := getGroupUserCount(group); exists {
		profileMap[usersCountProfileKey] = int64(userCount)
	}

	profile, err := structpb.NewStruct(profileMap)
	if err != nil {
		return nil, fmt.Errorf("okta-connectorv2: failed to construct group profile for group trait: %w", err)
	}

	ret := &v2.GroupTrait{
		Profile: profile,
	}

	return ret, nil
}

func getGroupUserCount(group *okta.Group) (float64, bool) {
	embedded := group.Embedded
	if embedded == nil {
		return 0, false
	}
	embeddedMap, ok := embedded.(map[string]interface{})
	if !ok {
		return 0, false
	}
	embeddedStats, ok := embeddedMap["stats"]
	if !ok {
		return 0, false
	}
	embeddedStatsMap, ok := embeddedStats.(map[string]interface{})
	if !ok {
		return 0, false
	}
	embeddedStatsUsersCount, ok := embeddedStatsMap["usersCount"]
	if !ok {
		return 0, false
	}
	userCount := embeddedStatsUsersCount.(float64)
	return userCount, true
}

func (o *groupResourceType) groupEntitlement(ctx context.Context, resource *v2.Resource) *v2.Entitlement {
	return sdkEntitlement.NewAssignmentEntitlement(resource, "member",
		sdkEntitlement.WithAnnotation(&v2.V1Identifier{
			Id: V1MembershipEntitlementID(resource.Id.GetResource()),
		}),
		sdkEntitlement.WithGrantableTo(resourceTypeUser),
		sdkEntitlement.WithDisplayName(fmt.Sprintf("%s Group Member", resource.DisplayName)),
		sdkEntitlement.WithDescription(fmt.Sprintf("Member of %s group in Okta", resource.DisplayName)),
	)
}

func groupGrant(resource *v2.Resource, user *okta.User) *v2.Grant {
	ur := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeUser.Id, Resource: user.Id}}

	return sdkGrant.NewGrant(resource, "member", ur, sdkGrant.WithAnnotation(&v2.V1Identifier{
		Id: fmtGrantIdV1(V1MembershipEntitlementID(resource.Id.Resource), user.Id),
	}))
}

func (g *groupResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	if principal.Id.ResourceType != resourceTypeUser.Id {
		l.Warn(
			"okta-connector: only users can be granted group membership",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("okta-connector: only users can be granted group membership")
	}

	groupId := entitlement.Resource.Id.Resource
	userId := principal.Id.Resource

	response, err := g.connector.client.Group.AddUserToGroup(ctx, groupId, userId)
	if err != nil {
		return nil, handleOktaResponseError(response, err)
	}

	l.Debug("Membership has been created",
		zap.String("Status", response.Status),
	)

	return nil, nil
}

func (g *groupResourceType) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	entitlement := grant.Entitlement
	principal := grant.Principal
	if principal.Id.ResourceType != resourceTypeUser.Id {
		l.Warn(
			"okta-connector: only users can have group membership revoked",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("okta-connector:only users can have group membership revoked")
	}

	groupId := entitlement.Resource.Id.Resource
	userId := principal.Id.Resource

	response, err := g.connector.client.Group.RemoveUserFromGroup(ctx, groupId, userId)
	if err != nil {
		return nil, handleOktaResponseError(response, err)
	}

	l.Warn("Membership has been revoked",
		zap.String("Status", response.Status),
	)

	return nil, nil
}

func (o *groupResourceType) Get(ctx context.Context, resourceId *v2.ResourceId, parentResourceId *v2.ResourceId) (*v2.Resource, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	l.Debug("getting group", zap.String("group_id", resourceId.Resource))

	var annos annotations.Annotations

	var group *okta.Group
	var resp *okta.Response
	var err error
	group, resp, err = o.connector.client.Group.GetGroup(ctx, resourceId.Resource)

	if err != nil {
		return nil, nil, handleOktaResponseError(resp, err)
	}

	if resp != nil {
		if desc, err := ratelimit.ExtractRateLimitData(resp.Response.StatusCode, &resp.Response.Header); err == nil {
			annos.WithRateLimiting(desc)
		}
	}

	resource, err := o.groupResource(ctx, group)
	if err != nil {
		return nil, annos, err
	}

	return resource, annos, nil
}

func groupBuilder(connector *Okta) *groupResourceType {
	return &groupResourceType{
		resourceType: resourceTypeGroup,
		connector:    connector,
	}
}
