package connector

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/crypto"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/ratelimit"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"go.uber.org/zap"
)

const (
	usersUrl = "/api/v1/users"
)

const (
	unknownProfileValue       = "unknown"
	userStatusSuspended       = "SUSPENDED"
	userStatusDeprovisioned   = "DEPROVISIONED"
	userStatusActive          = "ACTIVE"
	userStatusLockedOut       = "LOCKED_OUT"
	userStatusPasswordExpired = "PASSWORD_EXPIRED"
	userStatusProvisioned     = "PROVISIONED"
	userStatusRecovery        = "RECOVERY"
	userStatusStaged          = "STAGED"
)

type userResourceType struct {
	resourceType *v2.ResourceType
	emailFilters []string
	connector    *Okta
}

func (o *userResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *userResourceType) List(
	ctx context.Context,
	resourceID *v2.ResourceId,
	token *pagination.Token,
) ([]*v2.Resource, string, annotations.Annotations, error) {
	// If there are no email filters specified, don't sync users.
	if len(o.emailFilters) == 0 {
		return nil, "", nil, nil
	}
	bag, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeUser.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse page token: %w", err)
	}

	var rv []*v2.Resource
	qp := queryParams(token.Size, page)

	users, respCtx, err := listUsers(ctx, o.connector.client, token, qp)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to list users: %w", err)
	}

	nextPage, annos, err := parseResp(respCtx.OktaResponse)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to parse response: %w", err)
	}

	err = bag.Next(nextPage)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-connectorv2: failed to fetch bag.Next: %w", err)
	}

	for _, user := range users {
		if !shouldIncludeOktaUser(user, o.emailFilters) {
			continue
		}
		resource, err := userResource(ctx, user, o.connector.skipSecondaryEmails)
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

func shouldIncludeOktaUser(u *okta.User, emailDomainFilters []string) bool {
	if len(emailDomainFilters) == 0 {
		return false
	}

	var userEmails []string
	oktaProfile := *u.Profile
	if email, ok := oktaProfile["email"].(string); ok {
		userEmails = append(userEmails, email)
	}
	if secondEmail, ok := oktaProfile["secondEmail"].(string); ok {
		userEmails = append(userEmails, secondEmail)
	}

	if login, ok := oktaProfile["login"].(string); ok {
		if strings.Contains(login, "@") {
			userEmails = append(userEmails, login)
		}
	}

	return shouldIncludeUserByEmails(userEmails, emailDomainFilters)
}

func shouldIncludeUserByEmails(userEmails []string, emailDomainFilters []string) bool {
	for _, filter := range emailDomainFilters {
		for _, ue := range userEmails {
			if strings.HasSuffix(strings.ToLower(ue), "@"+filter) {
				return true
			}
		}
	}
	return false
}

func (o *userResourceType) Entitlements(
	_ context.Context,
	resource *v2.Resource,
	_ *pagination.Token,
) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func (o *userResourceType) Grants(
	ctx context.Context,
	resource *v2.Resource,
	token *pagination.Token,
) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func userName(user *okta.User) (string, string) {
	profile := *user.Profile

	firstName, ok := profile["firstName"].(string)
	if !ok {
		firstName = unknownProfileValue
	}
	lastName, ok := profile["lastName"].(string)
	if !ok {
		lastName = unknownProfileValue
	}

	return firstName, lastName
}

func listUsers(ctx context.Context, client *okta.Client, token *pagination.Token, qp *query.Params) ([]*okta.User, *responseContext, error) {
	if qp.Search == "" {
		qp.Search = "status pr" // ListUsers doesn't get deactivated users by default. this should fetch them all
	}

	uri := usersUrl
	if qp != nil {
		uri += qp.String()
	}

	reqUrl, err := url.Parse(uri)
	if err != nil {
		return nil, nil, err
	}

	// Using okta-response="omitCredentials,omitCredentialsLinks,omitTransitioningToStatus" in the content type header omits
	// the credentials, credentials links, and `transitioningToStatus` field from the response which applies performance optimization.
	// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/User/#tag/User/operation/listUsers!in=header&path=Content-Type&t=request
	oktaUsers := make([]*okta.User, 0)
	rq := client.CloneRequestExecutor()
	req, err := rq.
		WithAccept(ContentType).
		WithContentType(`application/json; okta-response="omitCredentials,omitCredentialsLinks,omitTransitioningToStatus"`).
		NewRequest(http.MethodGet, reqUrl.String(), nil)
	if err != nil {
		return nil, nil, err
	}

	// Need to set content type here because the response was still including the credentials when setting it with WithContentType above
	req.Header.Set("Content-Type", `application/json; okta-response="omitCredentials,omitCredentialsLinks,omitTransitioningToStatus"`)

	resp, err := rq.Do(ctx, req, &oktaUsers)
	if err != nil {
		return nil, nil, err
	}

	respCtx, err := responseToContext(token, resp)
	if err != nil {
		return nil, nil, err
	}
	return oktaUsers, respCtx, nil
}

func ciamUserBuilder(connector *Okta) *userResourceType {
	var loweredFilters []string
	for _, ef := range connector.ciamConfig.EmailDomains {
		loweredFilters = append(loweredFilters, strings.ToLower(ef))
	}
	return &userResourceType{
		resourceType: resourceTypeUser,
		emailFilters: loweredFilters,
		connector:    connector,
	}
}

// Create a new connector resource for a okta user.
func userResource(ctx context.Context, user *okta.User, skipSecondaryEmails bool) (*v2.Resource, error) {
	firstName, lastName := userName(user)

	oktaProfile := *user.Profile
	oktaProfile["c1_okta_raw_user_status"] = user.Status

	options := []resource.UserTraitOption{
		resource.WithUserProfile(oktaProfile),
		// TODO?: use the user types API to figure out the account type
		// https://developer.okta.com/docs/reference/api/user-types/
		// resource.WithAccountType(v2.UserTrait_ACCOUNT_TYPE_UNSPECIFIED),
	}

	displayName, ok := oktaProfile["displayName"].(string)
	if !ok {
		displayName = fmt.Sprintf("%s %s", firstName, lastName)
	}

	if user.Created != nil {
		options = append(options, resource.WithCreatedAt(*user.Created))
	}
	if user.LastLogin != nil {
		options = append(options, resource.WithLastLogin(*user.LastLogin))
	}

	if email, ok := oktaProfile["email"].(string); ok && email != "" {
		options = append(options, resource.WithEmail(email, true))
	}
	if secondEmail, ok := oktaProfile["secondEmail"].(string); ok && secondEmail != "" && !skipSecondaryEmails {
		options = append(options, resource.WithEmail(secondEmail, false))
	}

	if skipSecondaryEmails {
		oktaProfile["secondEmail"] = nil
	}

	employeeIDs := mapset.NewSet[string]()
	for profileKey, profileValue := range oktaProfile {
		switch strings.ToLower(profileKey) {
		case "employeenumber", "employeeid", "employeeidnumber", "employee_number", "employee_id", "employee_idnumber":
			if id, ok := profileValue.(string); ok {
				employeeIDs.Add(id)
			}
		case "login":
			if login, ok := profileValue.(string); ok {
				// If possible, calculate shortname alias from login
				splitLogin := strings.Split(login, "@")
				if len(splitLogin) == 2 {
					options = append(options, resource.WithUserLogin(login, splitLogin[0]))
				} else {
					options = append(options, resource.WithUserLogin(login))
				}
			}
		}
	}

	if employeeIDs.Cardinality() > 0 {
		options = append(options, resource.WithEmployeeID(employeeIDs.ToSlice()...))
	}

	switch user.Status {
	// TODO: change userStatusDeprovisioned to STATUS_DELETED once we show deleted stuff in baton & the UI
	// case userStatusDeprovisioned:
	// options = append(options, resource.WithDetailedStatus(v2.UserTrait_Status_STATUS_DELETED, user.Status))
	case userStatusSuspended, userStatusDeprovisioned:
		options = append(options, resource.WithDetailedStatus(v2.UserTrait_Status_STATUS_DISABLED, user.Status))
	case userStatusActive, userStatusProvisioned, userStatusStaged, userStatusPasswordExpired, userStatusRecovery, userStatusLockedOut:
		options = append(options, resource.WithDetailedStatus(v2.UserTrait_Status_STATUS_ENABLED, user.Status))
	default:
		options = append(options, resource.WithDetailedStatus(v2.UserTrait_Status_STATUS_UNSPECIFIED, user.Status))
	}

	ret, err := resource.NewUserResource(
		displayName,
		resourceTypeUser,
		user.Id,
		options,
		resource.WithAnnotation(&v2.RawId{Id: user.Id}),
	)
	return ret, err
}

func (o *userResourceType) CreateAccountCapabilityDetails(ctx context.Context) (*v2.CredentialDetailsAccountProvisioning, annotations.Annotations, error) {
	return &v2.CredentialDetailsAccountProvisioning{
		SupportedCredentialOptions: []v2.CapabilityDetailCredentialOption{
			v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_NO_PASSWORD,
			v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_RANDOM_PASSWORD,
		},
		PreferredCredentialOption: v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_NO_PASSWORD,
	}, nil, nil
}

func ToPtr[T any](v T) *T {
	return &v
}

func (r *userResourceType) CreateAccount(
	ctx context.Context,
	accountInfo *v2.AccountInfo,
	credentialOptions *v2.CredentialOptions,
) (
	connectorbuilder.CreateAccountResponse,
	[]*v2.PlaintextData,
	annotations.Annotations,
	error,
) {
	userProfile, err := getUserProfile(accountInfo)
	if err != nil {
		return nil, nil, nil, err
	}

	creds, err := getCredentialOption(credentialOptions)
	if err != nil {
		return nil, nil, nil, err
	}

	params, err := getAccountCreationQueryParams(accountInfo, credentialOptions)
	if err != nil {
		return nil, nil, nil, err
	}

	user, response, err := r.connector.client.User.CreateUser(ctx, okta.CreateUserRequest{
		Profile: userProfile,
		Type: &okta.UserType{
			Created:   ToPtr(time.Now()),
			CreatedBy: "ConductorOne",
		},
		Credentials: creds,
	}, params)
	if err != nil {
		return nil, nil, nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, nil, nil, fmt.Errorf("okta-connectorv2: failed to create user: %s", response.Status)
	}

	userResource, err := userResource(ctx, user, r.connector.skipSecondaryEmails)
	if err != nil {
		return nil, nil, nil, err
	}
	car := &v2.CreateAccountResponse_SuccessResult{
		Resource: userResource,
	}

	return car, nil, nil, nil
}

func getCredentialOption(credentialOptions *v2.CredentialOptions) (*okta.UserCredentials, error) {
	if credentialOptions.GetNoPassword() != nil {
		return nil, nil
	}

	if credentialOptions.GetRandomPassword() == nil {
		return nil, errors.New("unsupported credential options")
	}

	length := min(8, credentialOptions.GetRandomPassword().GetLength())
	plaintextPassword, err := crypto.GenerateRandomPassword(&v2.CredentialOptions_RandomPassword{
		Length: length,
	})
	if err != nil {
		return nil, err
	}

	return &okta.UserCredentials{
		Password: &okta.PasswordCredential{
			Value: plaintextPassword,
		},
	}, nil
}

func getUserProfile(accountInfo *v2.AccountInfo) (*okta.UserProfile, error) {
	pMap := accountInfo.Profile.AsMap()
	firstName, ok := pMap["first_name"]
	if !ok {
		return nil, fmt.Errorf("okta-connectorv2: missing first name in account info")
	}

	lastName, ok := pMap["last_name"]
	if !ok {
		return nil, fmt.Errorf("okta-connectorv2: missing last name in account info")
	}

	email, ok := pMap["email"]
	if !ok {
		return nil, fmt.Errorf("okta-connectorv2: missing email in account info")
	}

	login, ok := pMap["login"]
	if !ok {
		login = email
	}

	return &okta.UserProfile{
		"firstName": firstName,
		"lastName":  lastName,
		"email":     email,
		"login":     login,
	}, nil
}

func getAccountCreationQueryParams(accountInfo *v2.AccountInfo, credentialOptions *v2.CredentialOptions) (*query.Params, error) {
	if credentialOptions.GetNoPassword() != nil {
		return nil, nil
	}

	pMap := accountInfo.Profile.AsMap()
	requirePass := pMap["password_change_on_login_required"]
	requirePasswordChanged := false
	switch v := requirePass.(type) {
	case bool:
		requirePasswordChanged = v
	case string:
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			return nil, err
		}
		requirePasswordChanged = parsed
	case nil:
		// Do nothing
	}

	params := &query.Params{}
	if requirePasswordChanged {
		params.NextLogin = "changePassword"
		params.Activate = ToPtr(true) // This defaults to true anyways, but lets be explicit
	}
	return params, nil
}

func (o *userResourceType) Get(ctx context.Context, resourceId *v2.ResourceId, parentResourceId *v2.ResourceId) (*v2.Resource, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	l.Debug("getting user", zap.String("user_id", resourceId.Resource))

	var annos annotations.Annotations

	// If there are no email filters specified, don't sync user.
	if len(o.emailFilters) == 0 {
		return nil, nil, nil
	}

	user, respCtx, err := getUser(ctx, o.connector.client, resourceId.Resource)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to find user: %w", err)
	}

	resp := respCtx.OktaResponse
	if resp != nil {
		if desc, err := ratelimit.ExtractRateLimitData(resp.Response.StatusCode, &resp.Response.Header); err == nil {
			annos.WithRateLimiting(desc)
		}
	}

	if user == nil {
		return nil, annos, nil
	}

	if !shouldIncludeOktaUser(user, o.emailFilters) {
		return nil, annos, nil
	}

	resource, err := userResource(ctx, user, o.connector.skipSecondaryEmails)
	if err != nil {
		return nil, annos, err
	}

	return resource, annos, nil
}

func getUser(ctx context.Context, client *okta.Client, oktaUserID string) (*okta.User, *responseContext, error) {
	reqUrl, err := url.Parse(usersUrl)
	if err != nil {
		return nil, nil, err
	}

	reqUrl = reqUrl.JoinPath(oktaUserID)

	// Using okta-response="omitCredentials,omitCredentialsLinks,omitTransitioningToStatus" in the content type header omits
	// the credentials, credentials links, and `transitioningToStatus` field from the response which applies performance optimization.
	// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/User/#tag/User/operation/listUsers!in=header&path=Content-Type&t=request
	oktaUsers := &okta.User{}
	rq := client.CloneRequestExecutor()
	req, err := rq.
		WithAccept(ContentType).
		WithContentType(`application/json; okta-response="omitCredentials,omitCredentialsLinks,omitTransitioningToStatus"`).
		NewRequest(http.MethodGet, reqUrl.String(), nil)
	if err != nil {
		return nil, nil, err
	}

	// Need to set content type here because the response was still including the credentials when setting it with WithContentType above
	req.Header.Set("Content-Type", `application/json; okta-response="omitCredentials,omitCredentialsLinks,omitTransitioningToStatus"`)

	resp, err := rq.Do(ctx, req, &oktaUsers)
	if err != nil {
		return nil, nil, err
	}

	return oktaUsers, &responseContext{OktaResponse: resp}, nil
}
