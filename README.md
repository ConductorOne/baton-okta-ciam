![Baton Logo](./docs/images/baton-logo.png)

# `baton-okta-ciam` [![Go Reference](https://pkg.go.dev/badge/github.com/conductorone/baton-okta-ciam.svg)](https://pkg.go.dev/github.com/conductorone/baton-okta-ciam) ![main ci](https://github.com/conductorone/baton-okta-ciam/actions/workflows/main.yaml/badge.svg)

`baton-okta-ciam` is a connector for Okta built using the [Baton SDK](https://github.com/conductorone/baton-sdk). It communicates with the Okta API to sync data about which groups and users have access to applications, groups, and roles within an Okta domain.

Check out [Baton](https://github.com/conductorone/baton) to learn more about the project in general.

# Getting Started

## brew

```
brew install conductorone/baton/baton conductorone/baton/baton-okta-ciam

BATON_API_TOKEN=oktaAPIToken BATON_DOMAIN=domain-1234.okta.com baton-okta-ciam
baton resources
```

Or auth using a public/private keypair

```
BATON_OKTA_CLIENT_ID=appClientID \
BATON_OKTA_PRIVATE_KEY='auth.key' \
BATON_OKTA_PRIVATE_KEY_ID=appKID \
BATON_DOMAIN=domain-1234.okta.com baton-okta-ciam
baton resources
```

## docker

```
docker run --rm -v $(pwd):/out -e BATON_API_TOKEN=oktaAPIToken -e BATON_DOMAIN=domain-1234.okta.com ghcr.io/conductorone/baton-okta-ciam:latest -f "/out/sync.c1z"
docker run --rm -v $(pwd):/out ghcr.io/conductorone/baton:latest -f "/out/sync.c1z" resources
```

## source

```
go install github.com/conductorone/baton/cmd/baton@main
go install github.com/conductorone/baton-okta-ciam/cmd/baton-okta-ciam@main

BATON_API_TOKEN=oktaAPIToken BATON_DOMAIN=domain-1234.okta.com baton-okta-ciam
baton resources
```

# Data Model

`baton-okta-ciam` will pull down information about the following Okta resources:

- Applications
- Groups
- Roles
- Users
- Custom-Roles
- Resource-Sets
- Resourceset-Bindings

By default, `baton-okta-ciam` will sync information for inactive applications. You can exclude inactive applications setting the `--sync-inactive-apps` flag to `false`.

For syncing custom roles `--sync-custom-roles` must be provided. Its default value is `false`.

We have also introduced resourceset-bindings(resourcesetID and custom roles ID) for provisioning custom roles and members.

## Resourceset-bindings, custom roles and members(Users or Groups) usage:

- Let's use some IDs for this example
```
Resource Set `iamkuwy3gqcfNexfQ697`
Custom Role `cr0kuwv5507zJCtSy697`
Member `00ujp51vjgWd6ylZ6697`
```

- Granting custom roles for users.
```
BATON_API_TOKEN='oktaAPIToken' BATON_DOMAIN='domain-1234.okta.com' baton-okta-ciam \
--grant-entitlement 'resourceset-binding:iamkuwy3gqcfNexfQ697:cr0kuwv5507zJCtSy697:member' --grant-principal-type 'user' --grant-principal '00ujp51vjgWd6ylZ6697'
```

In the previous example we granted the custom role `cr0kuwv5507zJCtSy697` to user `00ujp5a9z0rMTsPRW697`.

- Revoking custom role grants(Unassigns a Member)
```
BATON_API_TOKEN='oktaAPIToken' BATON_DOMAIN='domain-1234.okta.com' baton-okta-ciam \
--revoke-grant 'resourceset-binding:iamkuwy3gqcfNexfQ697:cr0kuwv5507zJCtSy697:member:user:00ujp51vjgWd6ylZ6697' 
```

- Revoking everything associated to custom role(Deletes a Binding of a Role)
```
BATON_API_TOKEN='oktaAPIToken' BATON_DOMAIN='domain-1234.okta.com' baton-okta-ciam \
resource-set:iamkuwy3gqcfNexfQ697:bindings:custom-role:cr0kuwv5507zJCtSy697 
```

# Contributing, Support and Issues

We started Baton because we were tired of taking screenshots and manually building spreadsheets. We welcome contributions, and ideas, no matter how small -- our goal is to make identity and permissions sprawl less painful for everyone. If you have questions, problems, or ideas: Please open a Github Issue!

See [CONTRIBUTING.md](https://github.com/ConductorOne/baton/blob/main/CONTRIBUTING.md) for more details.

# `baton-okta-ciam` Command Line Usage

```
baton-okta-ciam

Usage:
  baton-okta-ciam [flags]
  baton-okta-ciam [command]

Available Commands:
  capabilities       Get connector capabilities
  completion         Generate the autocompletion script for the specified shell
  config             Get the connector config schema
  help               Help about any command

Flags:
      --api-token string                                 The API token for the service account ($BATON_API_TOKEN)
      --cache                                            Enable response cache ($BATON_CACHE) (default true)
      --cache-tti int                                    Response cache cleanup interval in seconds ($BATON_CACHE_TTI) (default 60)
      --cache-ttl int                                    Response cache time to live in seconds ($BATON_CACHE_TTL) (default 300)
      --ciam-email-domains strings                       The email domains to use for CIAM mode. Any users that don't have an email address with one of the provided domains will be ignored, unless explicitly granted a role ($BATON_CIAM_EMAIL_DOMAINS)
      --client-id string                                 The client ID used to authenticate with ConductorOne ($BATON_CLIENT_ID)
      --client-secret string                             The client secret used to authenticate with ConductorOne ($BATON_CLIENT_SECRET)
      --domain string                                    required: The URL for the Okta organization ($BATON_DOMAIN)
      --external-resource-c1z string                     The path to the c1z file to sync external baton resources with ($BATON_EXTERNAL_RESOURCE_C1Z)
      --external-resource-entitlement-id-filter string   The entitlement that external users, groups must have access to sync external baton resources ($BATON_EXTERNAL_RESOURCE_ENTITLEMENT_ID_FILTER)
  -f, --file string                                      The path to the c1z file to sync with ($BATON_FILE) (default "sync.c1z")
  -h, --help                                             help for baton-okta-ciam
      --log-format string                                The output format for logs: json, console ($BATON_LOG_FORMAT) (default "json")
      --log-level string                                 The log level: debug, info, warn, error ($BATON_LOG_LEVEL) (default "info")
      --otel-collector-endpoint string                   The endpoint of the OpenTelemetry collector to send observability data to (used for both tracing and logging if specific endpoints are not provided) ($BATON_OTEL_COLLECTOR_ENDPOINT)
  -p, --provisioning                                     This must be set in order for provisioning actions to be enabled ($BATON_PROVISIONING)
      --skip-full-sync                                   This must be set to skip a full sync ($BATON_SKIP_FULL_SYNC)
      --skip-secondary-emails                            Skip syncing secondary emails ($BATON_SKIP_SECONDARY_EMAILS)
      --sync-resources strings                           The resource IDs to sync ($BATON_SYNC_RESOURCES)
      --ticketing                                        This must be set to enable ticketing support ($BATON_TICKETING)
  -v, --version                                          version for baton-okta-ciam

Use "baton-okta-ciam [command] --help" for more information about a command.
```
