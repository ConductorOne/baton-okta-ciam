package main

import (
	"context"
	"fmt"
	"os"

	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/field"
	"github.com/conductorone/baton-sdk/pkg/types"

	"github.com/conductorone/baton-okta-ciam/pkg/config"
	"github.com/conductorone/baton-okta-ciam/pkg/connector"
	configschema "github.com/conductorone/baton-sdk/pkg/config"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

var version = "dev"

func main() {
	ctx := context.Background()
	_, cmd, err := configschema.DefineConfiguration(ctx, "baton-okta-ciam", getConnector, config.Config)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	cmd.Version = version
	err = cmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func getConnector(ctx context.Context, oc *config.OktaCiam) (types.ConnectorServer, error) {
	l := ctxzap.Extract(ctx)

	err := field.Validate(config.Config, oc)
	if err != nil {
		return nil, err
	}

	ccfg := &connector.Config{
		Domain:              oc.Domain,
		ApiToken:            oc.ApiToken,
		CiamEmailDomains:    oc.CiamEmailDomains,
		Cache:               oc.Cache,
		CacheTTI:            int32(oc.CacheTti),
		CacheTTL:            int32(oc.CacheTtl),
		SkipSecondaryEmails: oc.SkipSecondaryEmails,
	}

	cb, err := connector.New(ctx, ccfg)
	if err != nil {
		l.Error("error creating connector", zap.Error(err))
		return nil, err
	}

	connector, err := connectorbuilder.NewConnector(ctx, cb)
	if err != nil {
		l.Error("error creating connector", zap.Error(err))
		return nil, err
	}

	return connector, nil
}
