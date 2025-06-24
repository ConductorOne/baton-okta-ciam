package main

import (
	cfg "github.com/conductorone/baton-okta-ciam/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/config"
)

func main() {
	config.Generate("okta-ciam", cfg.Config)
}
