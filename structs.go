package main

import (
	"time"
)

type Config struct {
	SignerName                      string `json:"signer_name"`
	SignerEmail                     string `json:"signer_email"`
	CcName                          string `json:"cc_name"`
	CcEmail                         string `json:"cc_email"`
	IntegrationKey                  string `json:"integration_key"`
	UserImpersonationGUIDJwt        string `json:"user_impersonation_guid_jwt"`
	SecretKeyAuthorizationCodeGrant string `json:"secret_key_authorization_code_grant"`
	RSAPrivateKeyJwtLocation        string `json:"RSA_private_key_jwt_location"`
}

type AccessToken struct {
	Token  string `json:"access_token"`
	Type   string `json:"token_type"`
	Expiry int    `json:"expires_in"`
}

// Auto-generated using https://transform.tools/json-to-go
type AccountId struct {
	Sub        string `json:"sub"`
	Name       string `json:"name"`
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
	Created    string `json:"created"`
	Email      string `json:"email"`
	Accounts   []struct {
		AccountID    string `json:"account_id"`
		IsDefault    bool   `json:"is_default"`
		AccountName  string `json:"account_name"`
		BaseURI      string `json:"base_uri"`
		Organization struct {
			OrganizationID string `json:"organization_id"`
			Links          []struct {
				Rel  string `json:"rel"`
				Href string `json:"href"`
			} `json:"links"`
		} `json:"organization"`
	} `json:"accounts"`
}

// Auto-generated using https://transform.tools/json-to-go
type EnvelopeID struct {
	EnvelopeID     string    `json:"envelopeId"`
	URI            string    `json:"uri"`
	StatusDateTime time.Time `json:"statusDateTime"`
	Status         string    `json:"status"`
}

// Auto-generated using https://transform.tools/json-to-go
type CustomFields struct {
	TextCustomFields []struct {
		FieldID  string `json:"fieldId"`
		Name     string `json:"name"`
		Show     string `json:"show"`
		Required string `json:"required"`
		Value    string `json:"value"`
	} `json:"textCustomFields"`
	ListCustomFields []interface{} `json:"listCustomFields"`
}
