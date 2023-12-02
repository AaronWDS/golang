package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"examples"
	"github.com/golang-jwt/jwt"
	"github.com/pkg/browser"
)

// Random String generator made from: https://github.com/Onelinerhub/onelinerhub/blob/main/golang/how-to-generate-random-string.md
var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func rand_str(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

var DSAccessToken string
var DSAccountId string
var EnvelopeId string
var EnvelopeDefinition string
var config Config

// For RSA signing method, the key can be any []byte. It is recommended to generate
// a key using crypto/rand or something equivalent. You need the same key for signing
// and validating.
var RSAPrivateKey []byte

func makeDSToken(config Config) (string, error) {

	// Create a new JWT claim. Set your integration key, impersonated user GUID, time of issue, expiry time, account server, and required scopes
	rawJWT := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   config.IntegrationKey,
		"sub":   config.UserImpersonationGUIDJwt,
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Unix() + 3600,
		"aud":   "account-d.docusign.com",
		"scope": "signature impersonation",
	})

	RSAPrivateKey, err := os.ReadFile(config.RSAPrivateKeyJwtLocation)
	if err != nil {
		log.Fatalf("Error opening file: %s", err)
		return "", err
	}

	// Load the private.key file into JWT library
	rsaPrivate, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(RSAPrivateKey))
	if err != nil {
		log.Fatalf("key update error for: %s", err)
		return "", err
	}

	// Generate the signed JSON Web Token assertion with an RSA private key
	tokenString, err := rawJWT.SignedString(rsaPrivate)
	//fmt.Println(tokenString, err)
	if err != nil {
		log.Fatalf("Request Failed: %s", err)
		return "", err
	}

	// Submit the JWT to the account server and request and access token
	resp, err := http.PostForm("https://account-d.docusign.com/oauth/token",
		url.Values{
			"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
			"assertion":  {tokenString},
		})

	if err != nil {
		log.Fatalf("Request Failed: %s", err)
		return "", err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Request Failed: %s", err)
		return "", err
	}
	fmt.Printf("Body: %s\n", body)

	if strings.Contains(string(body), "consent_required") {
		fmt.Println("consent has not been granted to use this account")
		var loginUrl = fmt.Sprintf("https://account-d.docusign.com/oauth/auth?response_type=code&scope=signature+impersonation&client_id=%s&redirect_uri=https://developers.docusign.com/platform/auth/consent", config.IntegrationKey)
		browser.OpenURL(loginUrl)
		fmt.Println("A new browser window has been opened to: %s", loginUrl)
		fmt.Println("Waiting for 90 seconds then I'll try to login using JWT again")
		time.Sleep(90 * time.Second)
		makeDSToken(config)
	}

	// Done with the request, close it: https://stackoverflow.com/q/18598780/2226328
	resp.Body.Close()

	// Decode the response to JSON
	var token AccessToken
	jsonErr := json.Unmarshal(body, &token)
	if jsonErr != nil {
		log.Fatalf("There was an error decoding the json. err = %s", jsonErr)
		return "", jsonErr
	}
	//fmt.Println(token.Token)
	return token.Token, nil
}

// Internal API call to pull in the API account ID GUID used to make all subsequent API calls
func getAPIAccId(DSAccessToken string) (string, error) {
	client := &http.Client{}
	// Use http.NewRequest in order to set custom headers
	req, err := http.NewRequest("GET", "https://account-d.docusign.com/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+DSAccessToken)
	if err != nil {
		log.Fatalf("Request Failed: %s", err)
		return "", err
	}

	// Since http.NewRequest is being used, client.Do is needed to execute the request
	res, err := client.Do(req)
	if err != nil {
		log.Fatalf("Request Failed: %s", err)
		return "", err

	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("Request Failed: %s", err)
		return "", err
	}
	// fmt.Printf("Body: %s\n", body)
	res.Body.Close()

	// Decode the response to JSON
	var accountId AccountId
	jsonErr := json.Unmarshal(body, &accountId)
	if jsonErr != nil {
		log.Fatalf("There was an error decoding the json. err = %s", jsonErr)
		return "", jsonErr
	}

	//fmt.Println(accountId.Accounts[0].AccountID)
	return accountId.Accounts[0].AccountID, nil

}

// Make the envelope definition
func makeEnvelope(signerName string, signerEmail string, ccName string, ccEmail string) string {

	envelope := fmt.Sprintf(`{
    "emailSubject": "Please sign this document set",
    "documents": [{
        "documentBase64": "DQoNCg0KCQkJCXRleHQgZG9jDQoNCg0KDQoNCg0KUk0gIwlSTSAjCVJNICMNCg0KDQoNClxzMVwNCg0KLy9hbmNoMSANCgkvL2FuY2gyDQoJCS8vYW5jaDM=",
        "documentId": "1",
        "fileExtension": "txt",
        "name": "NDA"
    }],
    "recipients": {
        "carbonCopies": [
            {
                "email": "%s",
                "name": "%s",
                "recipientId": "2",
                "routingOrder": "2"
            }
        ],
        "signers": [
            {
                "email": "%s",
                "name": "%s",
                "recipientId": "1",
                "routingOrder": "1",
                "tabs": {
                    "signHereTabs": [{
                        "documentId": "1",
                        "name": "SignHereTab",
                        "pageNumber": "1",
                        "recipientId": "1",
                        "tabLabel": "SignHereTab",
                        "xPosition": "75",
                        "yPosition": "572"
                    }]
                },
            }
        ]
    },
    "status": "sent"
}`, ccEmail, ccName, signerEmail, signerName)

	return envelope
}

func makeCustomFieldsEnvelope(signerEmail string, signerName string, customerId string) string {

	dateTimeString := time.Now().Format("01-02-2006")

	envelope := fmt.Sprintf(`{
    "emailSubject": "Please review this recent order:",
    "documents": [{
        "documentBase64": "DQoNCg0KCQkJCXRleHQgZG9jDQoNCg0KDQoNCg0KUk0gIwlSTSAjCVJNICMNCg0KDQoNClxzMVwNCg0KLy9hbmNoMSANCgkvL2FuY2gyDQoJCS8vYW5jaDM=",
        "documentId": "1",
        "fileExtension": "txt",
        "name": "Order Summary %s"
    }],
   	    "customFields": {
                "textCustomFields": [
                {
                    "name": "trackingNumber",
                    "required": "false",
                    "show": "true",
        	    },
                {
                    "name": "shippingDate",
                    "required": "false",
                    "show": "true",
        	    },                
                {
                    "name": "customerID",
                    "required": "true",
                    "show": "true",
                    "value": "%s"
        	    }
                ]
            },
    "recipients": {
        "signers": [
            {
                "email": "%s",
                "name": "%s",
                "recipientId": "1",
                "routingOrder": "1",
                "tabs": {
                    "signHereTabs": [{
                        "documentId": "1",
                        "name": "SignHereTab",
                        "pageNumber": "1",
                        "recipientId": "1",
                        "tabLabel": "SignHereTab",
                        "xPosition": "75",
                        "yPosition": "572"
                    }]
                },
            }
        ]
    },
    "status": "sent"
}`, dateTimeString, customerId, signerEmail, signerName)

	return envelope
}

// Send an envelope
func sendEnvelope(DSAccessToken string, DSAccountId string, envelopeDefinition string) (string, error) {
	client := &http.Client{}
	// Use http.NewRequest in order to set custom headers
	req, err := http.NewRequest("POST", "https://demo.docusign.net/restapi/v2.1/accounts/"+DSAccountId+"/envelopes", strings.NewReader(envelopeDefinition))
	req.Header.Set("Authorization", "Bearer "+DSAccessToken)
	if err != nil {
		log.Fatalf("Request Failed: %s", err)
		return "", err
	}
	// Since http.NewRequest is being used, client.Do is needed to execute the request
	res, err := client.Do(req)
	if err != nil {
		log.Fatalf("Request Failed: %s", err)
		return "", err
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("Request Failed: %s", err)
		return "", err
	}

	// Decode the response to JSON
	var envelope EnvelopeID
	jsonErr := json.Unmarshal(body, &envelope)
	if jsonErr != nil {
		log.Fatalf("Request Failed: %s", jsonErr)
		return "", jsonErr
	}
	return envelope.EnvelopeID, nil
}

// Gets envelope custom fields
func getCustomFields(DSAccessToken string, DSAccountId string, envelopeId string) ([]string, error) {
	client := &http.Client{}
	// Use http.NewRequest in order to set custom headers
	req, err := http.NewRequest("GET", "https://demo.docusign.net/restapi/v2.1/accounts/"+DSAccountId+"/envelopes/"+envelopeId+"/custom_fields", nil)
	req.Header.Set("Authorization", "Bearer "+DSAccessToken)
	if err != nil {
		log.Fatalf("Request Failed: %s", err)
		return []string{}, err
	}
	// Since http.NewRequest is being used, client.Do is needed to execute the request
	res, err := client.Do(req)
	if err != nil {
		log.Fatalf("Request Failed: %s", err)
		return []string{}, err
	}
	// fmt.Printf("response: %s\n", res)

	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("Request Failed: %s", err)
		return []string{}, err
	}

	// Decode the response to JSON
	var customFields CustomFields
	jsonErr := json.Unmarshal(body, &customFields)
	if jsonErr != nil {
		log.Fatalf("Request Failed: %s", jsonErr)
		return []string{}, jsonErr
	}
	fmt.Print(customFields.TextCustomFields[0].FieldID + " -> tracking id\n")
	fmt.Print(customFields.TextCustomFields[1].FieldID + " -> ship date\n")
	responseArray := []string{customFields.TextCustomFields[0].FieldID, customFields.TextCustomFields[1].FieldID}
	return responseArray, nil
}

// Sets custom field values for an envelope
func setCustomfieldValues(DSAccessToken string, DSAccountId string, envelopeId string, trackingNumberFieldId string, shippingDateFieldId string) (string, error) {
	client := &http.Client{}

	// For the sake of the example these are arbitrary values,
	// on a real application these values should be retreived
	// from an orders table on a database
	shippingDate := time.Now().Add(time.Hour * 24 * 3).Format("01-02-2006")
	trackingNumber := "1Z" + rand_str(16)

	requestBody := fmt.Sprintf(`{ textCustomFields: [
        { "fieldId" : "%s",
          "value"  : "%s" },
          { "fieldId" : "%s",
          "value"  : "%s" }

        ]}`, trackingNumberFieldId, trackingNumber, shippingDateFieldId, shippingDate)

	// Use http.NewRequest in order to set custom headers
	req, err := http.NewRequest("PUT", "https://demo.docusign.net/restapi/v2.1/accounts/"+DSAccountId+"/envelopes/"+envelopeId+"/custom_fields", strings.NewReader(requestBody))
	req.Header.Set("Authorization", "Bearer "+DSAccessToken)
	if err != nil {
		log.Fatalf("Request Failed: %s", err)
		return "", err
	}
	// Since http.NewRequest is being used, client.Do is needed to execute the request
	res, err := client.Do(req)
	if err != nil {
		log.Fatalf("Request Failed: %s", err)
		return "", err
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("Request Failed: %s", err)
		return "", err
	}
	fmt.Printf("Body: %s\n", body)

	return string(body), nil
}

// Voids an envelope
func voidEnvelope(DSAccessToken string, DSAccountId string, EnvelopeID string) (string, error) {
	client := &http.Client{}

	voidBody := `{
		"status": "voided",
		"voidedReason": "The reason for voiding the envelope"
	  }`

	// Use http.NewRequest in order to set custom headers
	req, err := http.NewRequest("PUT", "https://demo.docusign.net/restapi/v2.1/accounts/"+DSAccountId+"/envelopes/"+EnvelopeID, strings.NewReader(voidBody))
	req.Header.Set("Authorization", "Bearer "+DSAccessToken)
	if err != nil {
		log.Fatalf("Request Failed: %s", err)
		return "", err
	}
	// Since http.NewRequest is being used, client.Do is needed to execute the request
	res, err := client.Do(req)
	if err != nil {
		log.Fatalf("Request Failed: %s", err)
		return "", err
	}
	fmt.Print("Void Envelope Response: " + res.Status + "\n")
	return res.Status, err

}

func main() {

	fmt.Println("\n\nWelcome to the DocuSign Go Launcher using Authorization Code grant or JWT grant authentication.")

	data, err := os.ReadFile("config.json")
	if err != nil {
		log.Fatalf("Error when opening file: %v", err)
	}

	err = json.Unmarshal(data, &config)
	if err != nil {
		log.Fatalf("Error when unmarshaling JSON: %v", err)
	}

	//fmt.Printf("Config: %+v\n", config)

	// we delcared the config variable around line 92

	fmt.Println("We're making an Access token using JWT grant authentication.\n")
	dSAccessToken, err := makeDSToken(config)
	if err != nil {
		log.Fatalf("Failed to retrieve token: %s", err)
	}
	fmt.Printf("access token: %s\n", dSAccessToken)

	fmt.Println("\n\nNow we're retrieving your API account ID to make further API calls")
	dSAccountId, err := getAPIAccId(dSAccessToken)
	if err != nil {
		log.Fatalf("Failed to API Account ID token: %s", err)
	}

	// section 1: send an envelope (and VOID IT)

	envelopeDefinition := makeEnvelope(config.SignerName, config.SignerEmail, config.CcName, config.CcEmail)
	envelopeId, err := sendEnvelope(dSAccessToken, dSAccountId, envelopeDefinition)
	if err != nil {
		log.Fatalf("Failed to retrieve token: %s", err)
	}

	voidEnvelope(dSAccessToken, dSAccountId, envelopeId)

	// section 2: BONUS: Let's create an envelope with Custom Fields then update them programmatically
	envelopeDefinitionCustomTabs := makeCustomFieldsEnvelope(config.SignerEmail, config.SignerName, "CUSTOMER-"+rand_str(14))
	// fmt.Printf(envelopeDefinitionCustomTabs)

	envelopeId2, err := sendEnvelope(dSAccessToken, dSAccountId, envelopeDefinitionCustomTabs)
	if err != nil {
		log.Fatalf("update custom fields request failed: %s", err)
	}
	// fmt.Print("envelope ID is: " + envelopeId2 + "\n")

	// Lets retrieve the Envelope custom Fields ids
	customFieldIds, err := getCustomFields(dSAccessToken, dSAccountId, envelopeId2)

	// Set the shipping date and tracking number on the envelope
	finalRes, err := setCustomfieldValues(dSAccessToken, dSAccountId, envelopeId2, customFieldIds[0], customFieldIds[1])
	fmt.Printf("Envelope Custom fields updated successfully: \n%s", finalRes)

}
