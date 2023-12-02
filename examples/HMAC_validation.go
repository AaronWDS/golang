package examples

import (
	"encoding/base64"
	"crypto/hmac"
	"crypto/sha256"
	"os"
	"fmt"
)



func computeHash(secret []byte, payload []byte) string{
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	base64Hash := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return base64Hash
}

func checkHash(secret string, payload []byte, verify string) bool {

	return hmac.Equal([]byte(verify), []byte(computeHash([]byte(secret), payload)))
}

func main(){
	jsonResult, err := os.ReadFile("./payload.txt")
	if err != nil {
		fmt.Printf("Error opening file: %s", err)
		os.Exit(1)

	}

	fmt.Printf("Is this HMAC valid? %t", checkHash("{DocuSign HMAC private key}", jsonResult, "{JSON response signature}"))


}