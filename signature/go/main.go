package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func main() {
	// Setup the two endpoints that Pomelo will hit in order to process card
	// transactions:
	http.HandleFunc("/transactions/authorizations", authorizations)
	http.HandleFunc("/transactions/adjustments/", adjustments)

	// start http server
	http.ListenAndServe(":1080", nil)
}

// authorizations is your endpoint to handle card transactions that you can
// approve or reject. Here you'd check the user balance and apply any custom
// business logic
func authorizations(w http.ResponseWriter, r *http.Request) {
	if !checkSignature(r) {
		fmt.Println("Invalid signature, aborting")
		return
	}

	// do your logic

	fmt.Println("Authorization processed")

	response := struct {
		Status       string `json:"status,omitempty"`
		StatusDetail string `json:"status_detail,omitempty"`
		Message      string `json:"message,omitempty"`
	}{"APPROVED", "APPROVED", "Ok"}

	// Marshal object to bytes (alternatively to string and then to bytes). It's
	// important to sign the exact same bytes that are written to the response
	// body.
	// Be careful with frameworks that allow you to return objects directly,
	// because their json marshalling might be different from yours. In that
	// case we recommend using a filter/interceptor/middleware to access the
	// raw response body
	body, _ := json.Marshal(response)

	signResponse(body, w, r) // sign response first so headers are written before body
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

// adjustments is your endpoint to handle forced transactions that you need to
// register in your system, but can't reject
func adjustments(w http.ResponseWriter, r *http.Request) {
	if !checkSignature(r) {
		fmt.Println("Invalid signature, aborting")
		return
	}

	// do your logic

	fmt.Println("Adjustment processed")

	// adjustments have an empty response with no response body. Be careful with empty
	// objects and frameworks that might encode these as {}, the string "None",
	// a blank space ' ', etc. Signing those strings  will make the signature check to fail.

	signResponse(nil, w, r) // write signature headers first
	w.Header().Set("Content-Type", "application/json")
	w.Write(nil) // write body after adding the response headers
}

// checkSignature does all the signature validations that you need to implement
// to make sure only Pomelo has signed this request and not an attacker. A
// signature mismatch should abort the http request or return Forbidden
func checkSignature(r *http.Request) bool {
	endpoint := r.Header.Get("X-Endpoint")
	timestamp := r.Header.Get("X-Timestamp")
	signature := r.Header.Get("X-Signature")

	// Pomelo sends the algorithm + the signature in the X-Signature header, separated by a space
	// ex:
	// 		X-Signature:hmac-sha256 whk5MLlMd+zJBkEDGa9LYZVUsNsdKWJ94Qm3EXy6VK8=
	if strings.HasPrefix(signature, "hmac-sha256") {
		signature = strings.TrimPrefix(signature, "hmac-sha256 ")
	} else {
		fmt.Printf("Unsupported signature algorithm, expecting hmac-sha256, got %s\n", signature)
		return false
	}

	// important to read the raw body directly from the request as bytes, prior
	// to any json object deserialization which are framework-specific and can
	// change the string representation
	bodyBytes, _ := ioutil.ReadAll(r.Body)

	secret := getApiSecret(r.Header.Get("X-Api-Key"))

	// construct a new hasher and hash timestamp + endpoint + body without any
	// separators nor any decoding
	hash := hmac.New(sha256.New, secret)
	hash.Write([]byte(timestamp))
	hash.Write([]byte(endpoint))
	hash.Write(bodyBytes)

	hashResultBytes := hash.Sum(nil)                                 // calculated signature result
	hashResult := base64.StdEncoding.EncodeToString(hashResultBytes) // string representation

	// compare signatures using a cryptographically secure function
	// for that you normally need the signature bytes, so decode from base64
	signatureBytes, _ := base64.StdEncoding.DecodeString(signature)
	signaturesMatch := hmac.Equal(signatureBytes, hashResultBytes)

	if !signaturesMatch {
		fmt.Printf("Signature mismatch. Received %s, calculated %s\n", signature, hashResult)
		return false
	}

	return true
}

// signResponse computes the signature of the given response and writes the
// necessary headers that Pomelo needs in order to reconstruct and validate the
// signature. If this method computes the signature wrongly, Pomelo will reject
// al responses!
func signResponse(body []byte, w http.ResponseWriter, r *http.Request) {
	endpoint := r.Header.Get("X-Endpoint")

	// do not re-send the same timestamp that pomelo sent, simply send the
	// current time. Clock skews can cause the signature check to fail!
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	secret := getApiSecret(r.Header.Get("X-Api-Key"))

	// construct a new hasher and hash timestamp + endpoint + body (if not nil) without
	// separators nor any decoding (notice how body might not be part of the signature)
	hash := hmac.New(sha256.New, secret)
	hash.Write([]byte(timestamp))
	hash.Write([]byte(endpoint))

	// be careful with empty bodies, do not hash spaces, empty json objects
	// (like {}), the string 'null', etc. Simply don't hash anything
	// if body is nil we don't pass it to the hasher so it's not considered for
	// signing
	if body != nil {
		hash.Write(body)
	}

	hashResultBytes := hash.Sum(nil)                                 // calculated signature result
	hashResult := base64.StdEncoding.EncodeToString(hashResultBytes) // string representation

	w.Header().Set("X-Endpoint", endpoint)
	w.Header().Set("X-Timestamp", timestamp)

	// remember to write the algorithm plus the hash result
	w.Header().Set("X-Signature", "hmac-sha256 "+hashResult)
}

// We do not recommend storing api secrets in your code, specially in plaintext
// This is here just for example purposes
var apiSecrets = map[string]string{
	"Lp0g+cwb19eEfTn1YIOydEnqPcZOg8YxHctnMe+1cQA=": "uC8fVXzXMyaw1PseV452i6ozQwIIa4olcSpjuvn5E4E=",
}

// getApiSecret returns the api secret for a given api key. We recommend you
// support multiple key pairs simultaneously and not just one key pair.
func getApiSecret(apiKey string) []byte {
	apiSecret, _ := apiSecrets[apiKey]
	key, _ := base64.StdEncoding.DecodeString(apiSecret)

	// abort if key not found!

	return key
}
