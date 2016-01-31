// auth_verify project auth_verify.go
package auth_verify

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/ianmcmahon/encoding_ssh"
)

// Parse string Comma key value and return map
// key=value,key2=value2
func ParseCommaKeyValue(entireString string) (map[string]string, error) {
	m := make(map[string]string)
	if len(entireString) > 1 {
		var keyValueSlice []string
		for _, keyValueString := range strings.Split(entireString, ",") {

			keyValueSlice = strings.Split(keyValueString, "=")
			if len(keyValueSlice) != 2 {
				return m, nil
			} else {
				// strip "
				m[keyValueSlice[0]] = strings.Trim(keyValueSlice[1], "\"")
			}
		}
		return m, nil
	} else {
		return m, nil
	}
}

// Takes
func convertPkix(key interface{}) (*rsa.PublicKey, error) {
	// Marshal to ASN.1 DER encoding
	pkix, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}

	re, err := x509.ParsePKIXPublicKey([]byte(pkix))
	if err != nil {
		return nil, fmt.Errorf("Public key error in parsing :'%s'\n", err)
	}
	return re.(*rsa.PublicKey), nil
}

// santise path
func checkPath(base_path string, header_path string) (string, error) {
	//need to remove special char
	abs_base_path, err := filepath.Abs(base_path)
	if err != nil {
		return "", fmt.Errorf("Error absolute basedir path :'%v'", err)
	}

	xpath, err := filepath.Abs(filepath.Join(abs_base_path, header_path))
	if err != nil {
		return "", fmt.Errorf("Error absolute header path :'%v'", err)
	}

	rel, err := filepath.Rel(abs_base_path, xpath)
	if err != nil {
		return "", fmt.Errorf("Error rel path :'%v'", err)
	}
	abspath := filepath.Join(abs_base_path, rel)

	if strings.Contains(abspath, abs_base_path) == false {
		return "", fmt.Errorf("Error base path in join. Probably security issue")
	}

	return abspath, nil
}

func ReadPublicKey(base_path string, header_path string) (*rsa.PublicKey, error) {
	abspath, err := checkPath(base_path, header_path)
	if err != nil {
		return nil, fmt.Errorf("Failed to check path to key :'%v'", err)
	}
	bytes, err := ioutil.ReadFile(abspath)
	if err != nil {
		return nil, fmt.Errorf("Failed to read public key :'%v'", err)
	}
	// decode string ssh-rsa format to native type
	pub_key, err := ssh.DecodePublicKey(string(bytes))
	if err != nil {
		return nil, fmt.Errorf("Decoding public key failed :'%v'", err)
	}
	public_key, err := convertPkix(pub_key)
	if err != nil {
		return nil, fmt.Errorf("convert public key failed :'%v'", err)
	}
	return public_key, nil
}

// The CreateAuthorizationHeader returns the Authorization header for the give request.
// Only support SDCsignature for now
func ParseAuthorizationHeader(headers http.Header, isMantaRequest bool) (map[string]string, error) {
	//"Signature keyId='/user_test/keys/user_test',algorithm='rsa-sha256' FOUmNhldoFHsit6QkTedZDeOUbIcIY+1cgZAm7HYjx3B1r/r9826j0r18v1kW874uX0oLNhh33r1+pXlUgAZ+xkmelaFhh9fk8tsv3JIJGKZnF0pJjDs0oQ5mYT0W9TmEF6WHE3bhO2ipM1m1pCdLyFjTe0LTDJs4VPs0q+3u4MD4TUZq24TF+9XlHeEkVkUHAqhXqSTw2FXi9XheQonns3V0BQbitulkcIOkjHlp+IHedCbaD7l6tLawkiJaPIKZUWH4ugvnPwUhVAQDDxkJ9KGlCb2JWJArspCcI/dHqOwKDn1O+4s0t+pQqKlKl93YQSEaerZosaXdT8ux3vVXg=="
	// Check Authorization syntax based on SDC signature "Signature keyId=\"/%s/keys/%s\",algorithm=\"%s\" %s"
	if authorization_header, ok := headers["Authorization"]; ok {
		authorization_header_slice := strings.Fields(authorization_header[0])
		if len(authorization_header_slice) != 3 {
			return make(map[string]string), fmt.Errorf("Authorization header malformed. Length is not correct")
		}
		if authorization_header_slice[0] != "Signature" {
			return make(map[string]string), fmt.Errorf("Authorization header malformed. Incorrect signature")
		}
		m, err := ParseCommaKeyValue(authorization_header_slice[1])
		if err != nil {
			return make(map[string]string), fmt.Errorf("Authorization header malformed. Key value parse error: %s", err)
		}
		// Add signature
		m["sig"] = authorization_header_slice[2]

		return m, nil
	} else {
		return make(map[string]string), fmt.Errorf("No Authorization header")
	}
}

func Verify(base_key_dir string, headers http.Header, isMantaRequest bool) (bool, error) {
	// Parse header
	m, err := ParseAuthorizationHeader(headers, false)
	if err != nil {
		return false, fmt.Errorf("%v", err)
	}
	my_key, err := ReadPublicKey(base_key_dir, m["keyId"])
	if err != nil {
		return false, fmt.Errorf("%v", err)
	}
	// Try to get the right hash if not will fall to default
	hashFunc := getHashFunction(m["algorithm"])

	if date, ok := headers["Date"]; ok {
		// TODO: Verify date formant and that its lagging or passing by 300 sec
		access, err := VerifySignature(my_key, hashFunc, date[0], m["sig"])
		if err != nil {
			return false, fmt.Errorf("%v", err)
		}
		return access, nil
	} else {
		return false, fmt.Errorf("No Date header")
	}
}

// sig is the signature
// signing String that will be hashed
func VerifySignature(public_key *rsa.PublicKey, hashFunc crypto.Hash, signing string, sig string) (bool, error) {
	hash := hashFunc.New()
	hash.Write([]byte(signing))
	digest := hash.Sum(nil)

	decoded_sign, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return false, fmt.Errorf("decode signed signature failed :'%s'\n", err)
	}
	err = rsa.VerifyPKCS1v15(public_key, hashFunc, digest, []byte(decoded_sign))
	if err != nil {
		return false, fmt.Errorf("An error occurred while signing the key: %s", err)
	} else {
		return true, nil
	}
}

// Helper method to get the Hash function based on the algorithm
func getHashFunction(algorithm string) (hashFunc crypto.Hash) {
	switch strings.ToLower(algorithm) {
	case "rsa-sha1":
		hashFunc = crypto.SHA1
	case "rsa-sha224", "rsa-sha256":
		hashFunc = crypto.SHA256
	case "rsa-sha384", "rsa-sha512":
		hashFunc = crypto.SHA512
	default:
		hashFunc = crypto.SHA256
	}
	return
}
