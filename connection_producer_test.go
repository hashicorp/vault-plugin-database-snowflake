// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package snowflake

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	random "math/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOpenSnowflake(t *testing.T) {
	// Generate a new RSA key for testing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}
	var pemKey bytes.Buffer
	pem.Encode(&pemKey, pemBlock)

	db, err := openSnowflake("account.snowflakecomputing.com/db", "user", pemKey.String())
	if err != nil {
		t.Fatalf("Failed to open Snowflake connection: %v", err)
	}

	require.NotNil(t, db.Stats())
}

func TestParseSnowflakeFieldsFromURL(t *testing.T) {
	tests := map[string]struct {
		connectionURL string
		wantAccount   string
		wantDB        string
		wantErr       error
	}{
		"valid URL": {
			connectionURL: "account.snowflakecomputing.com/db",
			wantAccount:   "account",
			wantDB:        "db",
			wantErr:       nil,
		},
		"complex URL": {
			connectionURL: "dev.org_v2.1.5-us-eas2-1.snowflakecomputing.com/secret-db.name/withslash",
			wantAccount:   "dev.org_v2.1.5-us-eas2-1",
			wantDB:        "secret-db.name/withslash",
			wantErr:       nil,
		},
		"invalid URL": {
			connectionURL: "invalid-url",
			wantAccount:   "",
			wantDB:        "",
			wantErr:       ErrInvalidSnowflakeURL,
		},
		"missing account name": {
			connectionURL: ".snowflakecomputing.com/db",
			wantAccount:   "",
			wantDB:        "",
			wantErr:       ErrInvalidSnowflakeURL,
		},
		"missing database name": {
			connectionURL: "account.snowflakecomputing.com/",
			wantAccount:   "",
			wantDB:        "",
			wantErr:       ErrInvalidSnowflakeURL,
		},
		"missing domain": {
			connectionURL: "account..com/db",
			wantAccount:   "",
			wantDB:        "",
			wantErr:       ErrInvalidSnowflakeURL,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			user, db, err := parseSnowflakeFieldsFromURL(tt.connectionURL)

			require.Equal(t, tt.wantAccount, user)
			require.Equal(t, tt.wantDB, db)
			require.Equal(t, tt.wantErr, err)
		})
	}
}

func TestGetPrivateKey(t *testing.T) {
	fileName := fmt.Sprintf("%s.pem", RandomWithPrefix("test"))
	file, err := os.Create(fileName)
	if err != nil {
		t.Fatalf("Failed to create private key file: %v", err)
	}
	defer file.Close()
	defer os.Remove(fileName)

	// Write content to the file
	_, err = file.Write([]byte(testPrivateKey))
	if err != nil {
		t.Fatalf("Failed to write to file: %v", err)
	}
	tests := map[string]struct {
		providedPrivateKey string
		wantErr            error
	}{
		"valid private key file": {
			providedPrivateKey: fileName,
			wantErr:            nil,
		},
		"valid private key string": {
			providedPrivateKey: testPrivateKey,
			wantErr:            nil,
		},
		"empty private key": {
			providedPrivateKey: "",
			wantErr:            ErrInvalidPrivateKey,
		},
		"invalid private key": {
			providedPrivateKey: "-----BEGIN PRIVATE KEY-----\ninvalid\n",
			wantErr:            ErrInvalidPrivateKey,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := getPrivateKey(tt.providedPrivateKey)

			require.Equal(t, tt.wantErr, err)
		})
	}
}

// RandomWithPrefix is used to generate a unique name with a prefix, for
// randomizing names in acceptance tests
func RandomWithPrefix(name string) string {
	return fmt.Sprintf("%s-%d", name, random.Int())
}

// Used in tests. Original ref in Vault:
// https://github.com/hashicorp/vault-enterprise/blob/main/builtin/logical/nomad/backend_test.go#L687
const testPrivateKey = `
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCz5diGxba9PA3u
BjfEzGBs03x3dqh6oKzA6nTkEF/RWC/d95tqGbjba5tdd3kyDZQaJTuwlV7i1SkN
66lVVFflCv+GmJeATJ9EMAAAkqquXrkpJLrZMJtP94lnRqHbkdXV68ji4zbSSXlB
aG1CMPJpWVNLfxgWpddC+k65TkMbpRsqekxymwI9PJQoQm8n3lktzPQcnwiQgeud
fQu3Sk6GSWWPk2ThxeFTwIWTwgY3PtJUDJytSx98BQw00Rusg4h85M8dHVyrdf2E
7j/mm3zS4gMwXDC6agDudBHQCGUqTD1KyQIjMmErArCyxBjt+ai80bR84R3/69Ic
rs6xhb6DAgMBAAECggEAPBcja2kxcCZWNNKo4DiwYMmHwtPE1SlEazAlmWSKzP+b
BZbGt/sdj1VzURYuSnTUqqMTPBm41yYCj57PMix5K42v6sKfoIB3lqw94/MZxiLn
0IFvVErzJhP2NqQWPqSI++rFcFwbHMTkFuAN1tVIs73dn9M1NaNxsvKvRyCIM/wz
5YQSDyTkdW4jQM2RvUFOoqwmeyAlQoBRMgQ4bHfLHxmPEjFgw1MAmmG8bJdkupin
MVzhZyKj4Fh80Xa2MU4KokijjG41hmYbg/sjNHaHJFDA92Rwq13dhWytrauJDxa/
3yj8pHWc23Y3hXvRAf/cibDVzXmmLj49W1i06KuUCQKBgQDj5yF/DJV0IOkhfbol
+f5AGH4ZrEXA/JwA5SxHU+aKhUuPEqK/LeUWqiy3szFjOz2JOnCC0LMN42nsmMyK
sdQEKHp2SPd2wCxsAKZAuxrEi6yBt1mEPFFU5yzvZbdMqYChKJjm9fbRHtuc63s8
PyVw67Ii9o4ij+PxfTobIs18xwKBgQDKE59w3uUDt2uoqNC8x4m5onL2p2vtcTHC
CxU57mu1+9CRM8N2BEp2VI5JaXjqt6W4u9ISrmOqmsPgTwosAquKpA/nu3bVvR9g
WlN9dh2Xgza0/AFaA9CB++ier8RJq5xFlcasMUmgkhYt3zgKNgRDfjfREWM0yamm
P++hAYRcZQKBgHEuYQk6k6J3ka/rQ54GmEj2oPFZB88+5K7hIWtO9IhIiGzGYYK2
ZTYrT0fvuxA/5GCZYDTnNnUoQnuYqsQaamOiQqcpt5QG/kiozegJw9JmV0aYauFs
HyweHsfJaQ2uhE4E3mKdNnVGcORuYeZaqdp5gx8v+QibEyXj/g5p60kTAoGBALKp
TMOHXmW9yqKwtvThWoRU+13WQlcJSFvuXpL8mCCrBgkLAhqaypb6RV7ksLKdMhk1
fhNkOdxBv0LXvv+QUMhgK2vP084/yrjuw3hecOVfboPvduZ2DuiNp2p9rocQAjeH
p8LgRN+Bqbhe7fYhMf3WX1UqEVM/pQ3G43+vjq39AoGAOyD2/hFSIx6BMddUNTHG
BEsMUc/DHYslZebbF1zAWnkKdTt+URhtHAFB2tYRDgkZfwW+wr/w12dJTIkX965o
HO7tI4FgpU9b0i8FTuwYkBfjwp2j0Xd2/VBR8Qpd17qKl3I6NXDsf3ykjGZAvldH
Tll+qwEZpXSRa5OWWTpGV8I=
-----END PRIVATE KEY-----`
