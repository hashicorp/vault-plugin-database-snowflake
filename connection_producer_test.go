// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package snowflake

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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

	db, err := openSnowflake("account.snowflakecomputing.com/db", "user", pemKey.Bytes())
	if err != nil {
		t.Fatalf("Failed to open Snowflake connection: %v", err)
	}

	require.NotNil(t, db.Stats())
}

// TestParseSnowflakeFieldsFromURL validates that URL
// parsing for keypair authentication works as expected
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

// TestGetPrivateKey ensures reading private
// keys works as expected for multiple cases
func TestGetPrivateKey(t *testing.T) {
	tests := map[string]struct {
		providedPrivateKey string
		wantErr            error
	}{
		"valid private key string": {
			providedPrivateKey: testPrivateKey,
			wantErr:            nil,
		},
		"valid private key single-line string": {
			providedPrivateKey: testSingleLinePrivateKey,
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
			_, err := getPrivateKey([]byte(tt.providedPrivateKey))

			require.Equal(t, tt.wantErr, err)
		})
	}
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

// Used in tests. Original ref in Vault:
// https://github.com/hashicorp/vault-enterprise/blob/main/builtin/logical/nomad/backend_test.go#L687
const testSingleLinePrivateKey = "-----BEGIN PRIVATE KEY-----\n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\nf6JQ3izyHmapAXkeiN1i6S0dyj7Z8oY=\n-----END PRIVATE KEY-----\n"
