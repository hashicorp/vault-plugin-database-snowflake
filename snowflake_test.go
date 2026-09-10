// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package snowflake

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/sdk/database/dbplugin/v5"
	dbtesting "github.com/hashicorp/vault/sdk/database/dbplugin/v5/testing"
	"github.com/snowflakedb/gosnowflake"
	"github.com/stretchr/testify/require"
)

const (
	envVarSnowflakeAccount    = "SNOWFLAKE_ACCOUNT"
	envVarSnowflakeUser       = "SNOWFLAKE_USER"
	envVarSnowflakeDatabase   = "SNOWFLAKE_DATABASE"
	envVarSnowflakeSchema     = "SNOWFLAKE_SCHEMA"
	envVarSnowflakePrivateKey = "SNOWFLAKE_PRIVATE_KEY"

	envVarRunAccTests = "VAULT_ACC"

	// Acceptance tests use service users because password-only sign-ins require MFA.
	defaultRSAKeyCreationStmts = `
CREATE USER {{username}} TYPE=SERVICE RSA_PUBLIC_KEY='{{public_key}}';
GRANT ROLE public TO USER {{username}};
GRANT USAGE ON DATABASE %s TO USER {{username}};`

	defaultUsageCreationStmt = "GRANT USAGE ON DATABASE %s TO USER {{username}};"
)

var runAcceptanceTests = os.Getenv(envVarRunAccTests) != ""

func connDetails(t *testing.T) (string, []byte, string) {
	connURL, rawBase64PrivateKey, user, err := getKeyPairAuthParameters("")
	if err != nil {
		t.Fatalf("failed to retrieve connection URL: %s", err)
	}

	// decode base64 encoded private key from environment
	privateKey, err := base64.StdEncoding.DecodeString(rawBase64PrivateKey)
	if err != nil {
		t.Fatalf("failed to decode private key: %s", err)
	}

	return connURL, privateKey, user
}

// TestSnowflakeSQL_Initialize verifies key-pair authentication with and without
// connection URL parameters.
func TestSnowflakeSQL_Initialize(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	// the environment variable SNOWFLAKE_PRIVATE_KEY in CI
	// is a base64 encoded string. As such, this test expects the
	// input for the variable to be base64 encoded
	t.Run("keypair auth with raw private key", func(t *testing.T) {
		db := new()
		defer dbtesting.AssertClose(t, db)

		connURL, privateKey, user := connDetails(t)

		expectedConfig := map[string]interface{}{
			"connection_url": connURL,
			"username":       user,
			"private_key":    privateKey,
			dbplugin.SupportedCredentialTypesKey: []interface{}{
				dbplugin.CredentialTypePassword.String(),
				dbplugin.CredentialTypeRSAPrivateKey.String(),
			},
		}
		req := dbplugin.InitializeRequest{
			Config: map[string]interface{}{
				"connection_url": connURL,
				"username":       user,
				"private_key":    privateKey,
			},
			VerifyConnection: true,
		}
		resp := dbtesting.AssertInitialize(t, db, req)
		if !reflect.DeepEqual(resp.Config, expectedConfig) {
			t.Fatalf("Actual: %#v\nExpected: %#v", resp.Config, expectedConfig)
		}

		connProducer := db.snowflakeConnectionProducer
		if !connProducer.Initialized {
			t.Fatal("Database should be initialized")
		}
	})

	// the environment variable SNOWFLAKE_PRIVATE_KEY in CI
	// is a base64 encoded string. As such, this test expects the
	// input for the variable to be base64 encoded
	t.Run("keypair auth with query params", func(t *testing.T) {
		db := new()
		defer dbtesting.AssertClose(t, db)

		connURL, rawBase64PrivateKey, user, err := getKeyPairAuthParameters("disableOCSPChecks=true&maxRetryCount=5")
		if err != nil {
			t.Fatalf("failed to retrieve connection URL: %s", err)
		}

		// decode base64 encoded private key from environment
		privateKey, err := base64.StdEncoding.DecodeString(rawBase64PrivateKey)
		if err != nil {
			t.Fatalf("failed to decode private key: %s", err)
		}

		expectedConfig := map[string]interface{}{
			"connection_url": connURL,
			"username":       user,
			"private_key":    privateKey,
			dbplugin.SupportedCredentialTypesKey: []interface{}{
				dbplugin.CredentialTypePassword.String(),
				dbplugin.CredentialTypeRSAPrivateKey.String(),
			},
		}
		req := dbplugin.InitializeRequest{
			Config: map[string]interface{}{
				"connection_url": connURL,
				"username":       user,
				"private_key":    privateKey,
			},
			VerifyConnection: true,
		}
		resp := dbtesting.AssertInitialize(t, db, req)
		if !reflect.DeepEqual(resp.Config, expectedConfig) {
			t.Fatalf("Actual: %#v\nExpected: %#v", resp.Config, expectedConfig)
		}

		connProducer := db.snowflakeConnectionProducer
		if !connProducer.Initialized {
			t.Fatal("Database should be initialized")
		}
	})
}

func TestSnowflake_NewUser(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	dbName := getTestDatabase(t)

	type testCase struct {
		creationStmts []string
		keyBits       int
		expectErr     bool
	}

	tests := map[string]testCase{
		"new user with empty creation statements": {
			creationStmts: []string{},
			keyBits:       2048,
			expectErr:     true,
		},
		"new user with 2048 bit rsa_private_key credential using name": {
			creationStmts: []string{
				fmt.Sprintf(`
CREATE USER {{name}} TYPE=SERVICE RSA_PUBLIC_KEY='{{public_key}}';
GRANT ROLE public TO USER {{name}};
GRANT USAGE ON DATABASE %s TO USER {{name}};`, dbName),
			},
			keyBits: 2048,
		},
		"new user with 3072 bit rsa_private_key credential": {
			creationStmts: []string{
				fmt.Sprintf(defaultRSAKeyCreationStmts, dbName),
			},
			keyBits: 3072,
		},
		"new user with 4096 bit rsa_private_key credential and split statements": {
			creationStmts: []string{
				"CREATE USER {{username}} TYPE=SERVICE RSA_PUBLIC_KEY='{{public_key}}';",
				"GRANT ROLE public TO USER {{username}};",
				fmt.Sprintf(defaultUsageCreationStmt, dbName),
			},
			keyBits: 4096,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			connURL, privateKey, user := connDetails(t)

			db := new()
			defer dbtesting.AssertClose(t, db)

			initReq := dbplugin.InitializeRequest{
				Config: map[string]interface{}{
					"connection_url": connURL,
					"username":       user,
					"private_key":    privateKey,
				},
				VerifyConnection: true,
			}
			dbtesting.AssertInitialize(t, db, initReq)

			pub, priv := testGenerateRSAKeyPair(t, test.keyBits)
			createReq := dbplugin.NewUserRequest{
				UsernameConfig: dbplugin.UsernameMetadata{
					DisplayName: "test",
					RoleName:    "test",
				},
				Statements: dbplugin.Statements{
					Commands: test.creationStmts,
				},
				CredentialType: dbplugin.CredentialTypeRSAPrivateKey,
				PublicKey:      pub,
				Expiration:     time.Now().Add(time.Hour),
			}

			ctx, cancel := context.WithTimeout(context.Background(), getRequestTimeout(t))
			defer cancel()

			createResp, err := db.NewUser(ctx, createReq)
			if test.expectErr {
				require.Error(t, err, "empty creation statements must be rejected")
				return
			}
			require.NoError(t, err, "failed to create user")
			defer attemptDropUser(connURL, user, createResp.Username, privateKey)
			assertRSAKeyPairCredentialsExist(t, connURL, createResp.Username, priv)
		})
	}
}

func TestSnowflake_RenewUser(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	connURL, privateKey, user := connDetails(t)
	dbName := getTestDatabase(t)

	db := new()
	defer dbtesting.AssertClose(t, db)

	initReq := dbplugin.InitializeRequest{
		Config: map[string]interface{}{
			"connection_url": connURL,
			"username":       user,
			"private_key":    privateKey,
		},
		VerifyConnection: true,
	}
	dbtesting.AssertInitialize(t, db, initReq)

	pub, priv := testGenerateRSAKeyPair(t, 2048)

	createReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "test",
			RoleName:    "test",
		},
		Statements: dbplugin.Statements{
			Commands: []string{
				fmt.Sprintf(defaultRSAKeyCreationStmts, dbName),
			},
		},
		CredentialType: dbplugin.CredentialTypeRSAPrivateKey,
		PublicKey:      pub,
		Expiration:     time.Now().Add(time.Hour),
	}

	createResp := dbtesting.AssertNewUser(t, db, createReq)
	defer attemptDropUser(connURL, user, createResp.Username, privateKey)

	assertRSAKeyPairCredentialsExist(t, connURL, createResp.Username, priv)

	renewReq := dbplugin.UpdateUserRequest{
		Username: createResp.Username,
		Expiration: &dbplugin.ChangeExpiration{
			NewExpiration: time.Now().Add(time.Minute),
		},
	}

	dbtesting.AssertUpdateUser(t, db, renewReq)

	assertRSAKeyPairCredentialsExist(t, connURL, createResp.Username, priv)
}

func TestSnowflake_RevokeUser(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	connURL, privateKey, user := connDetails(t)
	dbName := getTestDatabase(t)

	type testCase struct {
		deleteStatements []string
	}

	tests := map[string]testCase{
		"name revoke": {
			deleteStatements: []string{
				`
				DROP USER {{name}};`,
			},
		},
		"username revoke": {
			deleteStatements: []string{
				`
				DROP USER {{username}};`,
			},
		},
		"default revoke": {},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			db := new()
			defer dbtesting.AssertClose(t, db)

			initReq := dbplugin.InitializeRequest{
				Config: map[string]interface{}{
					"connection_url": connURL,
					"username":       user,
					"private_key":    privateKey,
				},
				VerifyConnection: true,
			}
			dbtesting.AssertInitialize(t, db, initReq)

			pub, priv := testGenerateRSAKeyPair(t, 2048)

			createReq := dbplugin.NewUserRequest{
				UsernameConfig: dbplugin.UsernameMetadata{
					DisplayName: "test",
					RoleName:    "test",
				},
				Statements: dbplugin.Statements{
					Commands: []string{
						fmt.Sprintf(defaultRSAKeyCreationStmts, dbName),
					},
				},
				CredentialType: dbplugin.CredentialTypeRSAPrivateKey,
				PublicKey:      pub,
				Expiration:     time.Now().Add(time.Hour),
			}

			createResp := dbtesting.AssertNewUser(t, db, createReq)
			t.Cleanup(func() {
				attemptDropUser(connURL, user, createResp.Username, privateKey)
			})

			assertRSAKeyPairCredentialsExist(t, connURL, createResp.Username, priv)

			deleteReq := dbplugin.DeleteUserRequest{
				Username: createResp.Username,
				Statements: dbplugin.Statements{
					Commands: test.deleteStatements,
				},
			}
			dbtesting.AssertDeleteUser(t, db, deleteReq)
			assertRSAKeyPairCredentialsDoNotExist(t, connURL, createResp.Username, priv)
		})
	}
}

func TestSnowflake_DefaultUsernameTemplate(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	connURL, privateKey, user := connDetails(t)
	dbName := getTestDatabase(t)

	db := new()
	defer dbtesting.AssertClose(t, db)

	initReq := dbplugin.InitializeRequest{
		Config: map[string]interface{}{
			"connection_url": connURL,
			"username":       user,
			"private_key":    privateKey,
		},
		VerifyConnection: true,
	}
	dbtesting.AssertInitialize(t, db, initReq)

	pub, priv := testGenerateRSAKeyPair(t, 2048)
	createReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "test",
			RoleName:    "test",
		},
		Statements: dbplugin.Statements{
			Commands: []string{
				fmt.Sprintf(defaultRSAKeyCreationStmts, dbName),
			},
		},
		CredentialType: dbplugin.CredentialTypeRSAPrivateKey,
		PublicKey:      pub,
		Expiration:     time.Now().Add(time.Hour),
	}
	createResp := dbtesting.AssertNewUser(t, db, createReq)
	defer attemptDropUser(connURL, user, createResp.Username, privateKey)

	if createResp.Username == "" {
		t.Fatalf("Missing username")
	}

	assertRSAKeyPairCredentialsExist(t, connURL, createResp.Username, priv)

	require.Regexp(t, `^v_test_test_[a-zA-Z0-9]{20}_[0-9]{10}$`, createResp.Username)
}

func TestSnowflake_CustomUsernameTemplate(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	connURL, privateKey, user := connDetails(t)
	dbName := getTestDatabase(t)

	db := new()
	defer dbtesting.AssertClose(t, db)

	initReq := dbplugin.InitializeRequest{
		Config: map[string]interface{}{
			"connection_url":    connURL,
			"username":          user,
			"private_key":       privateKey,
			"username_template": "{{.DisplayName}}_{{random 10}}",
		},
		VerifyConnection: true,
	}
	dbtesting.AssertInitialize(t, db, initReq)

	pub, priv := testGenerateRSAKeyPair(t, 2048)
	createReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "test",
			RoleName:    "test",
		},
		Statements: dbplugin.Statements{
			Commands: []string{
				fmt.Sprintf(defaultRSAKeyCreationStmts, dbName),
			},
		},
		CredentialType: dbplugin.CredentialTypeRSAPrivateKey,
		PublicKey:      pub,
		Expiration:     time.Now().Add(time.Hour),
	}
	createResp := dbtesting.AssertNewUser(t, db, createReq)
	defer attemptDropUser(connURL, user, createResp.Username, privateKey)

	if createResp.Username == "" {
		t.Fatalf("Missing username")
	}

	assertRSAKeyPairCredentialsExist(t, connURL, createResp.Username, priv)

	require.Regexp(t, `^test_[a-zA-Z0-9]{10}$`, createResp.Username)
}

func getKeyPairAuthParameters(optionalQueryParams string) (connURL string, pKey string, user string, err error) {
	user = os.Getenv(envVarSnowflakeUser)
	pKey = os.Getenv(envVarSnowflakePrivateKey)
	account := os.Getenv(envVarSnowflakeAccount)
	database := os.Getenv(envVarSnowflakeDatabase)

	if user == "" {
		err = multierror.Append(err, fmt.Errorf("SNOWFLAKE_USER not set"))
	}
	if pKey == "" {
		err = multierror.Append(err, fmt.Errorf("SNOWFLAKE_PRIVATE_KEY not set"))
	}
	if account == "" {
		err = multierror.Append(err, fmt.Errorf("SNOWFLAKE_ACCOUNT not set"))
	}

	if database == "" {
		err = multierror.Append(err, fmt.Errorf("SNOWFLAKE_DATABASE not set"))
	}

	connURL = fmt.Sprintf("%s.snowflakecomputing.com/%s", account, database)

	if optionalQueryParams != "" {
		connURL = fmt.Sprintf("%s?%s", connURL, optionalQueryParams)
	}

	return connURL, pKey, user, err
}

func verifyConnWithKeyPairCredential(connString, username string, private *rsa.PrivateKey) error {
	// empty password always fails here, so we set a placeholder so we can parse
	// this is cleared out in the config below
	url := fmt.Sprintf("%s:%s@%s", username, "empty", connString)
	conf, err := gosnowflake.ParseDSN(url)
	if err != nil {
		return err
	}

	config := &gosnowflake.Config{
		Authenticator: gosnowflake.AuthTypeJwt,
		Account:       conf.Account,
		Region:        conf.Region,
		Database:      conf.Database,
		Schema:        conf.Schema,
		User:          username,
		PrivateKey:    private,
		Password:      "",
	}
	dsn, err := gosnowflake.DSN(config)
	if err != nil {
		return err
	}

	db, err := sql.Open("snowflake", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	return db.Ping()
}

func assertRSAKeyPairCredentialsDoNotExist(t *testing.T, connString, username string, private *rsa.PrivateKey) {
	t.Helper()
	err := verifyConnWithKeyPairCredential(connString, username, private)
	require.Error(t, err, "revoked RSA credentials must not authenticate")
}

func assertRSAKeyPairCredentialsExist(t *testing.T, connString, username string, private *rsa.PrivateKey) {
	t.Helper()
	err := verifyConnWithKeyPairCredential(connString, username, private)
	if err != nil {
		t.Fatalf("failed to log in with RSA key pair credential: %s", err)
	}
}

func getTestDatabase(t *testing.T) string {
	database := os.Getenv(envVarSnowflakeDatabase)
	if database == "" {
		t.Fatalf("SNOWFLAKE_DATABASE not set")
	}

	return database
}

// Needed to not clutter the shared instance with testing artifacts
func attemptDropUser(connString, rootUser, username string, privateKey []byte) {
	db, err := openSnowflake(connString, rootUser, privateKey)
	if err != nil {
		log.Printf("connection issue: %s", err)
		return
	}

	defer db.Close()
	_, err = db.Exec(fmt.Sprintf("DROP USER IF EXISTS %s", username))
	if err != nil {
		log.Printf("query issue: %s", err)
	}
}

func getRequestTimeout(t *testing.T) time.Duration {
	rawDur := os.Getenv("VAULT_TEST_DATABASE_REQUEST_TIMEOUT")
	if rawDur == "" {
		return 1 * time.Minute
	}

	dur, err := time.ParseDuration(rawDur)
	if err != nil {
		t.Fatalf("Failed to parse custom request timeout %q: %s", rawDur, err)
	}
	return dur
}

func testGenerateRSAKeyPair(t *testing.T, bits int) ([]byte, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)
	public, err := x509.MarshalPKIXPublicKey(key.Public())
	require.NoError(t, err)
	publicBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: public,
	}
	return pem.EncodeToMemory(publicBlock), key
}
