package snowflake

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/database/dbplugin/v5"
	dbtesting "github.com/hashicorp/vault/sdk/database/dbplugin/v5/testing"
	"github.com/snowflakedb/gosnowflake"
	_ "github.com/snowflakedb/gosnowflake"
)

const (
	envVarSnowflakeAccount  = "SNOWFLAKE_ACCOUNT"
	envVarSnowflakeUser     = "SNOWFLAKE_USER"
	envVarSnowflakePassword = "SNOWFLAKE_PASSWORD"
	envVarSnowflakeDatabase = "SNOWFLAKE_DATABASE"
	envVarSnowflakeSchema   = "SNOWFLAKE_SCHEMA"

	envVarRunAccTests = "VAULT_ACC"
)

var runAcceptanceTests = os.Getenv(envVarRunAccTests) != ""

func connectToInstance(t *testing.T) string {
	connURL, err := getDsnString()
	if err != nil {
		t.Fatalf("failed to retrieve connection DSN: %s", err)
	}

	return connURL
}

func TestSnowflakeSQL_Initialize(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	db := new()
	defer dbtesting.AssertClose(t, db)

	connURL, err := getDsnString()
	if err != nil {
		t.Fatalf("failed to retrieve connection DSN: %s", err)
	}

	expectedConfig := map[string]interface{}{
		"connection_url": connURL,
	}
	req := dbplugin.InitializeRequest{
		Config: map[string]interface{}{
			"connection_url": connURL,
		},
		VerifyConnection: true,
	}
	resp := dbtesting.AssertInitialize(t, db, req)
	if !reflect.DeepEqual(resp.Config, expectedConfig) {
		t.Fatalf("Actual: %#v\nExpected: %#v", resp.Config, expectedConfig)
	}

	connProducer := db.SQLConnectionProducer
	if !connProducer.Initialized {
		t.Fatal("Database should be initialized")
	}
}

func TestSnowflake_NewUser(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	type testCase struct {
		creationStmts []string
		expectErr     bool
	}

	tests := map[string]testCase{
		"name creation": {
			creationStmts: []string{`
				CREATE USER {{name}} PASSWORD = '{{password}}' DEFAULT_ROLE = myrole;
				GRANT ROLE myrole TO USER {{name}};`,
			},
			expectErr: false,
		},
		"username creation": {
			creationStmts: []string{`
				CREATE USER {{username}} PASSWORD = '{{password}}';
				GRANT ROLE myrole TO USER {{username}};`,
			},
			expectErr: false,
		},
		"empty creation": {
			creationStmts: []string{},
			expectErr:     true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			connURL := connectToInstance(t)

			db := new()
			defer dbtesting.AssertClose(t, db)

			initReq := dbplugin.InitializeRequest{
				Config: map[string]interface{}{
					"connection_url": connURL,
				},
				VerifyConnection: true,
			}
			dbtesting.AssertInitialize(t, db, initReq)

			password := "y8fva_sdVA3rasf"

			createReq := dbplugin.NewUserRequest{
				UsernameConfig: dbplugin.UsernameMetadata{
					DisplayName: "test",
					RoleName:    "test",
				},
				Statements: dbplugin.Statements{
					Commands: test.creationStmts,
				},
				Password:   password,
				Expiration: time.Time{},
			}

			ctx, cancel := context.WithTimeout(context.Background(), getRequestTimeout(t))
			defer cancel()

			createResp, err := db.NewUser(ctx, createReq)
			if test.expectErr && err == nil {
				t.Fatalf("err expected, got nil")
			}
			if !test.expectErr && err != nil {
				t.Fatalf("no error expected, got: %s", err)
			}

			err = testCredentialsExist(connURL, createResp.Username, password)
			attemptDropUser(connURL, createResp.Username)

			if test.expectErr && err == nil {
				t.Fatalf("err expected, got nil")
			}
			if !test.expectErr && err != nil {
				t.Fatalf("no error expected, got: %s", err)
			}
		})
	}
}

func TestSnowflake_RenewUser(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	connURL := connectToInstance(t)

	db := new()
	defer dbtesting.AssertClose(t, db)

	initReq := dbplugin.InitializeRequest{
		Config: map[string]interface{}{
			"connection_url": connURL,
		},
		VerifyConnection: true,
	}
	dbtesting.AssertInitialize(t, db, initReq)

	password := "y8fva_sdVA3rasf"

	createReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "test",
			RoleName:    "test",
		},
		Statements: dbplugin.Statements{
			Commands: []string{`
				CREATE USER {{name}} PASSWORD = '{{password}}';
				GRANT ROLE myrole TO USER {{name}};`,
			},
		},
		Password:   password,
		Expiration: time.Now().Add(2 * time.Second),
	}

	createResp := dbtesting.AssertNewUser(t, db, createReq)

	assertCredentialsExist(t, connURL, createResp.Username, password)

	renewReq := dbplugin.UpdateUserRequest{
		Username: createResp.Username,
		Expiration: &dbplugin.ChangeExpiration{
			NewExpiration: time.Now().Add(time.Minute),
		},
	}

	dbtesting.AssertUpdateUser(t, db, renewReq)

	// Sleep longer than the initial expiration time
	time.Sleep(2 * time.Second)

	assertCredentialsExist(t, connURL, createResp.Username, password)
	attemptDropUser(connURL, createResp.Username)
}

func TestSnowflake_RevokeUser(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	connURL := connectToInstance(t)

	type testCase struct {
		deleteStatements []string
	}

	tests := map[string]testCase{
		"name revoke": {
			deleteStatements: []string{`
				DROP USER {{name}};`,
			},
		},
		"username revoke": {
			deleteStatements: []string{`
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
				},
				VerifyConnection: true,
			}
			dbtesting.AssertInitialize(t, db, initReq)

			password := "y8fva_sdVA3rasf"

			createReq := dbplugin.NewUserRequest{
				UsernameConfig: dbplugin.UsernameMetadata{
					DisplayName: "test",
					RoleName:    "test",
				},
				Statements: dbplugin.Statements{
					Commands: []string{`
						CREATE USER {{name}} PASSWORD = '{{password}}';
						GRANT ROLE myrole TO USER {{name}};`,
					},
				},
				Password:   password,
				Expiration: time.Now().Add(2 * time.Second),
			}

			createResp := dbtesting.AssertNewUser(t, db, createReq)

			assertCredentialsExist(t, connURL, createResp.Username, password)

			deleteReq := dbplugin.DeleteUserRequest{
				Username: createResp.Username,
				Statements: dbplugin.Statements{
					Commands: test.deleteStatements,
				},
			}
			dbtesting.AssertDeleteUser(t, db, deleteReq)
			assertCredentialsDoNotExist(t, connURL, createResp.Username, password)
		})
	}
}

func getDsnString() (string, error) {
	user := os.Getenv(envVarSnowflakeUser)
	password := os.Getenv(envVarSnowflakePassword)
	account := os.Getenv(envVarSnowflakeAccount)

	if user == "" || password == "" || account == "" {
		err := errors.New("critical env vars were not set. user, password, and account must all be set")
		return "", err
	}

	dsnString := fmt.Sprintf("%s:%s@%s", user, password, account)

	database := os.Getenv(envVarSnowflakeDatabase)
	schema := os.Getenv(envVarSnowflakeSchema)

	if database != "" {
		dsnString += "/" + database
		if schema != "" {
			dsnString += "/" + schema
		}
	}

	return dsnString, nil
}

func testCredentialsExist(connString, username, password string) error {
	// Log in with the new credentials
	conf, err := gosnowflake.ParseDSN(connString)
	if err != nil {
		return err
	}
	connURL := fmt.Sprintf("%s:%s@%s.%s", username, password, conf.Account, conf.Region)

	db, err := sql.Open("snowflake", connURL)
	if err != nil {
		return err
	}
	defer db.Close()
	return db.Ping()
}

func assertCredentialsExist(t *testing.T, connString, username, password string) {
	t.Helper()
	err := testCredentialsExist(connString, username, password)
	if err != nil {
		t.Fatalf("failed to login: %s", err)
	}
}

func assertCredentialsDoNotExist(t *testing.T, connString, username, password string) {
	t.Helper()
	err := testCredentialsExist(connString, username, password)
	if err == nil {
		t.Fatalf("logged in when it shouldn't have been able to")
	}
}

// Needed to not clutter the shared instance with testing artifacts
func attemptDropUser(connString, username string) {
	db, err := sql.Open("snowflake", connString)

	if err != nil {
		log.Printf("connection issue: %s", err)
	}

	defer db.Close()
	_, err = db.Exec(fmt.Sprintf("DROP USER %s", username))

	if err != nil {
		log.Printf("query issue: %s", err)
	}
}

func getRequestTimeout(t *testing.T) time.Duration {
	rawDur := os.Getenv("VAULT_TEST_DATABASE_REQUEST_TIMEOUT")
	if rawDur == "" {
		return 2 * time.Second
	}

	dur, err := time.ParseDuration(rawDur)
	if err != nil {
		t.Fatalf("Failed to parse custom request timeout %q: %s", rawDur, err)
	}
	return dur
}
