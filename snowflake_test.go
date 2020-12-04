package snowflake

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"reflect"
	"testing"
	"time"

	dbplugin "github.com/hashicorp/vault/sdk/database/dbplugin/v5"
	dbtesting "github.com/hashicorp/vault/sdk/database/dbplugin/v5/testing"
	_ "github.com/snowflakedb/gosnowflake"
)

const (
	envVarSnowflakeAccount   = "SNOWFLAKE_ACCOUNT"
	envVarSnowflakeUser   	 = "SNOWFLAKE_USER"
	envVarSnowflakePassword  = "SNOWFLAKE_PASSWORD"
	envVarSnowflakeWarehouse = "SNOWFLAKE_WAREHOUSE"
	envVarSnowflakeDatabase  = "SNOWFLAKE_DATABASE"
	envVarSnowflakeSchema    = "SNOWFLAKE_SCHEMA"
	envVarSnowflakeRole      = "SNOWFLAKE_ROLE"

	envVarRunAccTests = "VAULT_ACC"
)

var runAcceptanceTests = os.Getenv(envVarRunAccTests) != ""

func TestMain(m *testing.M) {
	flag.Parse()

	controller, err := newTestController()
	if err != nil {
		log.Fatal(err)
	}

	if err := controller.Setup(); err != nil {
		log.Fatal(err)
	}

	// Run the actual tests
	code := m.Run()

	if err := controller.Teardown(); err != nil {
		log.Fatal(err)
	}

	os.Exit(code)
}

// testController takes care of performing one-time setup and teardown tasks per
// test run, such as adding the IP of the machine to Atlas' allowlist. This is
// only applicable when running acceptance tests.
type testController struct {
	dsn    string
}

func newTestController() (testController, error) {
	if !runAcceptanceTests {
		return testController{}, nil
	}

	user := os.Getenv(envVarSnowflakeUser)
	password := os.Getenv(envVarSnowflakePassword)
	account := os.Getenv(envVarSnowflakeAccount)
	database := os.Getenv(envVarSnowflakeDatabase)
	schema := os.Getenv(envVarSnowflakeSchema)

	if user == "" || account == "" {
		return testController{}, fmt.Errorf("username and account must be provided")
	}

	dsnString := user
	if password != "" {
		dsnString += ":" + password
	}
	dsnString += "@" + account
	if database != "" {
		dsnString += "/" + database
		if schema != "" {
			dsnString += "/" + schema
		}
	}

	controller := testController{
		dsn:    dsnString,
	}

	return controller, nil
}

func (c testController) Teardown() error {
	if !runAcceptanceTests {
		return nil
	}

	_, err := c.client.ProjectIPWhitelist.Delete(context.Background(), c.projectID, c.ip)
	return err
}