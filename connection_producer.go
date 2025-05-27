// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package snowflake

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/vault/sdk/database/helper/dbutil"
	"net/url"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/hashicorp/vault/sdk/database/helper/connutil"
	"github.com/mitchellh/mapstructure"
	"github.com/snowflakedb/gosnowflake"
)

var (
	ErrInvalidSnowflakeURL           = fmt.Errorf("invalid connection URL format, expect <account_name>.snowflakecomputing.com/<db_name>")
	accountAndDBNameFromConnURLRegex = regexp.MustCompile(`^(.+)\.snowflakecomputing.com/(.+)$`) // Expected format: <account_name>.snowflakecomputing.com/<db_name>
)

type snowflakeConnectionProducer struct {
	ConnectionURL            string      `json:"connection_url"`
	MaxOpenConnections       int         `json:"max_open_connections"`
	MaxIdleConnections       int         `json:"max_idle_connections"`
	MaxConnectionLifetimeRaw interface{} `json:"max_connection_lifetime"`
	Username                 string      `json:"username"`
	Password                 string      `json:"password"`
	PrivateKey               string      `json:"private_key"`
	UsernameTemplate         string      `json:"username_template"`
	DisableEscaping          bool        `json:"disable_escaping"`

	Initialized           bool
	RawConfig             map[string]any
	Type                  string
	maxConnectionLifetime time.Duration
	snowflakeDB           *sql.DB
	mu                    sync.RWMutex
}

func (c *snowflakeConnectionProducer) secretValues() map[string]string {
	return map[string]string{
		c.Password:   "[password]",
		c.PrivateKey: "[private_key]",
	}
}

func (c *snowflakeConnectionProducer) Init(ctx context.Context, initConfig map[string]interface{}, verifyConnection bool) (saveConfig map[string]interface{}, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.RawConfig = initConfig

	decoderConfig := &mapstructure.DecoderConfig{
		Result:           c,
		WeaklyTypedInput: true,
		TagName:          "json",
	}

	decoder, err := mapstructure.NewDecoder(decoderConfig)
	if err != nil {
		return nil, err
	}

	err = decoder.Decode(initConfig)
	if err != nil {
		return nil, err
	}

	if len(c.ConnectionURL) == 0 {
		return nil, fmt.Errorf("connection_url cannot be empty")
	}

	if len(c.Password) > 0 {
		// Return an error here once Snowflake ends support for password auth.
		// TODO figure out how DB plugins can dispatch logs

		username := c.Username
		password := c.Password

		if !c.DisableEscaping {
			username = url.PathEscape(c.Username)
			password = url.PathEscape(c.Password)
		}

		// Replace templated username and password in connection URL with actual values
		c.ConnectionURL = dbutil.QueryHelper(c.ConnectionURL, map[string]string{
			"username": username,
			"password": password,
		})
	}

	if c.MaxOpenConnections == 0 {
		c.MaxOpenConnections = 4
	}

	if c.MaxIdleConnections == 0 {
		c.MaxIdleConnections = c.MaxOpenConnections
	}
	if c.MaxIdleConnections > c.MaxOpenConnections {
		c.MaxIdleConnections = c.MaxOpenConnections
	}
	if c.MaxConnectionLifetimeRaw == nil {
		c.MaxConnectionLifetimeRaw = "0s"
	}

	c.maxConnectionLifetime, err = parseutil.ParseDurationSecond(c.MaxConnectionLifetimeRaw)
	if err != nil {
		return nil, errwrap.Wrapf("invalid max_connection_lifetime: {{err}}", err)
	}

	c.Initialized = true

	if verifyConnection {
		if _, err := c.Connection(ctx); err != nil {
			c.close()
			return nil, fmt.Errorf("error verifying connection: %w", err)
		}
	}

	return initConfig, nil
}

func (c *snowflakeConnectionProducer) Initialize(ctx context.Context, config map[string]any, verifyConnection bool) error {
	_, err := c.Init(ctx, config, verifyConnection)
	return err
}

func (c *snowflakeConnectionProducer) Connection(ctx context.Context) (interface{}, error) {
	// This is intentionally not grabbing the lock since the calling functions (e.g. CreateUser)
	// are claiming it.

	if !c.Initialized {
		return nil, connutil.ErrNotInitialized
	}

	if c.snowflakeDB != nil {
		return c.snowflakeDB, nil
	}

	var db *sql.DB
	var err error
	if c.PrivateKey != "" {
		db, err = openSnowflake(c.ConnectionURL, c.Username, c.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("error opening Snowflake connection: %w", err)
		}
	} else {
		db, err = sql.Open(snowflakeSQLTypeName, c.ConnectionURL)
		if err != nil {
			return nil, fmt.Errorf("failed to open connection: %w", err)
		}
	}

	c.snowflakeDB = db
	c.snowflakeDB.SetMaxOpenConns(c.MaxOpenConnections)
	c.snowflakeDB.SetMaxIdleConns(c.MaxIdleConnections)
	c.snowflakeDB.SetConnMaxLifetime(c.maxConnectionLifetime)

	return c.snowflakeDB, nil
}

// close terminates the database connection without locking
func (c *snowflakeConnectionProducer) close() error {
	if c.snowflakeDB != nil {
		if err := c.snowflakeDB.Close(); err != nil {
			return err
		}
	}

	return nil
}

// Close terminates the database connection with locking
func (c *snowflakeConnectionProducer) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.snowflakeDB = nil

	return c.close()
}

// Open the DB connection to Snowflake or return an error.
func openSnowflake(connectionURL, username, providedPrivateKey string) (*sql.DB, error) {
	// Parse thee connection_url for required fields. Should be of
	// the form <account_name>.snowflakecomputing.com/<db_name>
	accountName, dbName, err := parseSnowflakeFieldsFromURL(connectionURL)
	if err != nil {
		return nil, err
	}

	privateKey, err := getPrivateKey(providedPrivateKey)
	if err != nil {
		return nil, err
	}

	snowflakeConfig := &gosnowflake.Config{
		Account:       accountName,
		Database:      dbName,
		User:          username,
		Authenticator: gosnowflake.AuthTypeJwt,
		PrivateKey:    privateKey,
	}
	connector := gosnowflake.NewConnector(gosnowflake.SnowflakeDriver{}, *snowflakeConfig)

	return sql.OpenDB(connector), nil
}

// parseSnowflakeFieldsFromURL uses a regex to extract account and DB
// info from a connectionURL
func parseSnowflakeFieldsFromURL(connectionURL string) (string, string, error) {
	if !accountAndDBNameFromConnURLRegex.MatchString(connectionURL) {
		return "", "", ErrInvalidSnowflakeURL
	}
	res := accountAndDBNameFromConnURLRegex.FindStringSubmatch(connectionURL)
	if len(res) != 3 {
		return "", "", ErrInvalidSnowflakeURL
	}

	return res[1], res[2], nil
}

// Open and decode the private key file
func getPrivateKey(providedPrivateKey string) (*rsa.PrivateKey, error) {
	var block *pem.Block

	// Try loading a file with the provided private key field first. If the the file doesn't
	// exist, assume they provided the raw key and decode it. If there was an error, then
	// assume they provided a file path to a private key.
	keyFile, err := os.ReadFile(providedPrivateKey)
	if err != nil && os.IsNotExist(err) {
		block, _ = pem.Decode([]byte(providedPrivateKey))
	} else {
		block, _ = pem.Decode(keyFile)
	}

	if block == nil {
		return nil, fmt.Errorf("failed to read provided private_key")
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("unexpected private key type, expected type 'PRIVATE KEY', got '%s'", block.Type)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key to PKCS8: %w", err)
	}

	privateKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key was parsed into an unexpected type")
	}

	return privateKey, nil
}
