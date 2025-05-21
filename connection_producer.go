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
	"os"
	"regexp"
	"sync"

	"github.com/hashicorp/vault/sdk/database/helper/connutil"
	"github.com/mitchellh/mapstructure"
	"github.com/snowflakedb/gosnowflake"
)

var (
	ErrInvalidSnowflakeURL           = fmt.Errorf("invalid connection URL format, expect <account_name>.snowflakecomputing.com/<db_name>")
	accountAndDBNameFromConnURLRegex = regexp.MustCompile(`^(.+)\.snowflakecomputing.com/(.+)$`) // Expected format: <account_name>.snowflakecomputing.com/<db_name>
)

type snowflakeConnectionProducer struct {
	ConnectionURL         string `json:"connection_url"`
	MaxOpenConnections    int    `json:"max_open_connections"`
	MaxIdleConnections    int    `json:"max_idle_connections"`
	MaxConnectionLifetime string `json:"max_connection_lifetime"`
	Username              string `json:"username"`
	Password              string `json:"password"`
	PrivateKey            string `json:"private_key"`
	UsernameTemplate      string `json:"username_template"`
	DisableEscaping       bool   `json:"disable_escaping"`

	Initialized bool
	RawConfig   map[string]any
	Type        string
	snowflakeDB *sql.DB
	sync.Mutex
}

func (c *snowflakeConnectionProducer) secretValues() map[string]string {
	return map[string]string{
		c.Password: "[password]",
	}
}

func (c *snowflakeConnectionProducer) Init(ctx context.Context, initConfig map[string]interface{}, verifyConnection bool) (saveConfig map[string]interface{}, err error) {
	c.Lock()
	defer c.Unlock()

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

	if len(c.Password) > 0 {
		// Return an error here once Snowflake ends support for password auth.
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
	// are claiming it. (The locking patterns could be refactored to be more consistent/clear.)

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

	return db, nil
}

// close terminates the database connection without locking
func (c *snowflakeConnectionProducer) close() error {
	if c.snowflakeDB != nil {
		if err := c.snowflakeDB.Close(); err != nil {
			return err
		}
	}

	c.snowflakeDB = nil
	return nil
}

// Close terminates the database connection with locking
func (c *snowflakeConnectionProducer) Close() error {
	c.Lock()
	defer c.Unlock()

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
	// exist, assume they provided the raw key and decode it. Otherwise return an error. If there
	// was no error, then they likely provided a file path to a private key.
	keyFile, err := os.ReadFile(providedPrivateKey)
	if err != nil {
		if os.IsNotExist(err) {
			block, _ = pem.Decode([]byte(providedPrivateKey))
		} else {
			return nil, fmt.Errorf("failed to read private key file: %w", err)
		}
	} else {
		block, _ = pem.Decode(keyFile)
	}

	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode the private key value")
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
