# vault-plugin-database-snowflake

A Vault plugin for Snowflake. It is one of the supported plugins for the HashiCorp 
Vault Database Secrets Engine and allows for the programmatic generation of unique, 
ephemeral Snowflake [Database User](https://docs.snowflake.com/en/user-guide/admin-user-management.html) 
credentials in a Snowflake account.

This project uses the database plugin interface introduced in Vault version 1.6.0.

**This plugin is included in Vault version 1.7+.**

## Bugs and Feature Requests

Bugs should be filed under the Issues section of this repo.

Feature requests can be submitted in the Issues section as well.

## Quick Links

 * [Database Secrets Engine for Snowflake - Docs](https://developer.hashicorp.com/vault/docs/secrets/databases/snowflake)
 * [Database Secrets Engine for Snowflake - API Docs](https://developer.hashicorp.com/vault/api-docs/secret/databases/snowflake)
 * [Snowflake Website](https://www.snowflake.com/)
 * [Vault Website](https://www.vaultproject.io)
 
**Please note**: HashiCorp takes Vault's security and their users' trust very seriously.

If you believe you have found a security issue in Vault or with this plugin, _please 
responsibly disclose_ by contacting HashiCorp at [security@hashicorp.com](mailto:security@hashicorp.com).

### Configure Plugin

A [scripted configuration](bootstrap/configure.sh) of the plugin is provided in
this repository. You can use the script or manually configure the secrets engine
using documentation.

To apply the scripted configuration, run the `make configure` target to
register, enable, and configure the plugin with your local Vault instance. You
can specify the plugin name, plugin directory, mount path, connection URL and
private key path. Default values for plugin name and directory from the
Makefile will be used if arguments aren't provided.

```sh
$ PLUGIN_NAME=vault-plugin-secrets-azure \
  PLUGIN_DIR=$GOPATH/vault-plugins \
  CONNECTION_URL=foo.snowflakecomputing.com/BAR \
  PRIVATE_KEY=/path/to/private/key/file \
  make configure
```


## Acceptance Testing

In order to perform acceptance testing, you need to set the environment variable `VAULT_ACC=1` 
as well as provide all the necessary information to connect to a Snowflake Project. All 
`SNOWFLAKE_*` environment variables must be provided in order for the acceptance tests to 
run properly. A cluster must be available during the test. A [30-day trial account](https://signup.snowflake.com/) 
can be provisioned manually to test.

| Environment Variable | Description |
|----------------------|-------------|
| SNOWFLAKE_ACCOUNT    | The account string for your snowflake instance. If you are using a non-AWS provider, or a region that isn't us-west-1 for AWS, region and provider should be included here. (example: `ec#####.east-us-2.azure`) |
| SNOWFLAKE_USER       | The accountadmin level user that you are using with Vault |
| SNOWFLAKE_PASSWORD   | The password associated with the provided user |
| SNOWFLAKE_DB         | optional: The DB you are restricting the connection to |
| SNOWFLAKE_SCHEMA     | optional: The schema you are restricting the connection to |
| SNOWFLAKE_WAREHOUSE  | optional: The warehouse you are restricting the connection to |

To run the acceptance tests, invoke `make testacc`:

```sh
$ make testacc
```
