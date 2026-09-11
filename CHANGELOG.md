## v0.17.0
### September 11, 2026

* [VAULT-50062] Prepare v0.17.0 Release (#190)
* test: use RSA in Snowflake acceptance tests (#192)
* Upgrading version for crypto as part of security vulnerability (#187)
* go: resolve GHSA-wf45-q9ch-q8gh by upgrading github.com/apache/thrift to v0.23.0 (#181)

## v0.16.0
### March 17, 2026

IMPROVEMENTS:
* Updated dependencies:
   * go 1.25.0 => 1.26.1
   * google.golang.org/genproto/googleapis/rpc v0.0.0-20250425173222-7b384671a197 => v0.0.0-20251202230838-ff82c1b0f217
   * golang.org/x/sync v0.16.0 => v0.19.0
   * github.com/hashicorp/vault/sdk v0.19.0 => v0.24.0
   * github.com/snowflakedb/gosnowflake v1.17.0 => v1.19.0
   * golang.org/x/mod v0.27.0 => v0.30.0
   * golang.org/x/text v0.28.0 => v0.32.0
   * golang.org/x/oauth2 v0.30.0 => v0.34.0
   * golang.org/x/term v0.34.0 => v0.38.0
   * golang.org/x/sys v0.35.0 => v0.40.0
   * golang.org/x/tools v0.36.0 => v0.39.0
   * golang.org/x/crypto v0.41.0 => v0.46.0
   * golang.org/x/net v0.43.0 => v0.48.0
   * cloud.google.com/go/compute/metadata v0.6.0 => v0.9.0
   * go.opentelemetry.io/auto/sdk v1.1.0 => v1.2.1
   * google.golang.org/protobuf v1.36.6 => v1.36.11
   * go.opentelemetry.io/otel v1.37.0 => v1.40.0
   * go.opentelemetry.io/otel/metric v1.37.0 => v1.40.0
   * go.opentelemetry.io/otel/trace v1.37.0 => v1.40.0
   * github.com/dvsekhvalnov/jose2go v1.6.0 => v1.7.0
   * google.golang.org/grpc v1.73.0 => v1.79.3

## v0.15.0
### October 3, 2025

* Automated dependency upgrades (#125)
* Update changelog for v0.14.2 release (#157)
* Update dependencies (#148)
* Refresh the connection when necessary (#134)
* Enable query parameters parsing in connection URL for keypair auth (#135)
* init changie (#131)
* Add backport assistant workflow (#130)
* Add backport assistant workflow (#128)
* [Compliance] - PR Template Changes Required (#126)
* Update CHANGELOG.md (#127)
* Update CHANGELOG for 0.14.1 (#123)
* escape dot in regex and add test to fix secvuln (#122)
* Automated dependency upgrades (#115)
* Add support for keypair root configuration (#109)

## v0.14.2
### September 17, 2025

* release/vault-1.20.x: Update dependencies (#153)
* Backport of Refresh the connection when necessary into release/vault-1.20.x (#147)
* Backport Enable query parameters parsing in connection URL for keypair auth into `release/vault-1.20.x` (#137)

## 0.14.1
### June 5, 2025

IMPROVEMENTS:

* Added key-pair auth support for database configuration in Vault 1.20.x (https://github.com/hashicorp/vault-plugin-database-snowflake/pull/116)

## 0.14.0
### May 23, 2025

IMPROVEMENTS:

* Updated dependencies (https://github.com/hashicorp/vault-plugin-database-snowflake/pull/105)

## 0.13.2
### June 5, 2025

IMPROVEMENTS:

* Added key-pair auth support for database configuration in Vault 1.19.6 (https://github.com/hashicorp/vault-plugin-database-snowflake/pull/117)

## 0.13.0
### Feb 11, 2025

IMPROVEMENTS:

* Updated dependencies (https://github.com/hashicorp/vault-plugin-database-snowflake/pull/100)

## 0.12.2
### June 5, 2025

IMPROVEMENTS:

* Added key-pair auth support for database configuration in Vault 1.18.11 Enterprise (https://github.com/hashicorp/vault-plugin-database-snowflake/pull/118)

## 0.12.0
### Sept 4, 2024

IMPROVEMENTS:
* Updated dependencies (https://github.com/hashicorp/vault-plugin-database-snowflake/pull/92)

## 0.11.2
### June 5, 2025

IMPROVEMENTS:

* Added key-pair auth support for database configuration in Vault 1.17.18 Enterprise (https://github.com/hashicorp/vault-plugin-database-snowflake/pull/119)

## 0.11.0
### May 20, 2024

IMPROVEMENTS:
* Updated dependencies (https://github.com/hashicorp/vault-plugin-database-snowflake/pull/90)
* Updated dependencies [GH-82](https://github.com/hashicorp/vault-plugin-database-snowflake/pull/82):
  * `github.com/hashicorp/vault/sdk` v0.10.2 -> v0.11.0
  * `github.com/jackc/pgx/v4` v4.18.1 -> v4.18.2
  * `github.com/snowflakedb/gosnowflake` v1.7.2 -> v1.8.0

## 0.10.3
### June 5, 2025

IMPROVEMENTS:

* Added key-pair auth support for database configuration in Vault 1.16.22 Enterprise (https://github.com/hashicorp/vault-plugin-database-snowflake/pull/120)

## 0.10.0
### Jan 31, 2024
CHANGES:
* bump go.mod go version from 1.20 to 1.21 [GH-80](https://github.com/hashicorp/vault-plugin-database-snowflake/pull/80)

## 0.9.2
### Jan 24, 2024
CHANGES:
* downgrade go.mod go version from 1.21 to 1.20 [GH-78](https://github.com/hashicorp/vault-plugin-database-snowflake/pull/78)

## 0.9.1
### Jan 23, 2024
IMPROVEMENTS:
* Updated dependencies:
  * github.com/hashicorp/vault/sdk v0.9.2 -> v0.10.2
  * github.com/snowflakedb/gosnowflake v1.6.24 -> v1.7.2

## 0.9.0
### August 22, 2023

IMPROVEMENTS:
* Updated dependencies [GH-68](https://github.com/hashicorp/vault-plugin-database-snowflake/pull/68)::
   * `github.com/snowflakedb/gosnowflake` v1.6.23 -> v1.6.24
* Updated dependencies [GH-67](https://github.com/hashicorp/vault-plugin-database-snowflake/pull/67)::
   * `github.com/hashicorp/vault/sdk` v0.9.0 -> v0.9.2
   * `github.com/snowflakedb/gosnowflake` v1.6.18 -> v1.6.23
   * `github.com/stretchr/testify` v1.8.2 -> v1.8.4
