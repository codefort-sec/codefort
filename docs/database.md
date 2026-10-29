# CodeFort Database Design

## 1. Database
Use PostgreSQL as the primary relational store. Use SQLAlchemy models and Alembic migrations in the FastAPI service. Store large artifacts (full logs, archives, source snapshots) in restricted object storage where appropriate; store references and hashes in PostgreSQL.

## 2. Core Tables

### users
- `id` UUID primary key
- `github_user_id` BIGINT unique, not null
- `login` VARCHAR(100), not null
- `display_name` VARCHAR(200), nullable
- `created_at`, `updated_at` TIMESTAMPTZ
- `last_login_at` TIMESTAMPTZ

### organizations
- `id` UUID primary key
- `github_org_id` BIGINT unique, nullable for personal accounts
- `login` VARCHAR(100), not null
- `created_at` TIMESTAMPTZ

### memberships
- `id` UUID primary key
- `user_id` FK users
- `organization_id` FK organizations
- `role` ENUM: `OWNER`, `ADMIN`, `MEMBER`, `VIEWER`
- unique (`user_id`, `organization_id`)

### repositories
- `id` UUID primary key
- `github_repo_id` BIGINT unique, not null
- `organization_id` FK organizations, nullable
- `owner_login`, `name`, `full_name`
- `is_private` BOOLEAN
- `installation_id` BIGINT nullable
- `is_connected` BOOLEAN default false
- `policy_json` JSONB
- `created_at`, `updated_at` TIMESTAMPTZ

### pull_requests
- `id` UUID primary key
- `repository_id` FK repositories
- `github_pr_number` INTEGER
- `title` TEXT
- `author_login` VARCHAR(100)
- `head_sha`, `base_sha` VARCHAR(64)
- `state` VARCHAR(20)
- `html_url` TEXT
- `created_at`, `updated_at` TIMESTAMPTZ
- unique (`repository_id`, `github_pr_number`)

### scans
- `id` UUID primary key
- `repository_id` FK repositories
- `pull_request_id` FK pull_requests
- `head_sha` VARCHAR(64), not null
- `status` ENUM: `QUEUED`, `RUNNING`, `COMPLETED`, `FAILED`, `CANCELLED`
- `verdict` ENUM: `PASS`, `REVIEW_REQUIRED`, `BLOCKED`, `SCAN_PENDING`, `SCAN_ERROR`
- `risk_score` SMALLINT constrained 0–100, nullable until completed
- `scoring_version` VARCHAR(40)
- `coverage_json` JSONB
- `summary_json` JSONB
- `started_at`, `completed_at`, `created_at` TIMESTAMPTZ
- index (`repository_id`, `created_at` DESC), index (`pull_request_id`, `created_at` DESC)

### findings
- `id` UUID primary key
- `scan_id` FK scans
- `rule_id` VARCHAR(120)
- `title` VARCHAR(300)
- `description` TEXT
- `severity` ENUM: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- `confidence` NUMERIC(4,3) constrained 0–1, nullable
- `file_path` TEXT nullable
- `line_start`, `line_end` INTEGER nullable
- `evidence_id` UUID nullable FK evidence
- `recommendation` TEXT
- `fingerprint` VARCHAR(128) for deduplication
- `created_at` TIMESTAMPTZ
- index (`scan_id`, `severity`), index (`fingerprint`)

### evidence
- `id` UUID primary key
- `scan_id` FK scans
- `kind` VARCHAR(40): `STATIC`, `DEPENDENCY`, `WORKFLOW`, `SANDBOX`, `MODEL`
- `source` VARCHAR(200)
- `summary` TEXT
- `details_redacted` JSONB
- `artifact_uri` TEXT nullable
- `sha256` VARCHAR(64) nullable
- `created_at` TIMESTAMPTZ

### telemetry_events
- `id` UUID primary key
- `scan_id` FK scans
- `event_type` VARCHAR(40): `PROCESS`, `NETWORK`, `FILE`, `SYSCALL`
- `occurred_at` TIMESTAMPTZ
- `process_id`, `parent_process_id` INTEGER nullable
- `destination_host` TEXT nullable
- `destination_port` INTEGER nullable
- `file_path_redacted` TEXT nullable
- `details_redacted` JSONB
- index (`scan_id`, `occurred_at`)

### patches
- `id` UUID primary key
- `scan_id` FK scans
- `status` ENUM: `DRAFT`, `VALIDATING`, `READY`, `REJECTED`, `APPLIED`
- `diff_text` TEXT
- `validation_json` JSONB
- `created_by` FK users
- `applied_at` TIMESTAMPTZ nullable
- `created_at` TIMESTAMPTZ

### incidents
- `id` UUID primary key
- `repository_id` FK repositories
- `scan_id` FK scans nullable
- `status` VARCHAR(30)
- `title` VARCHAR(300)
- `opened_at`, `closed_at` TIMESTAMPTZ
- `resolution` TEXT nullable

### audit_events
- `id` UUID primary key
- `actor_user_id` FK users nullable
- `organization_id` FK organizations nullable
- `action` VARCHAR(120)
- `resource_type` VARCHAR(80)
- `resource_id` UUID nullable
- `request_id` VARCHAR(100)
- `metadata_redacted` JSONB
- `created_at` TIMESTAMPTZ

### webhook_deliveries
- `id` UUID primary key
- `github_delivery_id` VARCHAR(200) unique
- `event_name` VARCHAR(100)
- `status` VARCHAR(30)
- `received_at`, `processed_at` TIMESTAMPTZ
- `error_code` VARCHAR(100) nullable

### extension_credentials
- `id` UUID primary key
- `user_id` FK users
- `token_hash` VARCHAR(128) unique
- `scopes` TEXT[]
- `expires_at`, `revoked_at`, `created_at` TIMESTAMPTZ

## 3. Relationships
- Organization has many memberships and repositories.
- Repository has many pull requests, scans, and incidents.
- Pull request has many scans; each scan belongs to one repository and PR.
- Scan has many findings, evidence items, telemetry events, and patches.
- Audit events reference the actor and affected resource when known.

## 4. Integrity and Security
- Use foreign keys and appropriate cascade rules; prefer soft deletion or explicit retention workflows for audit-critical records.
- Enforce `risk_score BETWEEN 0 AND 100` and valid line ranges.
- Enforce tenant authorization in application queries; consider PostgreSQL row-level security for multi-tenant deployments.
- Never store raw access tokens or unredacted secrets in ordinary tables.
- Use migrations for every schema change; test upgrade and rollback paths.
- Add retention indexes and scheduled cleanup jobs for eligible artifacts.

## 5. MVP Tables
For an initial prototype, start with `users`, `repositories`, `pull_requests`, `scans`, `findings`, and `audit_events`. Add telemetry, patches, organizations, and extension credentials as the related features are implemented.
