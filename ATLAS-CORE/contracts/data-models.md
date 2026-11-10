# ATLAS Data Models

Generated from the SQLAlchemy models. IDs are UUID strings. Timestamps are ISO-8601 UTC.

## audit_logs

| column | type | nullable | notes |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| timestamp | DATETIME | no |  |
| actor_id | VARCHAR(36) | yes |  |
| action | VARCHAR(100) | no |  |
| resource_type | VARCHAR(60) | no |  |
| resource_id | VARCHAR(36) | yes |  |
| assessment_id | VARCHAR(36) | yes |  |
| outcome | VARCHAR(20) | no |  |
| details | JSON | no |  |

## users

| column | type | nullable | notes |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| username | VARCHAR(100) | no |  |
| password_hash | VARCHAR(255) | no | never exposed by API |
| role | VARCHAR(20) | no |  |
| is_active | BOOLEAN | no |  |
| failed_login_count | INTEGER | no |  |
| locked_until | DATETIME | yes |  |
| last_login_at | DATETIME | yes |  |
| password_changed_at | DATETIME | yes |  |
| mfa_enabled | BOOLEAN | no |  |
| mfa_secret_encrypted | TEXT | yes |  |
| mfa_last_step | INTEGER | yes |  |
| created_at | DATETIME | no |  |

Constraints: `role IN ('viewer', 'analyst', 'approver', 'admin')`

## auth_sessions

| column | type | nullable | notes |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| user_id | VARCHAR(36) | no | FK→users.id |
| access_hash | VARCHAR(64) | no |  |
| access_expires_at | DATETIME | no |  |
| refresh_hash | VARCHAR(64) | no |  |
| prev_refresh_hash | VARCHAR(64) | yes |  |
| refresh_expires_at | DATETIME | no |  |
| ip | VARCHAR(64) | yes |  |
| user_agent | VARCHAR(200) | yes |  |
| revoked_at | DATETIME | yes |  |
| revoked_reason | VARCHAR(50) | yes |  |
| created_at | DATETIME | no |  |

## password_reset_tokens

| column | type | nullable | notes |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| user_id | VARCHAR(36) | no | FK→users.id |
| token_hash | VARCHAR(64) | no |  |
| expires_at | DATETIME | no |  |
| used_at | DATETIME | yes |  |
| created_by | VARCHAR(36) | yes |  |
| created_at | DATETIME | no |  |

## targets

| column | type | nullable | notes |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| name | VARCHAR(200) | no |  |
| base_domain | VARCHAR(255) | no |  |
| organization | VARCHAR(200) | yes |  |
| description | TEXT | yes |  |
| authorization_reference | VARCHAR(255) | yes |  |
| authorized_by | VARCHAR(255) | yes |  |
| authorization_document | TEXT | yes |  |
| authorization_valid_from | DATETIME | yes |  |
| authorization_valid_until | DATETIME | yes |  |
| credentials_encrypted | TEXT | yes | never exposed by API |
| created_by | VARCHAR(36) | yes | FK→users.id |
| created_at | DATETIME | no |  |

## assessments

| column | type | nullable | notes |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| target_id | VARCHAR(36) | no | FK→targets.id |
| name | VARCHAR(200) | no |  |
| description | TEXT | yes |  |
| status | VARCHAR(20) | no |  |
| environment | VARCHAR(20) | no |  |
| status_history | JSON | no |  |
| created_by | VARCHAR(36) | yes |  |
| owner_id | VARCHAR(36) | yes | FK→users.id |
| created_at | DATETIME | no |  |

Constraints: `environment IN ('test', 'staging', 'production')`; `status IN ('draft', 'active', 'paused', 'completed', 'archived')`

## assessment_members

| column | type | nullable | notes |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| assessment_id | VARCHAR(36) | no | FK→assessments.id |
| user_id | VARCHAR(36) | no | FK→users.id |
| permission | VARCHAR(15) | no |  |
| added_by | VARCHAR(36) | yes |  |
| created_at | DATETIME | no |  |

Constraints: `permission IN ('viewer', 'analyst', 'approver')`

## assets

| column | type | nullable | notes |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| assessment_id | VARCHAR(36) | no | FK→assessments.id |
| asset_type | VARCHAR(30) | no |  |
| value | VARCHAR(500) | no |  |
| scope_state | VARCHAR(20) | no |  |
| discovery_source | VARCHAR(100) | no |  |
| details | JSON | no |  |
| created_at | DATETIME | no |  |

Constraints: `asset_type IN ('domain', 'subdomain', 'ip', 'url', 'api', 'service', 'database', 'storage', 'third_party', 'auth_system', 'application_server')`; `scope_state IN ('authorized', 'excluded', 'discovered')`

## hypotheses

| column | type | nullable | notes |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| assessment_id | VARCHAR(36) | no | FK→assessments.id |
| category | VARCHAR(60) | no |  |
| title | VARCHAR(300) | no |  |
| reasoning | TEXT | no |  |
| supporting_evidence_ids | JSON | no |  |
| assumptions | JSON | no |  |
| missing_evidence | JSON | no |  |
| confidence | VARCHAR(10) | no |  |
| safe_validation_approach | TEXT | no |  |
| status | VARCHAR(25) | no |  |
| origin | VARCHAR(30) | no |  |
| created_at | DATETIME | no |  |

Constraints: `status IN ('open', 'experiment_planned', 'validated', 'refuted', 'closed')`; `confidence IN ('low', 'medium', 'high')`

## reports

| column | type | nullable | notes |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| assessment_id | VARCHAR(36) | no | FK→assessments.id |
| format | VARCHAR(10) | no |  |
| content | JSON | no |  |
| generated_by | VARCHAR(36) | yes |  |
| created_at | DATETIME | no |  |

## scope_rules

| column | type | nullable | notes |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| assessment_id | VARCHAR(36) | no | FK→assessments.id |
| rule_type | VARCHAR(20) | no |  |
| match_type | VARCHAR(20) | no |  |
| value | VARCHAR(500) | no |  |
| note | TEXT | yes |  |
| created_at | DATETIME | no |  |

Constraints: `rule_type IN ('include', 'exclude')`; `match_type IN ('domain', 'wildcard', 'ip', 'cidr', 'url_prefix')`

## evidence

| column | type | nullable | notes |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| assessment_id | VARCHAR(36) | no | FK→assessments.id |
| asset_id | VARCHAR(36) | yes | FK→assets.id |
| category | VARCHAR(100) | no |  |
| description | TEXT | no |  |
| collection_source | VARCHAR(100) | no |  |
| reference | VARCHAR(1000) | no |  |
| content_hash | VARCHAR(64) | no |  |
| payload | JSON | no |  |
| confidence | VARCHAR(10) | no |  |
| verification_status | VARCHAR(15) | no |  |
| verified_by | VARCHAR(36) | yes |  |
| timestamp | DATETIME | no |  |

Constraints: `confidence IN ('low', 'medium', 'high')`; `verification_status IN ('unverified', 'verified', 'disputed')`

## experiments

| column | type | nullable | notes |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| assessment_id | VARCHAR(36) | no | FK→assessments.id |
| hypothesis_id | VARCHAR(36) | yes | FK→hypotheses.id |
| experiment_type | VARCHAR(40) | no |  |
| parameters | JSON | no |  |
| synthetic_data | JSON | no |  |
| rate_limit_per_minute | INTEGER | no |  |
| max_requests | INTEGER | no |  |
| rollback_plan | TEXT | no |  |
| status | VARCHAR(20) | no |  |
| requested_by | VARCHAR(36) | yes |  |
| approved_by | VARCHAR(36) | yes |  |
| approved_at | DATETIME | yes |  |
| result | JSON | no |  |
| started_at | DATETIME | yes |  |
| finished_at | DATETIME | yes |  |
| created_at | DATETIME | no |  |

Constraints: `experiment_type IN ('http_status_check', 'header_review')`; `rate_limit_per_minute BETWEEN 1 AND 30`; `status IN ('draft', 'pending_approval', 'approved', 'rejected', 'running', 'completed', 'failed', 'rolled_back')`; `max_requests BETWEEN 1 AND 5`

## findings

| column | type | nullable | notes |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| assessment_id | VARCHAR(36) | no | FK→assessments.id |
| hypothesis_id | VARCHAR(36) | yes | FK→hypotheses.id |
| title | VARCHAR(300) | no |  |
| description | TEXT | no |  |
| classification | VARCHAR(30) | no |  |
| severity | VARCHAR(10) | yes |  |
| evidence_ids | JSON | no |  |
| rationale | TEXT | no |  |
| classified_by | VARCHAR(36) | yes |  |
| created_at | DATETIME | no |  |

Constraints: `classification IN ('confirmed_vulnerability', 'potential_vulnerability', 'informational_observation', 'false_positive', 'insufficient_evidence')`

## api_endpoints

| column | type | nullable | notes |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| assessment_id | VARCHAR(36) | no | FK→assessments.id |
| asset_id | VARCHAR(36) | yes | FK→assets.id |
| evidence_id | VARCHAR(36) | no | FK→evidence.id |
| method | VARCHAR(10) | no |  |
| path | VARCHAR(500) | no |  |
| documented | BOOLEAN | no |  |
| auth_scheme | VARCHAR(100) | yes |  |
| description | TEXT | yes |  |
| created_at | DATETIME | no |  |

## application_routes

| column | type | nullable | notes |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| assessment_id | VARCHAR(36) | no | FK→assessments.id |
| evidence_id | VARCHAR(36) | no | FK→evidence.id |
| method | VARCHAR(10) | no |  |
| path | VARCHAR(500) | no |  |
| framework | VARCHAR(50) | yes |  |
| source_file | VARCHAR(500) | yes |  |
| line | INTEGER | yes |  |
| auth_required | BOOLEAN | yes |  |
| created_at | DATETIME | no |  |

## database_schemas

| column | type | nullable | notes |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| assessment_id | VARCHAR(36) | no | FK→assessments.id |
| evidence_id | VARCHAR(36) | no | FK→evidence.id |
| name | VARCHAR(200) | no |  |
| technology | VARCHAR(50) | no |  |
| technology_confidence | VARCHAR(10) | no |  |
| source | VARCHAR(50) | no |  |
| created_at | DATETIME | no |  |

## observations

| column | type | nullable | notes |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| assessment_id | VARCHAR(36) | no | FK→assessments.id |
| asset_id | VARCHAR(36) | yes | FK→assets.id |
| evidence_id | VARCHAR(36) | yes | FK→evidence.id |
| category | VARCHAR(100) | no |  |
| kind | VARCHAR(25) | no |  |
| description | TEXT | no |  |
| collection_source | VARCHAR(100) | no |  |
| evidence_reference | VARCHAR(1000) | no |  |
| confidence | VARCHAR(10) | no |  |
| verification_status | VARCHAR(15) | no |  |
| timestamp | DATETIME | no |  |
| created_at | DATETIME | no |  |

Constraints: `confidence IN ('low', 'medium', 'high')`; `kind IN ('direct_observation', 'inference', 'hypothesis', 'confirmed', 'unknown')`; `verification_status IN ('unverified', 'verified', 'disputed')`; `kind = 'unknown' OR evidence_id IS NOT NULL`

## relationships

| column | type | nullable | notes |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| assessment_id | VARCHAR(36) | no | FK→assessments.id |
| source_asset_id | VARCHAR(36) | no | FK→assets.id |
| target_asset_id | VARCHAR(36) | no | FK→assets.id |
| relation_type | VARCHAR(50) | no |  |
| evidence_id | VARCHAR(36) | no | FK→evidence.id |
| confidence | VARCHAR(10) | no |  |
| crosses_trust_boundary | BOOLEAN | no |  |
| created_at | DATETIME | no |  |

Constraints: `confidence IN ('low', 'medium', 'high')`

## technologies

| column | type | nullable | notes |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| assessment_id | VARCHAR(36) | no | FK→assessments.id |
| asset_id | VARCHAR(36) | yes | FK→assets.id |
| evidence_id | VARCHAR(36) | no | FK→evidence.id |
| name | VARCHAR(200) | no |  |
| version | VARCHAR(100) | yes |  |
| category | VARCHAR(50) | no |  |
| confidence | VARCHAR(10) | no |  |
| created_at | DATETIME | no |  |

Constraints: `confidence IN ('low', 'medium', 'high')`

## database_tables

| column | type | nullable | notes |
|---|---|---|---|
| id | VARCHAR(36) | no | PK |
| schema_id | VARCHAR(36) | no | FK→database_schemas.id |
| name | VARCHAR(200) | no |  |
| columns | JSON | no |  |
| primary_key | JSON | no |  |
| foreign_keys | JSON | no |  |
| ownership_columns | JSON | no |  |
| sensitivity | VARCHAR(20) | no |  |
| created_at | DATETIME | no |  |
