-- =========================
-- USER
-- =========================
DEFINE TABLE user SCHEMAFULL
PERMISSIONS
  FOR select WHERE id = $auth.id
  FOR update WHERE id = $auth.id
  FOR create NONE
  FOR delete NONE;

DEFINE FIELD email       ON user TYPE string;
DEFINE FIELD name        ON user TYPE string;
DEFINE FIELD created_at  ON user TYPE datetime;

-- =========================
-- SESSION
-- =========================
DEFINE TABLE session SCHEMAFULL
PERMISSIONS
  FOR select WHERE user = $auth.id
  FOR delete WHERE user = $auth.id
  FOR create NONE
  FOR update NONE;

DEFINE FIELD user        ON session TYPE record<user>;
DEFINE FIELD refresh_hash ON session TYPE string;
DEFINE FIELD created_at  ON session TYPE datetime;
DEFINE FIELD expires_at  ON session TYPE datetime;
DEFINE FIELD user_agent  ON session TYPE string;
DEFINE FIELD ip          ON session TYPE string;

-- =========================
-- WORKSPACE
-- =========================
DEFINE TABLE workspace SCHEMAFULL
PERMISSIONS
  FOR select WHERE owner = $auth.id
  FOR update WHERE owner = $auth.id
  FOR delete WHERE owner = $auth.id
  FOR create WHERE $auth.id != NONE;

DEFINE FIELD name        ON workspace TYPE string;
DEFINE FIELD owner       ON workspace TYPE record<user>;
DEFINE FIELD created_at  ON workspace TYPE datetime;


-- =========================
-- BASE
-- =========================
DEFINE TABLE base SCHEMAFULL
PERMISSIONS
  FOR select WHERE workspace.owner = $auth.id
  FOR update WHERE workspace.owner = $auth.id
  FOR delete WHERE workspace.owner = $auth.id
  FOR create WHERE workspace.owner = $auth.id;

DEFINE FIELD workspace   ON base TYPE record<workspace>;
DEFINE FIELD name        ON base TYPE string;
DEFINE FIELD created_at  ON base TYPE datetime;


-- =========================
-- TABLE DEFINITION
-- =========================
DEFINE TABLE table_def SCHEMAFULL
PERMISSIONS
  FOR select WHERE base.workspace.owner = $auth.id
  FOR update WHERE base.workspace.owner = $auth.id
  FOR delete WHERE base.workspace.owner = $auth.id
  FOR create WHERE base.workspace.owner = $auth.id;

DEFINE FIELD base        ON table_def TYPE record<base>;
DEFINE FIELD name        ON table_def TYPE string;
DEFINE FIELD order       ON table_def TYPE number;
DEFINE FIELD created_at  ON table_def TYPE datetime;


-- =========================
-- FIELD (COLUMN)
-- =========================
DEFINE TABLE field SCHEMAFULL
PERMISSIONS
  FOR select WHERE table.base.workspace.owner = $auth.id
  FOR update WHERE table.base.workspace.owner = $auth.id
  FOR delete WHERE table.base.workspace.owner = $auth.id
  FOR create WHERE table.base.workspace.owner = $auth.id;

DEFINE FIELD table       ON field TYPE record<table_def>;
DEFINE FIELD name        ON field TYPE string;
DEFINE FIELD type        ON field TYPE string;
DEFINE FIELD config      ON field TYPE object;
DEFINE FIELD order       ON field TYPE number;
DEFINE FIELD created_at  ON field TYPE datetime;


-- =========================
-- RECORD (ROW)
-- =========================
DEFINE TABLE record SCHEMAFULL
PERMISSIONS
  FOR select WHERE table.base.workspace.owner = $auth.id
  FOR update WHERE table.base.workspace.owner = $auth.id
  FOR delete WHERE table.base.workspace.owner = $auth.id
  FOR create WHERE table.base.workspace.owner = $auth.id;

DEFINE FIELD table       ON record TYPE record<table_def>;
DEFINE FIELD created_at  ON record TYPE datetime;
DEFINE FIELD updated_at  ON record TYPE datetime;


-- =========================
-- CELL (VALUE)
-- =========================
DEFINE TABLE cell SCHEMAFULL
PERMISSIONS
  FOR select WHERE record.table.base.workspace.owner = $auth.id
  FOR update WHERE record.table.base.workspace.owner = $auth.id
  FOR delete WHERE record.table.base.workspace.owner = $auth.id
  FOR create WHERE record.table.base.workspace.owner = $auth.id;

DEFINE FIELD record      ON cell TYPE record<record>;
DEFINE FIELD field       ON cell TYPE record<field>;
DEFINE FIELD value       ON cell TYPE any;


-- =========================
-- RELATION (LINKED RECORDS)
-- =========================
DEFINE TABLE relation SCHEMAFULL
PERMISSIONS
  FOR select WHERE from_record.table.base.workspace.owner = $auth.id
  FOR update WHERE from_record.table.base.workspace.owner = $auth.id
  FOR delete WHERE from_record.table.base.workspace.owner = $auth.id
  FOR create WHERE from_record.table.base.workspace.owner = $auth.id;

DEFINE FIELD from_record ON relation TYPE record<record>;
DEFINE FIELD to_record   ON relation TYPE record<record>;
DEFINE FIELD field       ON relation TYPE record<field>;

