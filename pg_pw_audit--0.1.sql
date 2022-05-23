
--complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_pw_audit" to load this file. \quit

DROP TABLE IF EXISTS pg_pw_audit;

CREATE TABLE pg_pw_audit(
	username text,
	changed_when timestamp with time zone,
	changed_by text
);

CREATE FUNCTION pg_pw_audit_showhash(
	OUT username text,
	OUT changed_when timestamp with time zone,
	OUT changed_by text
)
RETURNS SETOF record
AS 'MODULE_PATHNAME', 'pg_pw_audit_showhash'
LANGUAGE C STRICT VOLATILE;
