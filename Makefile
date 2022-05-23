# Makefile

MODULE_big = pg_pw_audit
OBJS = \
	$(WIN32RES) \
	pg_pw_audit.o

EXTENSION = pg_pw_audit
DATA = pg_pw_audit--0.1.sql
PGFILEDESC = "pg_pw_audit - log password changes"

PG_CONFIG = /usr/pgsql-14/bin/pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
