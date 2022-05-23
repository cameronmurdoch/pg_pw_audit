/*-----------------------------------------------------------------------------
 *
 * pg_pw_audit.c
 *		PostgreSQL extension that logs passwords changes to a table via a
 *		background worker.
 *
 * Copyright (c) 2022, Cameron Murdoch
 *
 * Author: Cameron Murdoch <cam@macaroon.net>
 *
 * IDENTIFICATION
 *		pg_pw_audit.c
 * ----------------------------------------------------------------------------
 */

#include "postgres.h"

/* These are always necessary for a bgworker */
#include "miscadmin.h"
#include "postmaster/bgworker.h"
#include "postmaster/interrupt.h"
#include "storage/ipc.h"
#include "storage/latch.h"
#include "storage/lwlock.h"
#include "storage/proc.h"
#include "storage/shmem.h"

#include "access/xact.h"
#include "commands/user.h"
#include "fmgr.h"
#include "executor/spi.h"
#include "lib/stringinfo.h"
#include "pgstat.h"
#include "utils/snapmgr.h"
#include "utils/builtins.h"
#include "tcop/utility.h"
#include "funcapi.h"

PG_MODULE_MAGIC;

typedef struct pwaHashKey
{
	char		username[NAMEDATALEN];		/* usename whose password has changed */
} pwaHashKey;

typedef struct pwaEntry
{
	char		username[NAMEDATALEN];		/* usename whose password has changed */
	TimestampTz	changed_when;				/* when did it change */
	char		changed_by[NAMEDATALEN];	/* who changed it */

} pwaEntry;

typedef struct pwaSharedState
{
	LWLock		*lock;		/* Protects the hash table */
	int			test2;

} pwaSharedState;

/* Function declarations */

PG_FUNCTION_INFO_V1(pg_pw_audit_showhash);

/* Save the original hooks */
static shmem_startup_hook_type prev_shmem_startup_hook = NULL;
static check_password_hook_type prev_check_password_hook = NULL;

static pwaSharedState *pwa = NULL;
static HTAB *pwa_hash = NULL;

static void pwa_shmem_startup(void);
static void log_password_change(const char *username,
								const char *shadow_pass,
								PasswordType password_type,
								Datum validuntil_time,
								bool validuntil_null);

static Size pwa_memsize(void);

void _PG_init(void);
void _PG_fini(void);
void pg_pw_audit_main(Datum);

static volatile sig_atomic_t got_sigterm = false;

static void
pwa_shmem_startup(void)
{
	bool		found;
	HASHCTL		info;

	if (prev_shmem_startup_hook)
		prev_shmem_startup_hook();

	pwa = NULL;
	pwa_hash = NULL;

	LWLockAcquire(AddinShmemInitLock, LW_EXCLUSIVE);

	pwa = ShmemInitStruct("pg_pw_audit",
						  sizeof(pwaSharedState),
						  &found);
	if (!found)
	{
		/* First time */
		pwa->lock = &(GetNamedLWLockTranche("pg_pw_audit"))->lock;
	}

	info.keysize = NAMEDATALEN;
	info.entrysize = sizeof(pwaEntry);
	pwa_hash = ShmemInitHash("pg_pw_audit hash",
							 9, 10,
							 &info,
							 HASH_ELEM | HASH_STRINGS);

	LWLockRelease(AddinShmemInitLock);


	ereport(LOG,
			errcode(ERRCODE_SUCCESSFUL_COMPLETION),
			errmsg("keysize %zu, entrysize %zu", info.keysize, info.entrysize),
			errhidestmt(true));
}

/* Helper function to show contents of hash table */
Datum
pg_pw_audit_showhash(PG_FUNCTION_ARGS)
{
	ReturnSetInfo		*rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	TupleDesc			tupdesc;
	Tuplestorestate		*tupstore;
	MemoryContext		per_query_ctx;
	MemoryContext		oldcontext;
	HASH_SEQ_STATUS		hash_seq;
	pwaEntry			*entry;


	per_query_ctx = rsinfo->econtext->ecxt_per_query_memory;
	oldcontext = MemoryContextSwitchTo(per_query_ctx);

	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "return type must be a row type");

	tupstore = tuplestore_begin_heap(true, false, work_mem);
	rsinfo->returnMode = SFRM_Materialize;
	rsinfo->setResult = tupstore;
	rsinfo->setDesc = tupdesc;

	MemoryContextSwitchTo(oldcontext);

	/* Get shared lock to iterate over hashtable.
	 * This blocks creation of new hashtable entries,
	 * should be ok as the table will normally be small.
	 */
	LWLockAcquire(pwa->lock, LW_SHARED);

	hash_seq_init(&hash_seq, pwa_hash);
	while ((entry = hash_seq_search(&hash_seq)) != NULL)
	{
		Datum		values[3];
		bool		nulls[3];

		memset(values, 0, sizeof(values));
		memset(nulls, 0, sizeof(nulls));

        values[0] = CStringGetTextDatum(entry->username);
        values[1] = TimestampTzGetDatum(entry->changed_when);
        values[2] = CStringGetTextDatum(entry->changed_by);

		tuplestore_putvalues(tupstore, tupdesc, values, nulls);
	}

	/* Release the hashtable lock */
	LWLockRelease(pwa->lock);

	tuplestore_donestoring(tupstore);

	return (Datum) 0;
}

static Size
pwa_memsize(void)
{
	Size	size;

	size = MAXALIGN(sizeof(pwaSharedState));
	size = add_size(size, hash_estimate_size(10, sizeof(pwaEntry)));

	return size;
}

static void
log_password_change(const char *username,
					const char *shadow_pass,
					PasswordType password_type,
					Datum validuntil_time,
					bool validuntil_null)
{
	BackgroundWorker		worker;
	BackgroundWorkerHandle	*handle;
	BgwHandleStatus			status;
	pid_t					pid;
	pwaEntry				*entry;
	bool					found;
	Oid						changed_by_userid;
	char					*changed_by;

	if (prev_check_password_hook)
		prev_check_password_hook(username, shadow_pass,
								 password_type, validuntil_time,
								 validuntil_null);

	/* Do we need to do something if the oid doesn't return a user?
	 * Do we need to check the lengths of these? */
	changed_by_userid = GetUserId();
	changed_by = GetUserNameFromId(changed_by_userid, true);

	/* Does username need to be buffered here? NAMEDATALEN? */
	ereport(LOG_SERVER_ONLY,
			errcode(ERRCODE_SUCCESSFUL_COMPLETION),
			errmsg("Password for user %s just changed by %s", username, changed_by),
			errhidestmt(true));

	/* Lookup / add the hash table entry for username with the lock.
	 * Might be risky holding the exclusive lock here.
	 * Eventually we might have to use the sharelock and search before
	 * adding/updating. */
	LWLockAcquire(pwa->lock, LW_EXCLUSIVE);

	entry = (pwaEntry *) hash_search(pwa_hash, username, HASH_ENTER, &found);
	entry->changed_when = GetCurrentTimestamp();
	strcpy(entry->changed_by, changed_by);

	LWLockRelease(pwa->lock);

	memset(&worker, 0, sizeof(worker));
	worker.bgw_flags = BGWORKER_SHMEM_ACCESS | BGWORKER_BACKEND_DATABASE_CONNECTION;
	worker.bgw_start_time = BgWorkerStart_RecoveryFinished;
	worker.bgw_restart_time = BGW_NEVER_RESTART;
	sprintf(worker.bgw_library_name, "pg_pw_audit");
	sprintf(worker.bgw_function_name, "pg_pw_audit_main");
	sprintf(worker.bgw_name, "pg_pw_audit");
	sprintf(worker.bgw_type, "pg_pw_audit");
	strcpy(worker.bgw_extra, username); /* BGW_MAXLEN vs NAMEDATALEN - check sizes */
	worker.bgw_main_arg = Int32GetDatum(1);
	worker.bgw_notify_pid = MyProcPid;

    RegisterDynamicBackgroundWorker(&worker, &handle);

	status = WaitForBackgroundWorkerStartup(handle, &pid);

    if (status == BGWH_STOPPED)
        ereport(ERROR,
                (errcode(ERRCODE_INSUFFICIENT_RESOURCES),
                 errmsg("could not start background process"),
                 errhint("More details may be available in the server log.")));
    if (status == BGWH_POSTMASTER_DIED)
        ereport(ERROR,
                (errcode(ERRCODE_INSUFFICIENT_RESOURCES),
                 errmsg("cannot start background processes without postmaster"),
                 errhint("Kill all remaining database processes and restart the database.")));
    Assert(status == BGWH_STARTED);
}

static void
pg_pw_audit_sigterm(SIGNAL_ARGS)
{
	int save_errno = errno;
	got_sigterm = true;
	SetLatch(MyLatch);
	errno = save_errno;
}

void
pg_pw_audit_main(Datum main_arg)
{
	/* int	index = DatumGetInt32(main_arg); */
	StringInfoData	buf;
	pwaEntry		*entry;

	/* Establish signal handlers before unblocking signals. -- NEEDS FIXING? */
	pqsignal(SIGHUP, SignalHandlerForConfigReload);
	pqsignal(SIGTERM, pg_pw_audit_sigterm);

	/* We're now ready to receive signals */
	BackgroundWorkerUnblockSignals();

	LWLockAcquire(pwa->lock, LW_SHARED);
	entry = (pwaEntry *) hash_search(pwa_hash, MyBgworkerEntry->bgw_extra, HASH_FIND, NULL);
	LWLockRelease(pwa->lock);

	BackgroundWorkerInitializeConnection("postgres", NULL, 0);

	initStringInfo(&buf);
	/* is this really the best way to do this? Is it safe, from injections?
	 * Also, pulling everything out of the hash table to then instert as text/strings seems odd */
	appendStringInfo(&buf, "INSERT INTO pg_pw_audit values ('%s', '%s', '%s');",
					 entry->username, timestamptz_to_str(entry->changed_when), entry->changed_by);

	SetCurrentStatementStartTimestamp();
	StartTransactionCommand();
	PushActiveSnapshot(GetTransactionSnapshot());
	debug_query_string = buf.data;
	pgstat_report_activity(STATE_RUNNING, buf.data);

	SPI_connect();
	SPI_execute(buf.data, false, 0);
	SPI_finish();
	PopActiveSnapshot();
	CommitTransactionCommand();
	debug_query_string = NULL;
	pgstat_report_stat(true);
	pgstat_report_activity(STATE_IDLE, NULL);

	proc_exit(0);

}

void
_PG_init(void)
{

	/* Request additional shared resources */
	RequestAddinShmemSpace(pwa_memsize());
	RequestNamedLWLockTranche("pg_pw_audit", 1);

	prev_shmem_startup_hook = shmem_startup_hook;
	shmem_startup_hook = pwa_shmem_startup;
	prev_check_password_hook = check_password_hook;
	check_password_hook = log_password_change;
}

void
_PG_fini(void)
{
	check_password_hook = prev_check_password_hook;
}
