#include <postgres.h>
#include <catalog/pg_proc.h>
#include <catalog/pg_type.h>
#include <utils/syscache.h>
#include <utils/lsyscache.h>
#include <utils/guc.h>
#include <utils/builtins.h>
#include <utils/array.h>
#include <funcapi.h>

#if !defined(WIN32)
#include <unistd.h>
#endif

#include "hypertable_cache.h"
#include "errors.h"
#include "utils.h"

#if defined(WIN32)
#include "windows.h"
static int64
system_memory_bytes(void)
{
	MEMORYSTATUSEX status;

	status.dwLength = sizeof(status);
	GlobalMemoryStatusEx(&status);

	return status.ullTotalPhys;
}
#elif defined(_SC_PHYS_PAGES) && defined(_SC_PAGESIZE)
static int64
system_memory_bytes(void)
{
	int64		bytes;

	bytes = sysconf(_SC_PHYS_PAGES);
	bytes *= sysconf(_SC_PAGESIZE);

	return bytes;
}
#else
#error "Unsupported platform"
#endif

/*
 * Estimate the effective memory available to PostgreSQL based on the settings
 * of 'shared_buffers' and 'effective_cache_size'.
 *
 * Although we could rely solely on something like sysconf() to get the actual
 * system memory available, PostgreSQL will still be bound by 'shared_buffers'
 * and 'effective_cache_size' so might not effectively use the full memory on
 * the system anyway.
 *
 * If accurately set, 'effective_cache_size' is probably the best value to use
 * since it provides an estimate of the combined memory in both the shared
 * buffers and disk cache. A conservative setting of 'effective_cache_size' is
 * typically 1/2 the memory of the system, while a common recommended setting
 * for 'shared_buffers' is 1/4 of system memory. The caveat here is that it is
 * much more common to set 'shared_buffers', so therefore we try to use the max
 * of 'effective_cache_size' and twice the 'shared_buffers'.
 */
static int64
estimate_effective_memory(void)
{
	const char *val;
	const char *hintmsg;
	int			shared_buffers,
				effective_cache_size;
	int64		memory_bytes;
	int64		sysmem_bytes = system_memory_bytes();

	val = GetConfigOption("shared_buffers", false, false);

	if (NULL == val)
		elog(ERROR, "Missing configuration for 'shared_buffers'");

	if (!parse_int(val, &shared_buffers, GUC_UNIT_BLOCKS, &hintmsg))
		elog(ERROR, "Could not parse 'shared_buffers' setting: %s", hintmsg);

	val = GetConfigOption("effective_cache_size", false, false);

	if (NULL == val)
		elog(ERROR, "Missing configuration for 'effective_cache_size'");

	if (!parse_int(val, &effective_cache_size, GUC_UNIT_BLOCKS, &hintmsg))
		elog(ERROR, "Could not parse 'effective_cache_size' setting: %s", hintmsg);

	memory_bytes = Max((int64) shared_buffers * 4, (int64) effective_cache_size * 2);

	/* Both values are in blocks, so convert to bytes */
	memory_bytes *= BLCKSZ;

	if (memory_bytes > sysmem_bytes)
		memory_bytes = sysmem_bytes;

	return memory_bytes;
}

PG_FUNCTION_INFO_V1(estimate_effective_memory_bytes);

Datum
estimate_effective_memory_bytes(PG_FUNCTION_ARGS)
{
	PG_RETURN_INT64(estimate_effective_memory());
}

static inline int64
calculate_initial_chunk_target_size(void)
{
	/* Simply use a quarter of estimated memory for now */
	return estimate_effective_memory() / 4;
}

PG_FUNCTION_INFO_V1(chunk_adaptive_calculate_initial_chunk_target_size);

Datum
chunk_adaptive_calculate_initial_chunk_target_size(PG_FUNCTION_ARGS)
{
	PG_RETURN_INT64(calculate_initial_chunk_target_size());
}

static int64
convert_text_memory_amount_to_bytes_internal(const char *val)
{
	const char *hintmsg;
	int			nblocks;
	int64		bytes;

	if (!parse_int(val, &nblocks, GUC_UNIT_BLOCKS, &hintmsg))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("Invalid data amount"),
				 errhint("%s", hintmsg)));

	bytes = nblocks;
	bytes *= BLCKSZ;

	return bytes;
}

PG_FUNCTION_INFO_V1(convert_text_memory_amount_to_bytes);

Datum
convert_text_memory_amount_to_bytes(PG_FUNCTION_ARGS)
{
	const char *value = text_to_cstring(PG_GETARG_TEXT_P(0));

	PG_RETURN_INT64(convert_text_memory_amount_to_bytes_internal(value));
}

#define CHUNK_SIZING_FUNC_NARGS 2

static void
validate_chunk_sizing_func(regproc func)
{
	Form_pg_proc procform = get_procform(func);
	Oid *typearr = procform->proargtypes.values;

	if (procform->pronargs != CHUNK_SIZING_FUNC_NARGS ||
		typearr[0] != INT4OID ||
		typearr[1] != INT8OID ||
		procform->prorettype != INT8OID)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_FUNCTION_DEFINITION),
				 errmsg("Invalid number of function arguments"),
				 errhint("A chunk sizing function's signature should be (int, bigint) -> bigint")));
}

PG_FUNCTION_INFO_V1(chunk_adaptive_validate_chunk_sizing_func);

Datum
chunk_adaptive_validate_chunk_sizing_func(PG_FUNCTION_ARGS)
{
	validate_chunk_sizing_func(PG_GETARG_OID(0));
	PG_RETURN_VOID();
}

PG_FUNCTION_INFO_V1(chunk_adaptive_set_chunk_sizing);

Datum
chunk_adaptive_set_chunk_sizing(PG_FUNCTION_ARGS)
{
	Oid relid = PG_GETARG_OID(0);
	text *chunk_target_size = PG_ARGISNULL(1) ? NULL : PG_GETARG_TEXT_P(1);
	regproc chunk_sizing_func = PG_ARGISNULL(2) ? InvalidOid : PG_GETARG_OID(2);
	int64 chunk_target_size_bytes = 0;
	Hypertable *ht;
	Cache *hcache;
	HeapTuple tuple;
	TupleDesc tupdesc;
	CatalogSecurityContext sec_ctx;
	Datum values[2];
	bool nulls[2] = { false, false };

	if (!OidIsValid(relid))
		ereport(ERROR,
				(errcode(ERRCODE_IO_HYPERTABLE_NOT_EXIST),
				 errmsg("No such table exists")));

	hcache = hypertable_cache_pin();
	ht = hypertable_cache_get_entry(hcache, relid);

	if (NULL == ht)
		ereport(ERROR,
				(errcode(ERRCODE_IO_HYPERTABLE_NOT_EXIST),
				 errmsg("The table %s is not a hypertable", get_rel_name(relid))));

	if (NULL != chunk_target_size)
	{
		const char *target_size = text_to_cstring(chunk_target_size);

		if (strcasecmp(target_size, "off") != 0)
		{
			if (strcasecmp(target_size, "estimate") != 0)
				chunk_target_size_bytes =
					convert_text_memory_amount_to_bytes_internal(target_size);

			if (chunk_target_size_bytes <= 0)
				chunk_target_size_bytes = calculate_initial_chunk_target_size();
		}
	}

	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "function returning record called in context that cannot accept type record");

	tupdesc = BlessTupleDesc(tupdesc);

	if (OidIsValid(chunk_sizing_func))
	{
		validate_chunk_sizing_func(chunk_sizing_func);
		ht->chunk_sizing_func = chunk_sizing_func;
		values[0] = DatumGetObjectId(chunk_sizing_func);
	}
	else if (OidIsValid(ht->chunk_sizing_func))
	{
		validate_chunk_sizing_func(ht->chunk_sizing_func);
		values[0] = DatumGetObjectId(ht->chunk_sizing_func);
	}
	else
		nulls[0] = true;

	values[1] = DatumGetInt64(chunk_target_size_bytes);

	/* Update the hypertable entry */
	ht->fd.chunk_target_size = chunk_target_size_bytes;
	catalog_become_owner(catalog_get(), &sec_ctx);
	hypertable_update(ht);
	catalog_restore_user(&sec_ctx);

	cache_release(hcache);

	tuple = heap_form_tuple(tupdesc, values, nulls);

	PG_RETURN_DATUM(HeapTupleGetDatum(tuple));
}
