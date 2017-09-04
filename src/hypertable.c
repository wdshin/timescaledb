#include <postgres.h>
#include <access/htup_details.h>
#include <nodes/memnodes.h>
#include <nodes/value.h>
#include <catalog/namespace.h>
#include <utils/lsyscache.h>
#include <utils/memutils.h>
#include <utils/builtins.h>

#include "hypertable.h"
#include "dimension.h"
#include "chunk.h"
#include "subspace_store.h"
#include "hypertable_cache.h"
#include "trigger.h"
#include "scanner.h"
#include "utils.h"

Hypertable *
hypertable_from_tuple(HeapTuple tuple)
{
	Hypertable *h;
	Oid			namespace_oid;

	h = palloc0(sizeof(Hypertable));
	memcpy(&h->fd, GETSTRUCT(tuple), sizeof(FormData_hypertable));
	namespace_oid = get_namespace_oid(NameStr(h->fd.schema_name), false);
	h->main_table_relid = get_relname_relid(NameStr(h->fd.table_name), namespace_oid);
	h->space = dimension_scan(h->fd.id, h->main_table_relid, h->fd.num_dimensions);
	h->chunk_cache = subspace_store_init(h->space->num_dimensions, CurrentMemoryContext);

	if (!heap_attisnull(tuple, Anum_hypertable_chunk_sizing_func_schema) &&
		!heap_attisnull(tuple, Anum_hypertable_chunk_sizing_func_name))
	{
		FuncCandidateList func =
			FuncnameGetCandidates(list_make2(makeString(NameStr(h->fd.chunk_sizing_func_schema)),
											 makeString(NameStr(h->fd.chunk_sizing_func_name))),
								  2, NIL, false, false, false);

		if (NULL == func || NULL != func->next)
			elog(ERROR, "Could not find the adaptive chunking function '%s.%s'",
				 NameStr(h->fd.chunk_sizing_func_schema),
				 NameStr(h->fd.chunk_sizing_func_name));

		h->chunk_sizing_func = func->oid;
	}

	return h;
}

typedef struct ChunkCacheEntry
{
	MemoryContext mcxt;
	Chunk	   *chunk;
} ChunkCacheEntry;

static void
chunk_cache_entry_free(void *cce)
{
	MemoryContextDelete(((ChunkCacheEntry *) cce)->mcxt);
}

Chunk *
hypertable_get_chunk(Hypertable *h, Point *point)
{
	ChunkCacheEntry *cce = subspace_store_get(h->chunk_cache, point);

	if (NULL == cce)
	{
		MemoryContext old_mcxt,
					chunk_mcxt;
		Chunk	   *chunk;

		/*
		 * chunk_find() must execute on a per-tuple memory context since it
		 * allocates a lot of transient data. We don't want this allocated on
		 * the cache's memory context.
		 */
		chunk = chunk_find(h->space, point);

		if (NULL == chunk)
			chunk = chunk_create(h, point,
								 NameStr(h->fd.associated_schema_name),
								 NameStr(h->fd.associated_table_prefix));

		Assert(chunk != NULL);

		chunk_mcxt = AllocSetContextCreate(subspace_store_mcxt(h->chunk_cache),
										   "chunk cache memory context",
										   ALLOCSET_SMALL_SIZES);

		old_mcxt = MemoryContextSwitchTo(chunk_mcxt);

		cce = palloc(sizeof(ChunkCacheEntry));
		cce->mcxt = chunk_mcxt;

		/* Make a copy which lives in the chunk cache's memory context */
		chunk = cce->chunk = chunk_copy(chunk);

		subspace_store_add(h->chunk_cache, chunk->cube, cce, chunk_cache_entry_free);
		MemoryContextSwitchTo(old_mcxt);
	}

	Assert(NULL != cce);
	Assert(NULL != cce->chunk);
	Assert(MemoryContextContains(cce->mcxt, cce));
	Assert(MemoryContextContains(cce->mcxt, cce->chunk));

	return cce->chunk;
}

static inline Oid
hypertable_relid_lookup(Oid relid)
{
	Cache	   *hcache = hypertable_cache_pin();
	Hypertable *ht = hypertable_cache_get_entry(hcache, relid);
	Oid			result = (ht == NULL) ? InvalidOid : ht->main_table_relid;

	cache_release(hcache);

	return result;
}

/*
 * Returns a hypertable's relation ID (OID) iff the given RangeVar corresponds to
 * a hypertable, otherwise InvalidOid.
*/
Oid
hypertable_relid(RangeVar *rv)
{
	return hypertable_relid_lookup(RangeVarGetRelid(rv, NoLock, true));
}

bool
is_hypertable(Oid relid)
{
	if (!OidIsValid(relid))
		return false;
	return hypertable_relid_lookup(relid) != InvalidOid;
}

PG_FUNCTION_INFO_V1(hypertable_validate_triggers);

Datum
hypertable_validate_triggers(PG_FUNCTION_ARGS)
{
	if (relation_has_transition_table_trigger(PG_GETARG_OID(0)))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
		errmsg("Hypertables do not support transition tables in triggers.")));

	PG_RETURN_VOID();
}

static int
hypertable_scan_internal(ScanKeyData *scankey,
						 int num_scankeys,
						 int index_id,
						 tuple_found_func on_tuple_found,
						 void *scandata,
						 LOCKMODE lockmode)
{
	Catalog    *catalog = catalog_get();
	ScannerCtx	scanctx = {
		.table = catalog->tables[HYPERTABLE].id,
		.index = catalog->tables[HYPERTABLE].index_ids[index_id],
		.scantype = ScannerTypeIndex,
		.nkeys = num_scankeys,
		.scankey = scankey,
		.data = scandata,
		.limit = 1,
		.tuple_found = on_tuple_found,
		.lockmode = lockmode,
		.scandirection = ForwardScanDirection,
	};

	return scanner_scan(&scanctx);
}

static int
hypertable_scan_by_id(int32 hypertable_id,
					  tuple_found_func on_tuple_found,
					  void *scandata,
					  LOCKMODE lockmode)
{
	ScanKeyData scankey[1];

	/* Perform an index scan on the hypertable ID. */
	ScanKeyInit(&scankey[0], Anum_hypertable_pkey_idx_id,
				BTEqualStrategyNumber, F_INT4EQ, hypertable_id);

	return hypertable_scan_internal(scankey, 1, HYPERTABLE_ID_INDEX, on_tuple_found, scandata, lockmode);
}

static bool
hypertable_tuple_update(TupleInfo *ti, void *data)
{
	Hypertable  *ht = data;
	Datum		values[Natts_hypertable];
	bool		nulls[Natts_hypertable];
	HeapTuple	copy;

	heap_deform_tuple(ti->tuple, ti->desc, values, nulls);

	values[Anum_hypertable_schema_name - 1] = NameGetDatum(&ht->fd.schema_name);
	values[Anum_hypertable_table_name - 1] = NameGetDatum(&ht->fd.table_name);
	values[Anum_hypertable_associated_schema_name - 1] = NameGetDatum(&ht->fd.associated_schema_name);
	values[Anum_hypertable_associated_table_prefix - 1] = NameGetDatum(&ht->fd.associated_table_prefix);
	values[Anum_hypertable_num_dimensions - 1] = Int16GetDatum(ht->fd.num_dimensions);
	values[Anum_hypertable_chunk_target_size - 1] = Int64GetDatum(ht->fd.chunk_target_size);

	memset(nulls, 0, sizeof(nulls));

	if (OidIsValid(ht->chunk_sizing_func))
	{
		Form_pg_proc procform = get_procform(ht->chunk_sizing_func);

		namestrcpy(&ht->fd.chunk_sizing_func_schema, get_namespace_name(procform->pronamespace));
		StrNCpy(ht->fd.chunk_sizing_func_name.data, NameStr(procform->proname), NAMEDATALEN);

		values[Anum_hypertable_chunk_sizing_func_schema - 1] =
			NameGetDatum(&ht->fd.chunk_sizing_func_schema);
		values[Anum_hypertable_chunk_sizing_func_name - 1] =
			NameGetDatum(&ht->fd.chunk_sizing_func_name);
	}
	else
	{
		nulls[Anum_hypertable_chunk_sizing_func_schema - 1] = true;
		nulls[Anum_hypertable_chunk_sizing_func_name - 1] = true;
	}

	copy = heap_form_tuple(ti->desc, values, nulls);

	catalog_update_tid(ti->scanrel, &ti->tuple->t_self, copy);

	heap_freetuple(copy);

	return true;
}

bool
hypertable_update(Hypertable *ht)
{
	return hypertable_scan_by_id(ht->fd.id, hypertable_tuple_update, ht, RowExclusiveLock) > 0;
}
