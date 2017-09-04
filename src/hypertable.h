#ifndef TIMESCALEDB_HYPERTABLE_H
#define TIMESCALEDB_HYPERTABLE_H

#include <postgres.h>
#include <nodes/primnodes.h>

#include "catalog.h"
#include "dimension.h"

typedef struct SubspaceStore SubspaceStore;
typedef struct Chunk Chunk;
typedef struct HeapTupleData *HeapTuple;

typedef struct Hypertable
{
	FormData_hypertable fd;
	Oid			main_table_relid;
	Oid         chunk_sizing_func;
	Hyperspace *space;
	SubspaceStore *chunk_cache;
} Hypertable;

extern Hypertable *hypertable_from_tuple(HeapTuple tuple);
extern Chunk *hypertable_get_chunk(Hypertable *h, Point *point);
extern Oid	hypertable_relid(RangeVar *rv);
extern bool is_hypertable(Oid relid);
extern bool hypertable_update(Hypertable *ht);

#endif   /* TIMESCALEDB_HYPERTABLE_H */
