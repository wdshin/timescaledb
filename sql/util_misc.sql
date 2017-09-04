CREATE OR REPLACE FUNCTION _timescaledb_internal.convert_text_memory_amount_to_bytes(amount TEXT)
    RETURNS BIGINT AS '$libdir/timescaledb', 'convert_text_memory_amount_to_bytes'
    LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION _timescaledb_internal.estimate_effective_memory()
    RETURNS BIGINT AS '$libdir/timescaledb', 'estimate_effective_memory_bytes'
    LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION array_avg(double precision[])
RETURNS double precision AS
$$
   SELECT avg(v) FROM unnest($1) g(v)
$$ LANGUAGE SQL;
