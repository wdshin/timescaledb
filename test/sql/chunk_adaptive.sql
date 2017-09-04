-- Valid chunk sizing function for testing
CREATE OR REPLACE FUNCTION calculate_chunk_interval(
        dimension_id INTEGER,
        chunk_target_size BIGINT
)
    RETURNS BIGINT LANGUAGE PLPGSQL AS
$BODY$
DECLARE
BEGIN
    RETURN -1;
END
$BODY$;

-- Chunk sizing function with bad signature
CREATE OR REPLACE FUNCTION bad_calculate_chunk_interval(
        dimension_id INTEGER
)
    RETURNS BIGINT LANGUAGE PLPGSQL AS
$BODY$
DECLARE
BEGIN
    RETURN -1;
END
$BODY$;

CREATE TABLE test_adaptive(time timestamptz, temp float);

\set ON_ERROR_STOP 0
-- Bad signature of sizing func should fail
SELECT create_hypertable('test_adaptive', 'time',
                         chunk_target_size => '1MB',
                         chunk_sizing_func => 'bad_calculate_chunk_interval');

\set ON_ERROR_STOP 1

-- Setting sizing func with correct signature should work
SELECT create_hypertable('test_adaptive', 'time',
                         chunk_target_size => '1MB',
                         chunk_sizing_func => 'calculate_chunk_interval');

DROP TABLE test_adaptive;
CREATE TABLE test_adaptive(time timestamptz, temp float);

-- Size but no explicit func should use default func
SELECT create_hypertable('test_adaptive', 'time',
                         chunk_target_size => '1MB');
SELECT table_name, chunk_sizing_func_schema, chunk_sizing_func_name, chunk_target_size
FROM _timescaledb_catalog.hypertable;

-- Change the target size
SELECT * FROM set_adaptive_chunk_sizing('test_adaptive', '2MB');
SELECT table_name, chunk_sizing_func_schema, chunk_sizing_func_name, chunk_target_size
FROM _timescaledb_catalog.hypertable;

-- Setting NULL func should use existing function
SELECT * FROM set_adaptive_chunk_sizing('test_adaptive', '1MB', NULL);
SELECT table_name, chunk_sizing_func_schema, chunk_sizing_func_name, chunk_target_size
FROM _timescaledb_catalog.hypertable;

-- Setting NULL size disables adaptive chunking
SELECT * FROM set_adaptive_chunk_sizing('test_adaptive', NULL);
SELECT table_name, chunk_sizing_func_schema, chunk_sizing_func_name, chunk_target_size
FROM _timescaledb_catalog.hypertable;

SELECT * FROM set_adaptive_chunk_sizing('test_adaptive', '1MB');

-- Setting size to 'off' should also disable
SELECT * FROM set_adaptive_chunk_sizing('test_adaptive', 'off');
SELECT table_name, chunk_sizing_func_schema, chunk_sizing_func_name, chunk_target_size
FROM _timescaledb_catalog.hypertable;

-- Setting 0 size should estimate size
SELECT * FROM set_adaptive_chunk_sizing('test_adaptive', '0MB');
SELECT table_name, chunk_sizing_func_schema, chunk_sizing_func_name, chunk_target_size
FROM _timescaledb_catalog.hypertable;

SELECT * FROM set_adaptive_chunk_sizing('test_adaptive', '1MB');

-- Setting size to 'estimate' should also estimate size
SELECT * FROM set_adaptive_chunk_sizing('test_adaptive', 'estimate');
SELECT table_name, chunk_sizing_func_schema, chunk_sizing_func_name, chunk_target_size
FROM _timescaledb_catalog.hypertable;

-- Set a reasonable test value
SELECT * FROM set_adaptive_chunk_sizing('test_adaptive', '1MB');

INSERT INTO test_adaptive
SELECT time, random() * 35 FROM
generate_series('2017-03-07T18:18:03+00'::timestamptz - interval '175 days',
                '2017-03-07T18:18:03+00'::timestamptz,
                '5 minutes') as time;

SELECT * FROM chunk_relation_size('test_adaptive');
