CREATE OR REPLACE FUNCTION array_avg(double precision[])
RETURNS double precision AS
$$
   SELECT avg(v) FROM unnest($1) g(v)
$$ LANGUAGE SQL;

CREATE OR REPLACE FUNCTION _timescaledb_internal.calculate_chunk_interval(
        dimension_id INTEGER,
        chunk_target_size BIGINT
)
    RETURNS BIGINT LANGUAGE PLPGSQL AS
$BODY$
DECLARE
    dimension_row        _timescaledb_catalog.dimension;
    chunk_row            _timescaledb_catalog.chunk;
    chunk_interval       BIGINT;
    chunk_window         SMALLINT = 3;
    calculated_intervals BIGINT[];
BEGIN
    -- Get the dimension corresponding to the given dimension ID
    SELECT *
    INTO STRICT dimension_row
    FROM _timescaledb_catalog.dimension
    WHERE id = dimension_id;

    -- Get a window of most recent chunks
    FOR chunk_row IN
    SELECT * FROM _timescaledb_catalog.chunk c
    WHERE c.hypertable_id = dimension_row.hypertable_id
    ORDER BY c.id DESC LIMIT chunk_window
    LOOP
        DECLARE
            dimension_slice_row     _timescaledb_catalog.dimension_slice;
            chunk_relid             REGCLASS = format('%I.%I', chunk_row.schema_name, chunk_row.table_name)::regclass;
            max_dimension_value     BIGINT;
            min_dimension_value     BIGINT;
            chunk_interval          BIGINT;
            interval_fraction       FLOAT;
            chunk_size              BIGINT;
            extrapolated_chunk_size BIGINT;
            new_interval_length     BIGINT;
            chunk_size_fraction     FLOAT;
        BEGIN

        -- Get the chunk's min and max value for the dimension we are looking at
        EXECUTE format(
            $$
            SELECT _timescaledb_internal.to_internal_time(min(%1$I)),
                   _timescaledb_internal.to_internal_time(max(%1$I)) FROM %2$I.%3$I
            $$,
            dimension_row.column_name,
            chunk_row.schema_name,
            chunk_row.table_name
        ) INTO STRICT min_dimension_value, max_dimension_value;

        -- Get the chunk's slice for the given dimension
        SELECT * INTO STRICT dimension_slice_row
        FROM _timescaledb_catalog.dimension_slice s
        INNER JOIN _timescaledb_catalog.chunk_constraint cc
        ON (cc.dimension_slice_id = s.id)
        WHERE s.dimension_id = calculate_chunk_interval.dimension_id
        AND cc.chunk_id = chunk_row.id;

        SELECT * FROM pg_total_relation_size(chunk_relid)
        INTO STRICT chunk_size;

        -- Calculate the chunk's actual interval in the
        -- dimension. This might be different from the interval we set
        -- because of chunk collisions and cutting when setting the
        -- new interval.
        chunk_interval = dimension_slice_row.range_end - dimension_slice_row.range_start;

        -- Only change the interval if the previous chunk had an
        -- interval that is more than some threshold of the interval
        -- set for the dimension. A change in interval typically
        -- involves cuts in the chunk created immediately following
        -- the change due to collisions with previous chunks since all
        -- ranges are calculated from time epoch 0 irrespective of
        -- interval.
        IF (chunk_interval::FLOAT / dimension_row.interval_length) > 0.98 THEN
            interval_fraction := (max_dimension_value - min_dimension_value)::FLOAT / chunk_interval;

            -- Extrapolate the chunk relation size to the size the it
            -- would have if fully filled
            extrapolated_chunk_size := chunk_size + ((1.0 - interval_fraction) * chunk_size)::BIGINT;

            -- Now calculate the current size's fraction of the target size
            chunk_size_fraction := extrapolated_chunk_size::FLOAT / chunk_target_size;

            -- Apply some dampening. Do not change the interval if we
            -- are close to the target size or the previous chunk was
            -- partially filled
            IF interval_fraction > 0.7 AND abs(1.0 - chunk_size_fraction) > 0.15 THEN
                new_interval_length := (dimension_row.interval_length / chunk_size_fraction)::BIGINT;
                calculated_intervals := array_append(calculated_intervals, new_interval_length);
            END IF;
        END IF;
        END;
    END LOOP;

    chunk_interval = array_avg(calculated_intervals);

    IF chunk_interval IS NULL THEN
        RETURN -1;
    END IF;

    RETURN chunk_interval;
END
$BODY$;
