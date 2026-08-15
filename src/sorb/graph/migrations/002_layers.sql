-- The layer transition log — one row per (path, layer) state change
-- (added/modified/removed/opaque-cleared). Powers `state: removed`
-- components and the UI layer stack.
CREATE TABLE file_states (
    id           INTEGER PRIMARY KEY,
    source_id    TEXT,
    path         TEXT,
    layer_digest TEXT,
    ordinal      INT,
    state        TEXT
);
CREATE INDEX ix_file_states_path  ON file_states(source_id, path);
CREATE INDEX ix_file_states_layer ON file_states(layer_digest);
