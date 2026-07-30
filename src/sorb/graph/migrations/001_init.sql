-- Run-store schema v1
CREATE TABLE meta       (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE sources    (id TEXT PRIMARY KEY, kind TEXT, ref TEXT, provenance TEXT);
CREATE TABLE layers     (digest TEXT PRIMARY KEY, source_id TEXT, ordinal INT, created_by TEXT);
CREATE TABLE files      (id INTEGER PRIMARY KEY, source_id TEXT, path TEXT,
                         digest TEXT, size INT, role TEXT, coords TEXT);
CREATE TABLE findings   (id INTEGER PRIMARY KEY, claim TEXT, detector TEXT,
                         component_id INTEGER);
CREATE TABLE evidence   (id INTEGER PRIMARY KEY, finding_id INT, technique TEXT, tier INT,
                         detector TEXT, location TEXT, captured TEXT, confidence REAL,
                         modifiers TEXT);
CREATE TABLE components (id INTEGER PRIMARY KEY, purl TEXT, ctype TEXT, name TEXT,
                         version TEXT, qualifiers TEXT, hashes TEXT,
                         confidence REAL, tier_cap INT, attrs TEXT);
CREATE TABLE edges      (id INTEGER PRIMARY KEY, kind TEXT, src INT, dst INT,
                         attrs TEXT, evidence_ids TEXT);
CREATE TABLE annotations(id INTEGER PRIMARY KEY, subject_kind TEXT, subject_id INT,
                         code TEXT, detail TEXT, attrs TEXT);
CREATE TABLE projects   (id INTEGER PRIMARY KEY, source_id TEXT, path TEXT, name TEXT, kind TEXT);
CREATE TABLE resources  (id INTEGER PRIMARY KEY, rtype TEXT, name TEXT, attrs TEXT);

CREATE INDEX ix_components_purl ON components(purl);
CREATE INDEX ix_components_name ON components(name);
CREATE INDEX ix_files_digest    ON files(digest);
CREATE INDEX ix_files_path      ON files(source_id, path);
CREATE INDEX ix_edges_src       ON edges(kind, src);
CREATE INDEX ix_edges_dst       ON edges(kind, dst);
CREATE INDEX ix_evidence_find   ON evidence(finding_id);
CREATE INDEX ix_findings_comp   ON findings(component_id);
CREATE INDEX ix_annotations_sub ON annotations(subject_kind, subject_id);
