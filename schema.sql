PRAGMA foreign_keys = ON;

CREATE TABLE vendors (
    id   INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE products (
    id        INTEGER PRIMARY KEY,
    vendor_id INTEGER NOT NULL REFERENCES vendors(id),
    name      TEXT NOT NULL,
    UNIQUE (vendor_id, name)
);

CREATE TABLE versions (
    id         INTEGER PRIMARY KEY,
    product_id INTEGER NOT NULL REFERENCES products(id),
    version    TEXT NOT NULL,
    UNIQUE (product_id, version)
);

CREATE TABLE vulnerabilities (
    id                 INTEGER PRIMARY KEY,
    product_id         INTEGER NOT NULL REFERENCES products(id),
    kla_id             TEXT NOT NULL,
    description        TEXT,
    publish_date       TEXT,
    start_vuln_version TEXT NOT NULL,
    fixed_version      TEXT NOT NULL,
    UNIQUE (product_id, kla_id, start_vuln_version, fixed_version)
);

CREATE INDEX idx_versions_product ON versions(product_id);
CREATE INDEX idx_vulns_product    ON vulnerabilities(product_id);
CREATE INDEX idx_vulns_kla        ON vulnerabilities(kla_id);
