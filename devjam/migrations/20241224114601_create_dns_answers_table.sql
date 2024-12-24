-- Add migration script here

CREATE TABLE dns_answers (
    domain_name VARCHAR NOT NULL,
    ttl INTEGER NOT NULL,
    record_type VARCHAR NOT NULL,
    read_from_buffer_ts TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (domain_name, record_type)
);
