-- NetExec v1.5.1 ldap.db, the tables nxc/protocols/ldap/database.py declares; invented lab rows.
CREATE TABLE users (id INTEGER NOT NULL, domain VARCHAR, username VARCHAR, password VARCHAR, credtype VARCHAR, pillaged_from_hostid INTEGER, PRIMARY KEY (id));
CREATE TABLE hosts (id INTEGER NOT NULL, ip VARCHAR, hostname VARCHAR, domain VARCHAR, os VARCHAR, signing_required BOOLEAN, channel_binding VARCHAR, PRIMARY KEY (id));

INSERT INTO hosts VALUES (1, '10.10.10.23', 'DREADFORT', 'north.acme.local', 'Windows Server 2019 Standard 17763 x64', 0, 'Never');
INSERT INTO users VALUES (1, 'north.acme.local', 'roose.bolton', 'Flayed!2024', 'plaintext', NULL);
