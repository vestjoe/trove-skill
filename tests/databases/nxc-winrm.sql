-- NetExec v1.5.1 winrm.db, the tables nxc/protocols/winrm/database.py declares; invented lab rows.
CREATE TABLE hosts (id INTEGER NOT NULL, ip VARCHAR, port INTEGER, hostname VARCHAR, domain VARCHAR, os VARCHAR, PRIMARY KEY (id));
CREATE TABLE users (id INTEGER NOT NULL, domain VARCHAR, username VARCHAR, password VARCHAR, credtype VARCHAR, pillaged_from_hostid INTEGER, PRIMARY KEY (id), FOREIGN KEY(pillaged_from_hostid) REFERENCES hosts (id));
CREATE TABLE admin_relations (id INTEGER NOT NULL, userid INTEGER, hostid INTEGER, PRIMARY KEY (id), FOREIGN KEY(userid) REFERENCES users (id), FOREIGN KEY(hostid) REFERENCES hosts (id));
CREATE TABLE loggedin_relations (id INTEGER NOT NULL, userid INTEGER, hostid INTEGER, PRIMARY KEY (id), FOREIGN KEY(userid) REFERENCES users (id), FOREIGN KEY(hostid) REFERENCES hosts (id));

INSERT INTO hosts VALUES (1, '10.10.10.24', 5985, 'KARHOLD', 'north.acme.local', 'Windows 10 / Server 2019 Build 17763');
INSERT INTO users VALUES (1, 'north.acme.local', 'roose.bolton', 'Flayed!2024', 'plaintext', NULL);
INSERT INTO loggedin_relations VALUES (1, 1, 1);
INSERT INTO admin_relations VALUES (1, 1, 1);
