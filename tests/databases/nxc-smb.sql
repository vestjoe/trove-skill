-- NetExec v1.5.1 smb.db, the tables nxc/protocols/smb/database.py declares; invented lab rows.
CREATE TABLE hosts (id INTEGER NOT NULL, ip VARCHAR, hostname VARCHAR, domain VARCHAR, os VARCHAR, dc BOOLEAN, smbv1 BOOLEAN, signing BOOLEAN, spooler BOOLEAN, zerologon BOOLEAN, petitpotam BOOLEAN, PRIMARY KEY (id), UNIQUE (ip));
CREATE TABLE conf_checks (id INTEGER NOT NULL, name VARCHAR, description VARCHAR, PRIMARY KEY (id));
CREATE TABLE conf_checks_results (id INTEGER NOT NULL, host_id INTEGER, check_id INTEGER, secure BOOLEAN, reasons VARCHAR, PRIMARY KEY (id), FOREIGN KEY(host_id) REFERENCES hosts (id), FOREIGN KEY(check_id) REFERENCES conf_checks (id));
CREATE TABLE users (id INTEGER NOT NULL, domain VARCHAR, username VARCHAR, password VARCHAR, credtype VARCHAR, pillaged_from_hostid INTEGER, PRIMARY KEY (id), FOREIGN KEY(pillaged_from_hostid) REFERENCES hosts (id));
CREATE TABLE groups (id INTEGER NOT NULL, domain VARCHAR, name VARCHAR, rid VARCHAR, member_count_ad INTEGER, last_query_time VARCHAR, PRIMARY KEY (id));
CREATE TABLE admin_relations (id INTEGER NOT NULL, userid INTEGER, hostid INTEGER, PRIMARY KEY (id), FOREIGN KEY(userid) REFERENCES users (id), FOREIGN KEY(hostid) REFERENCES hosts (id));
CREATE TABLE group_relations (id INTEGER NOT NULL, userid INTEGER, groupid INTEGER, PRIMARY KEY (id), FOREIGN KEY(userid) REFERENCES users (id), FOREIGN KEY(groupid) REFERENCES groups (id));
CREATE TABLE shares (id INTEGER NOT NULL, hostid INTEGER, userid INTEGER, name VARCHAR, remark VARCHAR, read BOOLEAN, write BOOLEAN, PRIMARY KEY (id), FOREIGN KEY(hostid) REFERENCES hosts (id), FOREIGN KEY(userid) REFERENCES users (id), UNIQUE (hostid, userid, name));
CREATE TABLE loggedin_relations (id INTEGER NOT NULL, userid INTEGER, hostid INTEGER, PRIMARY KEY (id), FOREIGN KEY(userid) REFERENCES users (id), FOREIGN KEY(hostid) REFERENCES hosts (id));
CREATE TABLE dpapi_secrets (id INTEGER NOT NULL, host VARCHAR, dpapi_type VARCHAR, windows_user VARCHAR, username VARCHAR, password VARCHAR, url VARCHAR, PRIMARY KEY (id), UNIQUE (host, dpapi_type, windows_user, username, password, url));
CREATE TABLE dpapi_backupkey (id INTEGER NOT NULL, domain VARCHAR, pvk VARCHAR, PRIMARY KEY (id), UNIQUE (domain));

INSERT INTO hosts VALUES (1, '10.10.10.23', 'DREADFORT', 'north.acme.local', 'Windows Server 2019 Standard 17763 x64', NULL, 0, 0, NULL, NULL, NULL);
INSERT INTO hosts VALUES (2, '10.10.10.24', 'KARHOLD', 'north.acme.local', 'Windows 10 / Server 2019 Build 17763 x64', NULL, 1, 1, NULL, NULL, NULL);
INSERT INTO hosts VALUES (3, '192.168.56.31', 'OLDBOX', 'lab.example', 'Windows Server 2016 Standard 14393 x64', NULL, 0, 1, NULL, NULL, NULL);

INSERT INTO users VALUES (1, 'north.acme.local', 'roose.bolton', 'Flayed!2024', 'plaintext', NULL);
INSERT INTO users VALUES (2, 'north.acme.local', 'ramsay.snow', 'b4b9b02e6f09a9bd760f388b67351e2b', 'hash', NULL);
INSERT INTO users VALUES (3, 'DREADFORT', 'Administrator', 'aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe', 'hash', NULL);
INSERT INTO users VALUES (4, '', 'svc_gpp', 'GPPstillStandingStrong2k18', 'plaintext', NULL);
INSERT INTO users VALUES (5, 'north.acme.local', 'rickon.stark', 'Winter2022', 'plaintext', NULL);

INSERT INTO loggedin_relations VALUES (1, 1, 1);
INSERT INTO loggedin_relations VALUES (2, 1, 2);
INSERT INTO loggedin_relations VALUES (3, 2, 2);
INSERT INTO loggedin_relations VALUES (4, 5, 1);
INSERT INTO admin_relations VALUES (1, 2, 2);

INSERT INTO shares VALUES (1, 'DREADFORT', 1, 'ADMIN$', 'Remote Admin', 0, 0);
INSERT INTO shares VALUES (2, 'DREADFORT', 1, 'flaying', 'Bolton drop box', 1, 1);
INSERT INTO shares VALUES (3, 'DREADFORT', 1, 'IPC$', 'Remote IPC', 1, 0);

INSERT INTO groups VALUES (1, 'DREADFORT', 'Administrators', '544', 2, '2026-10-19 10:12:00');
INSERT INTO dpapi_secrets VALUES (1, '10.10.10.24', 'GOOGLE CHROME', 'KARHOLD\ramsay.snow', 'ramsay', 'Reek!Reek', 'https://intranet.north.acme.local/');
