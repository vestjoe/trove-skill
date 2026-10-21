-- Responder v3.2.2.0 Responder.db, the tables utils.py CreateResponderDb declares; invented lab rows.
CREATE TABLE Poisoned (timestamp TEXT, Poisoner TEXT, SentToIp TEXT, ForName TEXT, AnalyzeMode TEXT);
CREATE TABLE responder (timestamp TEXT, module TEXT, type TEXT, client TEXT, hostname TEXT, user TEXT, cleartext TEXT, hash TEXT, fullhash TEXT);
CREATE TABLE DHCP (timestamp TEXT, MAC TEXT, IP TEXT, RequestedIP TEXT);

INSERT INTO Poisoned VALUES ('2026-10-17 09:20:11', 'LLMNR', '192.168.56.25', 'riverrun', '0');
INSERT INTO Poisoned VALUES ('2026-10-17 09:31:40', 'NBT-NS', '192.168.56.26', 'GREYWATER', '0');
INSERT INTO responder VALUES ('2026-10-17 09:21:02', 'SMB', 'NTLMv2-SSP', '192.168.56.25', '', 'NORTH\meera.reed', '', '5ae8c693a2a59f543552dc884fe7a187:01010000000000008e72f7bfa0c9ba21bf50376cffc6c982758becf06d624b8697e4645553493fc6400bf3d8b9ae5cd65eee82b005196c6aef70bb081f74ded684f4b018e0b209247312cb89628abb3665fa6253543e68dc', 'meera.reed::NORTH:438a58b2bd844ad9:5ae8c693a2a59f543552dc884fe7a187:01010000000000008e72f7bfa0c9ba21bf50376cffc6c982758becf06d624b8697e4645553493fc6400bf3d8b9ae5cd65eee82b005196c6aef70bb081f74ded684f4b018e0b209247312cb89628abb3665fa6253543e68dc');
INSERT INTO responder VALUES ('2026-10-17 09:31:44', 'SMB', 'NTLMv2-SSP', '192.168.56.26', '', 'NORTH\jojen.reed', '', '9c1e4f0b7d2a6e83b5f41c07a9d3e268:0101000000000000a3c1f7bfa0c9ba21', 'jojen.reed::NORTH:7d3e91a0c4b2f856:9c1e4f0b7d2a6e83b5f41c07a9d3e268:0101000000000000a3c1f7bfa0c9ba2155e2a0d4c81b9f3e0000000002000a004e004f00520054004800');
INSERT INTO responder VALUES ('2026-10-17 09:40:12', 'HTTP', 'Basic', '192.168.56.27', '', 'hodor', 'HoldTheDoor!', '', '');
INSERT INTO responder VALUES ('2026-10-17 09:44:30', 'SMB', 'NTLMv2-SSP', '192.168.56.28', '', 'NORTH\gilly', '', 'truncated', 'gilly::NORTH:truncated');
