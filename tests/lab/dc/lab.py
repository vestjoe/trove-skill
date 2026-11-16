"""Lab helpers on the DC's own database: `nopreauth <account>` sets DONT_REQ_PREAUTH; `ntds` prints
each account as secretsdump's NTDS line (domain\\user:rid:lm:nt:::), the domain from the UPN as secretsdump takes it.
"""
import sys

from samba.auth import system_session
from samba.dcerpc import security
from samba.ndr import ndr_unpack
from samba.param import LoadParm
from samba.samdb import SamDB

BLANK_LM = "aad3b435b51404eeaad3b435b51404ee"
EMPTY_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"

lp = LoadParm()
lp.load_default()
db = SamDB(lp.private_path("sam.ldb"), session_info=system_session(), lp=lp)
if sys.argv[1] == "nopreauth":
    db.toggle_userAccountFlags(f"(sAMAccountName={sys.argv[2]})", 0x400000, "DONT_REQ_PREAUTH", on=True)
else:
    rows = db.search(db.domain_dn(), expression="(&(objectCategory=person)(objectClass=user))",
                     attrs=["sAMAccountName", "objectSid", "unicodePwd", "userPrincipalName"])
    for row in sorted(rows, key=lambda r: ndr_unpack(security.dom_sid, r["objectSid"][0]).split()[1]):
        rid = ndr_unpack(security.dom_sid, row["objectSid"][0]).split()[1]
        name = str(row["sAMAccountName"][0])
        if "userPrincipalName" in row:
            name = str(row["userPrincipalName"][0]).rsplit("@", 1)[1] + "\\" + name
        nt = bytes(row["unicodePwd"][0]).hex() if "unicodePwd" in row else EMPTY_NT
        print(f"{name}:{rid}:{BLANK_LM}:{nt}:::")
