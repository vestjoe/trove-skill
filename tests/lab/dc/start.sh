#!/bin/sh
# Provisions the lab domain arbor.lab.test with its invented accounts on first start, then runs Samba.
set -eu
if [ ! -f /var/lib/samba/private/sam.ldb ]; then
    rm -f /etc/samba/smb.conf
    samba-tool domain provision --realm=ARBOR.LAB.TEST --domain=ARBOR --server-role=dc \
        --dns-backend=SAMBA_INTERNAL --adminpass='Arbor-Admin-26' --host-name=lab-dc \
        --option='dns forwarder = 10.99.56.11' --option='vfs objects = dfs_samba4'
    samba-tool domain passwordsettings set --complexity=off --min-pwd-length=1 --history-length=0 \
        --min-pwd-age=0 --max-pwd-age=0
    samba-tool user create rowan.ash 'Spring-Lab-26'
    samba-tool user create alder.fern 'Spring-Lab-26' --must-change-at-next-login
    samba-tool user create hazel.birch 'Birch:Bark9'
    samba-tool user create willow.reed 'Not-In-Any-List-41'
    samba-tool user create elm.stone 'Spring-Lab-27'
    # Samba's KDC asks for preauth when krbtgt or the KDC config does; Windows looks only at the account.
    for account in hazel.birch krbtgt; do python3 /lab.py nopreauth "$account"; done
    cp /var/lib/samba/private/krb5.conf /etc/krb5.conf
    printf '[kdc]\n\trequire-preauth = false\n' >> /etc/krb5.conf
fi
touch /ready
exec samba -i --debug-stdout
