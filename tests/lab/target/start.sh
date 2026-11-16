#!/bin/sh
# Starts each service named in $SERVICES, then waits; one that fails to start does not stop the others.
# quill is the invented local account Hydra finds over ssh and ftp.
adduser -D quill && echo 'quill:Ink-Well-4' | chpasswd
for service in $SERVICES; do
    case "$service" in
        ssh) /usr/sbin/sshd ;;
        http) nginx ;;
        ftp)
            printf 'listen=YES\nanonymous_enable=YES\nlocal_enable=YES\nanon_root=/srv/ftp\nbackground=YES\nseccomp_sandbox=NO\nftpd_banner=Lab FTP ready\n' \
                > /etc/vsftpd/lab.conf
            vsftpd /etc/vsftpd/lab.conf ;;
        telnet) telnetd -l /bin/login ;;
        smtp)
            postconf -e "inet_interfaces = all" "myhostname = lab-web.lab.test" "mydestination = lab-web.lab.test"
            newaliases
            postfix start ;;
        smb)
            printf '[global]\nworkgroup = TROVELAB\nnetbios name = LAB-FILES\nserver role = standalone server\nmap to guest = Bad User\n[public]\npath = /srv/share\nguest ok = yes\n' \
                > /etc/samba/smb.conf
            smbd -D ;;
        dns)
            dnsmasq --no-resolv --no-hosts --address=/lab-web.lab.test/10.99.56.10 \
                --address=/lab-files.lab.test/10.99.56.11 --address=/lab-cache.lab.test/10.99.56.12 ;;
        snmp)
            printf 'agentAddress udp:0.0.0.0:161\nrocommunity public\nsysDescr Trove lab SNMP agent\nsysName lab-files\n' > /etc/snmp/snmpd.conf
            snmpd -C -Lo -c /etc/snmp/snmpd.conf ;;
        ntp)
            printf 'allow all\nlocal stratum 8\n' > /etc/chrony/chrony.conf
            chronyd -x ;;
        redis) redis-server --protected-mode no --daemonize yes ;;
        memcached) memcached -u nobody -d -U 11211 ;;
        *) echo "unknown service: $service" >&2; exit 1 ;;
    esac
done
exec tail -f /dev/null
