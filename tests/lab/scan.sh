#!/bin/sh
# Runs inside the scanner container: every masscan, naabu and nmap output format, into /out.
set -u
HOSTS="10.99.56.10 10.99.56.11 10.99.56.12"
NAMES="lab-web.lab.test lab-files.lab.test lab-cache.lab.test"
SPARE=10.99.56.250
LAB_PORTS=21,22,23,25,53,80,123,139,161,443,445,6379,8080,11211
cd /out
run() { echo "\$ $*" >> commands.txt; "$@" || echo "  exit $?" >> commands.txt; }

: > commands.txt
masscan --version | head -2 >> commands.txt
naabu -version 2>&1 | tail -1 | sed 's/\x1b\[[0-9;]*m//g' >> commands.txt
nmap --version | head -1 >> commands.txt

run masscan $(echo $HOSTS | tr ' ' ',') -p1-65535,U:53,U:123,U:161,U:11211 --banners --source-ip $SPARE \
    --rate 2000 --wait 5 -oB masscan.bin
for format in X G L J D; do
    case $format in X) ext=xml ;; G) ext=gnmap ;; L) ext=txt ;; J) ext=json ;; D) ext=ndjson ;; esac
    run masscan --readscan masscan.bin -o$format masscan.$ext
done
run masscan $(echo $HOSTS | tr ' ' ',') -p21-25,53,80,443,445,6379,8080,U:161 --banners --source-ip $SPARE \
    --rate 2000 --wait 5 > masscan-screen.txt 2>&1

run naabu -host $(echo $HOSTS | tr ' ' ',') -p $LAB_PORTS -silent -json -o naabu.json
run naabu -host $(echo $NAMES | tr ' ' ',') -r 10.99.56.11 -p $LAB_PORTS -silent -json -o naabu-names.json
run naabu -host $(echo $HOSTS | tr ' ' ',') -p $LAB_PORTS -silent -o naabu.txt
run naabu -host $(echo $HOSTS | tr ' ' ',') -p $LAB_PORTS -silent -sV -json -o naabu-sv.json
run naabu -host $(echo $HOSTS | tr ' ' ',') -p $LAB_PORTS -silent -sV -oX naabu.xml -oG naabu.gnmap
run naabu -host $(echo $HOSTS | tr ' ' ',') -p u:53,u:123,u:161,u:11211 -silent -json -o naabu-udp.json

run nmap -sV -sC -p $LAB_PORTS -oA nmap-full $HOSTS
run nmap -sU -sV -p53,123,161,11211 -oA nmap-udp $HOSTS
