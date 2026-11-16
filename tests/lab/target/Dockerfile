FROM alpine:3.20

RUN apk add --no-cache openssh nginx openssl vsftpd busybox-extras postfix samba dnsmasq net-snmp chrony \
        redis memcached \
 && ssh-keygen -A \
 && openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=lab-web.lab.test/O=Trove test lab" \
        -keyout /etc/nginx/lab.key -out /etc/nginx/lab.crt \
 && mkdir -p /srv/www /srv/ftp /srv/share \
 && printf '<html><head><title>Trove Lab Portal</title></head><body>lab</body></html>\n' > /srv/www/index.html

COPY nginx.conf /etc/nginx/http.d/default.conf
COPY start.sh /start.sh
CMD ["/bin/sh", "/start.sh"]
