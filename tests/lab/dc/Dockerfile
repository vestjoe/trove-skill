FROM alpine:3.20

RUN apk add --no-cache samba-dc krb5
COPY start.sh lab.py /
CMD ["/bin/sh", "/start.sh"]
