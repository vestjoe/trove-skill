# Pivot notes

svc_backup / Winter2024! works over SMB on 10.10.10.6 and 10.10.10.7.
Same password on the Jetty admin console at 10.10.10.6:8080/tcp - no lockout,
no MFA, and it takes you straight to the deploy screen.

Anonymous FTP is open on 10.10.10.5:21/tcp. Full listing of /pub, nothing
sensitive in it that I could see.

Not yet tried: kerberoasting, the print spooler on dc02.
