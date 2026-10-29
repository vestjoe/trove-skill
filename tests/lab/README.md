# Trove test lab

A throwaway Docker network of lab hosts and a scanner container, for capturing
real scanner output to test Trove's parsers against. Nothing here runs in CI.

```
tests/lab/capture.sh
```

builds the images, starts the lab, runs `scan.sh` inside the scanner, writes every
output to `tests/lab/out/` (ignored by git) and tears the lab down. It needs Docker
and takes a few minutes.

| Host | Address | Services |
|---|---|---|
| lab-web | 10.99.56.10 | ssh 22, ftp 21, telnet 23, smtp 25, http 80 and 8080, https 443 |
| lab-files | 10.99.56.11 | smb 139/445, dns 53 (tcp and udp), snmp 161/udp, ntp 123/udp |
| lab-cache | 10.99.56.12 | redis 6379, memcached 11211 (tcp and udp), http 80 and 8080, https 443 |
| scanner | 10.99.56.5 | masscan 1.3.2, naabu 2.7.0, nmap; resolves `*.lab.test` through lab-files |

`10.99.56.250` is left unused for masscan's `--source-ip`.

- **Add a service:** install its package in `target/Dockerfile`, add a case to
  `target/start.sh`, and name it in a host's `SERVICES` in `compose.yaml`.
- **Add a scanner or format:** install it in `scanner/Dockerfile` and add a `run`
  line to `scan.sh`; `run` records the command in `out/commands.txt`.
- **Use a capture in a test:** copy the file into `tests/fixtures/<tool>/` (imported
  by the end-to-end tests) or `tests/samples/<tool>/` (only by the test that names
  it) and add a row to `tests/SOURCES.md` with the command from `commands.txt`.

Lab addresses, names and the self-signed certificate are synthetic; the captures
hold nothing that needs removing before they are committed.
