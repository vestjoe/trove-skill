# Search records

`/loot-find` takes plain words, which must all appear in a record, and filters, alone or with words:

| Filter | Example |
|---|---|
| `--type <type>` (repeatable) | `--type credential` |
| `--where field=value` (repeatable, all must match) | `--where port=445` |
| `--origin tool\|ai\|you` | `--origin ai` |

`--where` operators:

| Operator | Means | Example |
|---|---|---|
| `field=a,b` | equals any of | `port=139,445` |
| `field!=value` | not equal | `state!=open` |
| `field>n`, `field<n` | greater, less | `port<1024` |
| `field~text` | contains | `product~IIS` |
| `field?` | has a value | `admin_hosts?` |
| `field!` | has no value | `secret!` |

`host` means `host_id` and takes an IP or a hostname, so `--where host=castelblack` returns the host and everything linked to it.

Fields by type:

| Type | Fields |
|---|---|
| host | ip, hostnames, os, state |
| service | host_id, port, protocol, name, product, version, banner, state |
| credential | principal, realm, secret, secret_hash, hash_type, state, source, host_id, hosts, admin_hosts, keys |
| principal | principal, realm, sid |
| group | name, realm, dn, sid |
| share | host_id, name, permissions, remark |
| finding | title, description, host_id, service_id, status, suggested_status |
| note | text, tags, host_id |
| relationship | src_id, kind, dst_id |

A protocol's common name (smb, rdp, winrm, mssql, ldap, kerberos, http, ssh, ftp, dns) also finds the services that speak it, so `/loot-find smb` works.
