# Records

What `loot find` prints. Use this to read its output and to cite it.

## Types

| type | fields | id |
|---|---|---|
| host | ip, hostnames (list), os, state | `host:<ip>` |
| service | host_id, port, protocol, name, product, version, banner, state | `service:<ip>-<proto>-<port>` |
| credential | principal, realm, secret, secret_hash, hash_type, state, source, host_id (list), hosts (list), admin_hosts (list), keys (list) | `credential:<realm>\<principal>-<8 hex>` (realm and suffix only when known) |
| principal | principal, realm, sid | `principal:<realm>\<principal>` |
| group | name, realm, dn, sid | `group:<realm>\<name>` |
| share | host_id, name, permissions, remark | `share:<ip>-<name>` |
| finding | title, description, host_id, service_id, status | `finding:<slug>-<8 hex>` |
| note | text, tags (list), host_id | `note:<8 hex>` |
| relationship | src_id, kind (`member_of`), dst_id | `rel:<src>-member_of-<dst>` |

An id is the record's name: quote it exactly when you cite a record. Ids of
principals and groups are lower case.

- A **host** lists its services under `services` in `find` output.
  `find --where host=<ip>` returns the host record itself and every record
  linked to it: services, shares, findings, notes and the credentials that
  worked there. A hostname works in place of the IP (`host=dc01`).
- A **credential** is one account's one password: its hashes, the crack and
  the logins with it are one record. `state` is `found` (seen in a file),
  `confirmed` (a login worked with it) or `cracked` (its hash was cracked; a
  cracked password that then worked stays `cracked`). `hosts` lists the
  hosts a NetExec login worked on, each cited to its login line. `host_id`
  is the host the secret was taken from, not one it worked on: the machine a
  SAM dump names in `$MACHINE.ACC` (its local accounts take that machine's
  name as their realm), the host a NetExec `--sam` or `--ntds` line was printed
  for, or the client Responder heard a hash from (`find --where host=<ip>` searches
  it). A NetExec pass-the-hash login is the NT hash in `secret_hash`, not a
  password. `admin_hosts` lists the hosts where that login showed `(Pwn3d!)`,
  each cited to its line (`find --where admin_hosts=<ip>`). A credential
  without `hosts` was not seen working anywhere, and one without
  `admin_hosts` was not seen with admin access: don't infer either from the
  file it came from.
  `keys` lists the account's Kerberos keys from a secretsdump, each as
  `<etype>:<hex>` cited to its line (`find --where keys~aes256`).
- **Group membership** is a `relationship`: `src_id` is the member,
  `dst_id` the group.
- `ext` holds other things a parser saw (for example `os_accuracy`). It is
  searchable as free text but has no citation.

## Citations and origins

Each field prints with its origin and the file it came from:
`[tool, nmap/scan.xml]`, sometimes followed by the exact quote.

| origin | means |
|---|---|
| `tool` | a parser read it from the file |
| `ai` | the agent proposed it during extraction and its quote was found in the file |
| `you` | the user wrote it (`loot note`) |

When a value matters, say its origin if it is `ai`: it came from reading
prose, not from a parser.

## Merge rules

Writing a record whose id already exists merges into it:

- A field from `you` is never overwritten.
- `tool` overwrites `ai`; `ai` never overwrites `tool`.
- Otherwise the later non-empty value wins.
- List fields (hostnames, tags, hosts, admin_hosts, keys) are combined.
- A cracked hash fills `secret` on the credential with that hash and sets its
  state to `cracked`, whichever file arrives first.
- A state never moves down: `cracked` over `confirmed` over `found`.

There is no severity field. A nuclei finding keeps nuclei's stated severity in
`ext.severity`; quote it as nuclei's. Never add one of your own in an answer.
