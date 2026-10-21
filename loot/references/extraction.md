# AI extraction

Use this when `loot import` or `loot pending` lists a file that needs AI
extraction. You read the text and propose records; the CLI keeps only the
fields whose quotes it finds in the file.

A blob named `<file> (lines not read by <parser>)` holds only the lines of a
tool file that were not that tool's output, such as prose pasted around a
scan or the command that ran the tool. The parser already read the rest;
quote these lines as they are. A password or hash given on a command line
(`-p 'Winter2024!'`, `user:pw@host`, `-H <hash>`) is a credential with state
`found`; its value leaves out the shell's quotes around it.

## Steps

1. `loot pending`. It lists each blob id and how many chunks are left.
2. For each blob, repeat until the reply says the file is done:
   `loot raw <blob>` prints the next chunk without a proposal.
3. Write one proposal for that chunk and pipe it in (an empty
   `{"records": []}` if the chunk holds nothing); the reply names the next
   chunk or says the file is done:

```sh
loot ingest-ai <blob> <<'JSON'
{"records": [
  {"type": "host",
   "fields": {"ip": {"value": "10.10.10.5", "evidence": "web01 (10.10.10.5)"},
              "hostnames": {"value": ["web01"], "evidence": "web01 (10.10.10.5)"}}},
  {"type": "credential",
   "fields": {"principal": {"value": "svc_backup", "evidence": "svc_backup creds work over SMB"}}}
]}
JSON
```

4. Read the reply. It says how many records were kept and why each dropped
   field was dropped. If the JSON was malformed, fix it and send it again.
   Don't resend fields that were dropped for their evidence.
5. Tell the user what was kept and what was dropped.

## Writing a proposal

- **evidence** is copied exactly from the text: same words, same spelling,
  same punctuation. Don't summarise or fix it. Short is fine; 3–12 words is
  typical. Matching ignores whitespace differences (spaces, tabs, line
  breaks), so evidence that wraps across lines is fine; nothing else is
  loosened.
- **value** must appear inside its own evidence for names, addresses, ports,
  usernames, passwords and hashes. If the text doesn't state it, leave the
  field out.
- One record per thing the text states. Leave out what it only implies.
- `host` (or `host_id`) is the host's IP address, or a hostname the evidence
  states that exactly one host Trove already holds carries; otherwise the link
  is dropped. A new host's name goes in `hostnames` of a `host` record.
- Never propose `severity`.
- Copy passwords, hashes, account names and hostnames with their exact case;
  a value that differs in case from its evidence is dropped. A plain hex hash
  (NT, LM) is the exception: any case is the same hash.
- Copy a password whole, character for character, including trailing `!`, `.`
  or spaces inside it. A password cut short or spaced differently from its
  evidence is dropped.
- A credential's `state` may only be `found`. Whether it was cracked or worked
  comes from tool output, so `cracked` or `confirmed` is dropped.
- A finding's `status` is `open` (or left out, which means `open`): only a
  tool or the user confirms a finding. Put your view in `suggested_status`
  (`open`, `confirmed`, `remediated` or `false_positive`), with the words that
  justify it as evidence. Anything else is dropped.
- A password or hash written with no account (a list of passwords, "the
  wifi key is X") is a credential with principal `(Unknown User)`, one record
  per password; never guess an account for it.
- A credential's `host` is the host its secret was taken from, and it must
  appear in its evidence like any other value.

## Types and fields

| type | fields (first is required) |
|---|---|
| host | ip, hostnames (list), os, state |
| service | host (IP or held hostname), port (required too), protocol (tcp/udp), name, product, version, state |
| credential | principal, realm, secret, secret_hash, hash_type, state, source, host (the host it was taken from) |
| principal | principal, realm, sid |
| group | name, realm, sid |
| share | host (IP or held hostname), name (required too), permissions, remark |
| finding | title, description, host (IP or held hostname), status (only `open`), suggested_status |
| note | text, tags (list), host (IP or held hostname) |
