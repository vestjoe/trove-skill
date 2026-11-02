# Notes and finding status

`/loot-note` saves a note with origin `you`. The agent then reads it like any other file and may extract records from it.

```
/loot-note "check the SQL Server on castelblack with rickon.stark" --host 192.168.56.22 --tag todo
```

Find tagged notes later with `/loot-find --type note --where tags=todo`.

A finding's status is one of `open`, `confirmed`, `failed`, `remediated` or `false_positive`. A tool's finding is `confirmed` when the tool saw it; a finding the agent read from a note starts `open`. Only you change a status, by asking, for example: "set finding:… to confirmed". The change is recorded with origin `you`.
