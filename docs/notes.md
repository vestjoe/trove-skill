# Notes and finding status

`/loot-note` saves a note with origin `you`. The agent then reads it like any other file and may extract records from it.

```
/loot-note "check the SQL Server on castelblack with rickon.stark" --host 192.168.56.22 --tag todo
```

Find tagged notes later with `/loot-find --type note --where tags=todo`.

A finding's status is one of `open`, `confirmed`, `failed`, `remediated` or `false_positive`. A tool sets a finding's status when it creates it: `confirmed` for a weakness it saw, `failed` for a login or operation the target refused. A finding the agent read from a note starts `open`. After that, only you change a status. Ask the agent, for example "set finding:… to confirmed", and Trove records the change with origin `you`.

![A parser sets a finding's status to confirmed or failed, and the agent sets open for a finding from a note. You can set any status with loot set.](assets/diagrams/finding-status-light.svg#only-light)
![A parser sets a finding's status to confirmed or failed, and the agent sets open for a finding from a note. You can set any status with loot set.](assets/diagrams/finding-status-dark.svg#only-dark)
