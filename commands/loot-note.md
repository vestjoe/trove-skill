---
description: Save a note in the current Trove engagement (add --host IP|name or --tag T)
---
Use the `loot` skill. Save this note: $ARGUMENTS

Run `{{LOOT}} note "<the note text>"`, quoting only the text. If the arguments include `--host <ip or hostname>` or `--tag <t>`, pass those as flags after the quoted text, not inside it. Report the note id.
If the output says the note is pending AI extraction, extract from that blob now by following the skill's references/extraction.md, then report what was kept and dropped.
