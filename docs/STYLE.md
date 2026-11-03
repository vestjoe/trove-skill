# Trove documentation style guide

This guide covers the language of the pages in `docs/` that the site publishes. It draws on the Google developer documentation style guide, the Microsoft Writing Style Guide, the US federal plain language guidelines and Wikipedia's list of signs of AI-generated writing. Where those sources disagree, this guide picks one rule so the pages stay consistent.

Check a page against the [review checklist](#review-checklist) before you open a pull request.

## Who reads the docs

The reader is an operator working in a CTF or training lab. They know the security tools and want to get a task done or look something up. They read in a hurry and often scan for a command or a field name. Many read English as a second language.

Write for that reader: say what to do and what happens, in plain words, and stop.

## Grammar

### Address the reader as "you"

Write in the second person. Don't write "we", "our" or "let's".

| Write | Don't write |
|---|---|
| Import the potfile after the dump that holds the hashes. | We recommend importing the potfile after the dump. |

### Use active voice

Name who does the action: you, Trove, the agent, a parser or the tool. Passive voice hides the actor and makes the reader guess.

| Write | Don't write |
|---|---|
| The CLI refuses two different values. | Two different values are refused. |
| Don't add the per-file counts together. | The per-file counts are not summed. |

Use passive voice only when the actor is unknown or doesn't matter to the reader, for example "Someone may have renamed the account with RID 500."

### Use present tense

Describe what Trove does now, in the present tense. Use "will" only for something that happens later in time, such as a step that runs after the current one. Don't use "would" for ordinary behaviour.

| Write | Don't write |
|---|---|
| The import report lists what Trove kept. | The import report will list what Trove kept. |

### Write instructions as commands

Start each step with a verb in the imperative. Don't add "please", "you can" or "you should" when the plain command says the same thing.

| Write | Don't write |
|---|---|
| Restart OpenCode or Claude Code. | You should restart OpenCode or Claude Code. |

### Put the condition or goal first

When a sentence has a condition or a goal, put it before the instruction. The reader can then skip an instruction that doesn't apply.

| Write | Don't write |
|---|---|
| To pick a different engagement, name it in your request. | Name it in your request if you want to pick a different engagement. |
| Over a VPN, lower `-rate`. | Lower `-rate` when you are on a VPN. |

### Keep the normal sentence order

Put the subject first, then the verb, then the object. A backward sentence makes the reader hold words in mind until the part that matters arrives. Avoid these shapes:

- Inverted order: "Neither does a failed login" becomes "A failed login makes no credential either."
- A long lead-in before the subject: "Per file, with the parser and the records it touched, the report gives…" becomes "The report gives each file's parser and the records it touched."
- An adverb or phrase between the verb and its object: "It refuses by name the fields only a tool observes" becomes "It refuses the fields that only a tool observes, and names each one."
- An empty opening: "There is", "There are", "It is … that", "What X does is". Start with the real subject.

### One idea per sentence

Keep sentences short, about 25 words or fewer. When a sentence joins two ideas with a semicolon, split it into two sentences. When a sentence lists more than four things with their details, use a list or a table.

Write full sentences. Don't write slogans, taglines or fragments such as "Same question, and now the answer also has:". Don't write short aphorisms that sound wise but leave the reader to work out the meaning.

### Use verbs, not nouns made from verbs

| Write | Don't write |
|---|---|
| Trove checks the quote. | Trove performs a check of the quote. |
| Extract the pending files. | Run the extraction of the pending files. |

### Use plain words

Use the short, common word: "use", not "utilize"; "about", not "approximately"; "start", not "initiate"; "help", not "facilitate". Common contractions such as "don't", "isn't" and "doesn't" are fine.

## Words and phrases to avoid

These words and patterns add nothing for the reader. Many of them also mark text as machine-written.

### Banned words

- "cited", "cite", "citing", "citation". Say what the reader sees instead: "names the file", "quotes the line", "gives the record id".
- Hype and puffery: powerful, seamless, robust, comprehensive, cutting-edge, crucial, key (as an adjective), pivotal, vital, essential, leverage, delve, showcase, underscore, testament, journey.
- Words that make a task sound trivial: simply, just, easy, easily, quickly, effortless, of course, obviously.
- Filler: please, please note, note that, it's important to note, it's worth noting, at this time, in order to (write "to"), basically, actually, really.
- Inflated verbs in place of "is" or "has": serves as, stands as, acts as, boasts, features.

### Banned patterns

- **Em dashes and en dashes.** Use a comma, a colon, parentheses or a new sentence. Write a range with "to", for example "ports 1 to 1024".
- **"Not X, but Y" and "X, rather than Y".** Use a contrast only when the reader would otherwise believe X. "That is 'nothing yet', not an error" earns its place, because a reader may take an empty answer for a failure. A contrast added for rhythm does not.
- **Lists of three for rhythm.** List what is true. If two items are true, list two.
- **Trailing "-ing" clauses that claim importance**, such as "…, making it easy to track every value" or "…, ensuring nothing is lost". Cut the clause, or state the fact as its own sentence.
- **Recaps.** Don't end a page or section with a summary of what it said. No "In summary", "In short" or "That's it".
- **Talking to the reader about the page.** Don't write "This page explains" or "In this section". The heading already says what the page covers.
- **Hedging.** Use "may" or "might" only for behaviour that really varies, such as the agent's wording. Don't hedge a fact the code settles.
- **Exclamation marks, emoji, idioms and jokes.**
- **Bold for emphasis in running text.** Use bold only for labels the reader sees on screen (**From the data**) and for the repeated entry labels on a reference page (**Reads:**, **Records:**).

## Focus

### Write about the page's topic

Each page has one job. The site follows the Diátaxis types:

| Page type | Its job | Pages |
|---|---|---|
| Tutorial | Take a new user through one complete task, step by step | `tutorial.md` |
| How-to | Help a user who knows Trove get one task done | `searching.md`, `notes.md`, `troubleshooting.md`, `install.md` |
| Reference | List facts to look up: commands, options, formats | `commands.md`, `tools.md` |
| Explanation | Say how Trove works and why it behaves as it does | `how-it-works.md` |

Keep each page to its job. A how-to doesn't explain design. A reference page doesn't teach. Link to the other page instead.

### Write only what is true and useful

- Describe what the code does today. Don't describe plans, future features or ideas.
- Use real output. Every example comes from a run on `tests/fixtures/` or `tests/corpus/goad/`. Shorten long output with `...`, and don't edit the lines you keep.
- Leave out internals the reader can't act on. The reasons behind a rule go in `docs/SPEC.md` or the commit message.
- Lead with what the reader gets from Trove. Mention where a value came from only when that is the point of the sentence.
- Don't add a section, note or warning that no reader needs.

### Keep terms consistent

Use one term for one thing, and don't swap in synonyms for variety.

| Use | Not |
|---|---|
| engagement | project, case, workspace |
| record | entry, item, object |
| the agent | the AI, the model, the LLM, Claude |
| parser | reader, module (for the code that reads a tool's output) |
| origin (`tool`, `ai`, `you`) | source, provenance |
| source file | origin file, input |
| import report | output, summary |
| AI extraction | AI parsing, AI import |
| pending | queued, waiting (as a state name) |
| refused | rejected, skipped |
| OpenCode or Claude Code | Claude Code or OpenCode, the harness |

## Formatting

### Headings

- Use sentence case: "Verify your install", not "Verify Your Install".
- Don't end a heading with a period or colon.
- Start a how-to heading with a verb ("Search records"). Name a reference heading after the thing ("`find`", "nmap").
- Use one `#` heading per page, then `##` and `###` in order.

### Lists and tables

- Use a numbered list for steps in order and a bulleted list for everything else.
- Keep list items parallel: all full sentences, or all fragments of the same shape.
- End an item that is a full sentence with a period.
- Use a table when each item has the same two or more properties.
- Indent a paragraph, list or code block inside a list item by four spaces. The site's Markdown ends the item at fewer, which breaks the list and restarts its numbering.

### Code and values

- Put commands the reader runs in fenced code blocks, one command per line. Use `sh` for shell and no language for slash commands and output.
- Use inline code for commands, flags, file names, paths, field names, record ids and literal values: `--where`, `raw/`, `admin_hosts`, `confirmed`.
- Write placeholders in angle brackets: `<name>`, `<targets>`.
- Use only the lab hosts, accounts and domains in the fixtures. Never use a real host, credential or client name.

### Punctuation, spelling and numbers

- Use straight quotes (`"` and `'`), not curly quotes.
- Use British spelling, as the rest of the repository does: behaviour, colour, recognise, summarise.
- Leave out the serial comma, as the existing pages do ("hosts, services and findings"), unless a list would be ambiguous without it.
- Use numerals for counts, ports and sizes. Use a comma in numbers of 1,000 and above: "12,000 bytes".
- Give links descriptive text: "see [Search records](searching.md)", not "click [here](searching.md)".

## Review checklist

Before you open a pull request, read the changed text and check:

1. No em dashes or en dashes.
2. No word from the banned list, and no form of "cite".
3. Every sentence names its actor and uses active voice, unless the actor doesn't matter.
4. Instructions start with a verb, and conditions come before them.
5. No backward sentences, no semicolon chains and no fragments.
6. No "not X, but Y" contrast unless the reader would otherwise believe X.
7. No recap, no hype and no talk about the page itself.
8. Each term matches the table above.
9. Every example is real output, and every claim matches what the code does.
10. The page does its one job and nothing else.

## Sources

- [Google developer documentation style guide: highlights](https://developers.google.com/style/highlights), [voice](https://developers.google.com/style/voice), [tone](https://developers.google.com/style/tone), [tense](https://developers.google.com/style/tense) and [clause order](https://developers.google.com/style/clause-order)
- [Microsoft Writing Style Guide: top 10 tips for style and voice](https://learn.microsoft.com/en-us/style-guide/top-10-tips-style-voice)
- [Digital.gov plain language guide: writing](https://digital.gov/guides/plain-language/writing)
- [Wikipedia: Signs of AI writing](https://en.wikipedia.org/wiki/Wikipedia:Signs_of_AI_writing)
- [Diátaxis](https://diataxis.fr/)
