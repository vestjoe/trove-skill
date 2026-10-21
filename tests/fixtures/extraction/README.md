# Extraction corpus

`corpus.jsonl` — one case per line. It is worth being precise about what this
checks, because the obvious reading is the wrong one.

**It is not an accuracy score.** Trove does not judge whether the operator's
data is "good", and it does not grade a model on whether it found the host a
human would have found. Extraction quality is the operator's to assess against
`raw/`, which is why `raw/` is lossless.

**It checks the two things the code is actually responsible for:**

1. every record the pipeline produces is **schema-valid and fully cited** — each
   field carries a `ProvRef` whose bytes, re-read from the blob, still say what
   the record claims;
2. every proposal that *cannot* be cited is **dropped and reported** — invented
   evidence, paraphrased evidence, a severity the model tried to assert, a port
   that is not a number, a host nobody has heard of.

That second half is the point. **Constrained decoding guarantees shape, not
truth**: a model can return perfectly schema-valid JSON naming a port the input
never contained. Half the cases here are that failure, written down.

## A case

```json
{
  "name": "invented-evidence",
  "why":  "what this case is defending",
  "source": "note.md",          // decides the input kind (freeform vs tool-output)
  "kind": null,                 // or force one
  "input": "...",               // the bytes, ingested into raw/ as-is
  "response": {"records": [...]},   // what the model returned, verbatim
  "expect": {"records": [...], "notices": ["substring"]}
}
```

`response` is checked against the real wire schema before anything else, so a
case cannot drift into testing a shape Trove would never accept.

## Growing it

Add a line. Cases are cheap and the corpus is the only place the caveat is
written down as something that runs. When a real model produces a surprising
proposal against a real engagement, paste it in here — a recorded failure is
worth more than an invented one.
