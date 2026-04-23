# Adding payloads

The payload schema is finalised in Phase 3 and lives at
`engine/src/wafeval/models.py::Payload`. Shape of each YAML entry:

```yaml
- id: sqli-union-001
  class: sqli              # sqli | xss | cmdi | lfi | ssti | xxe | nosql |
                           # ldap | ssrf | jndi | graphql | crlf | benign
  payload: "' UNION SELECT null,version()-- -"
  trigger:                 # how to confirm baseline fired — see below
    kind: any_of
    any_of:
      - { kind: contains, needle: "First name" }
      - { kind: regex, pattern: "SQLITE_ERROR|syntax error" }
  cwe: CWE-89
  source: "PayloadsAllTheThings / sqli/union.txt"
  notes: "Classic union-based SQLi against DVWA 'id' param."
```

Trigger kinds: `contains`, `regex`, `reflected`, `status`, `any_of`
(see `models.py` for exact fields). Destructive patterns (DROP TABLE,
rm -rf, fork bombs, `/etc/shadow`) are rejected at load time by a
`Payload.payload` field validator.

## Where the files live

`engine/src/wafeval/payloads/<class>.yaml` — one file per vuln class.
The default loader (`load_corpus`) iterates VulnClass and loads
whichever files exist. If you add a new class, add an enum value in
`models.py::VulnClass` and ship the matching YAML.

## Single-file corpora

Some runs need a *fixed* curated subset rather than the full per-class
split — e.g. apples-to-apples paper replication. Drop a standalone file
into the same dir (e.g. `payloads/paper_subset.yaml`), populate it with
self-contained entries, and invoke the engine with
`--corpus paper_subset`. Inside the file, every entry still declares its
`class:` (so `--classes sqli` filters the single-file output too).
Duplicating content from the per-class files is deliberate: a fixed
subset shouldn't drift when the main corpus grows.

The `benign` corpus is a related case — it's loaded via
`--classes benign` rather than `--corpus` because it shares the
per-class-file convention, but it's excluded from default runs because
`VulnClass.BENIGN` is never in the default `[SQLI, XSS]` filter.
