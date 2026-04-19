# Adding payloads — [Phase 3+]

The payload schema lands in Phase 3. Shape of each YAML entry:

```yaml
- id: sqli-union-001
  class: sqli              # sqli | xss | cmdi | lfi | ssti | xxe
  payload: "' UNION SELECT null,version()-- -"
  expected_trigger: regex  # or: response_code | content_contains
  cwe: CWE-89
  source: "PayloadsAllTheThings / sqli/union.txt"
  notes: "Classic union-based SQLi against DVWA 'id' param."
```

Destructive payloads are rejected at load time. See `engine/src/payloads/` once it exists.
