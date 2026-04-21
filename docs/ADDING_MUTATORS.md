# Adding a mutator

The mutator plugin interface lands in Phase 3 and is finalised in Phase 4.
Contract:

```python
# engine/src/wafeval/mutators/base.py
class Mutator(ABC):
    category: ClassVar[str]          # unique key, e.g. "lexical"
    complexity_rank: ClassVar[int]   # 1–5, used for ordering in the results table

    @abstractmethod
    def mutate(self, payload: Payload) -> list[MutatedPayload]: ...

REGISTRY: dict[str, type[Mutator]] = {}
def register(cls): REGISTRY[cls.category] = cls; return cls
```

## Single-request vs override-chain mutators

Two shapes are supported:

1. **String rewrite** (lexical, encoding, structural) — leave
   `request_overrides=None` on each `MutatedPayload`. The runner substitutes
   your mutated `body` into the default endpoint template from
   `engine/src/wafeval/targets.yaml` for the given `(target, vuln_class)`.

2. **Override chain** (context_displacement, multi_request) — populate
   `request_overrides` with one or more `RequestStep`s. The runner replays
   them in order, threading a shared cookie jar between steps, and evaluates
   the verdict against the *last* step's response.

`RequestStep` fields:

- `method` — `"GET"` or `"POST"`
- `path_override` — optional; falls back to the endpoint default path
- `query` — dict added as `?k=v`
- `form` — dict sent as `application/x-www-form-urlencoded`
- `json_body` — dict/list/str serialised as `application/json`
- `raw_body` + `content_type` — for text/plain, XML, etc.
- `file_fields` — `{name: (filename, content)}` multipart parts
- `headers` — override or add any header

## Steps to add a sixth category

1. Create `engine/src/wafeval/mutators/<name>.py`, subclass `Mutator`, pick
   a unique `category` and `complexity_rank` (6+).
2. Decorate with `@register`. Produce **≥5 variants per input payload** —
   the Phase 4 acceptance test enforces this invariant.
3. Import the module in `engine/src/wafeval/mutators/__init__.py` so the
   registration side-effect runs.
4. Add `engine/tests/test_<name>_mutator.py`. Cover:
   - registration under the category key
   - ≥5 variants for SQLi and XSS fixtures
   - variant-body distinctness from source
   - any class-specific invariants (encoding round-trip, multi-request
     destructive-safety, override-step shape)
5. If your variants use `request_overrides` to reach a novel transport
   (e.g. WebSocket upgrade, HTTP/2 pseudo-headers), add matching fields to
   `RequestStep` and the runner's `_build_httpx_kwargs` first.

## Safety

- Never emit a destructive variant — the `Payload` loader rejects inputs
  containing `DROP TABLE`, `rm -rf`, fork bombs, etc. Mutators that build
  multi-step chains (see `multi_request.py`) also re-scan each step's
  rendered body with the same list.
- Multi-step cookie jars are per-variant and disposed after the verdict is
  written; cross-variant state sharing is a Phase 5+ optimisation.
