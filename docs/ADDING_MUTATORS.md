# Adding a mutator — [Phase 3+]

The mutator plugin interface lands in Phase 3. Shape of the contract:

```python
# engine/src/mutators/base.py
class Mutator(ABC):
    category: str          # unique key, e.g. "lexical"
    complexity_rank: int   # 1-5, used for ordering in results table

    @abstractmethod
    def mutate(self, payload: Payload) -> list[MutatedPayload]: ...

REGISTRY: dict[str, type[Mutator]] = {}
def register(cls): REGISTRY[cls.category] = cls; return cls
```

To add a sixth category: drop `engine/src/mutators/<name>.py`, decorate with `@register`, generate ≥ 5 variants per input, add unit tests in `engine/tests/mutators/test_<name>.py`. See `docs/ARCHITECTURE.md` once the engine exists.
