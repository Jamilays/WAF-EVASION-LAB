SHELL := /usr/bin/env bash
COMPOSE := docker compose

.PHONY: help up up-paranoia up-ml up-dashboard down run run-host report report-host report-pdf clean reset-wafs shell-engine config test-phase1 test-phase2 test-phase3 test-phase4 test-phase5 test-phase6 test-engine logs ps curl-matrix build-engine build-dashboard api-host

help:
	@echo "WAF Evasion Lab — Make targets"
	@echo ""
	@echo "  make up            Start core stack (Traefik + 3 targets + 9 WAF×target)"
	@echo "  make up-paranoia   Start core + ModSec/Coraza paranoia-high variants"
	@echo "  make up-ml         Start core + open-appsec stubs (--profile ml)"
	@echo "  make up-dashboard  Start core + FastAPI + React dashboard (--profile dashboard)"
	@echo "  make down          Stop stack (keep volumes)"
	@echo "  make config        Validate docker-compose across all profiles"
	@echo "  make test-phase1   Run Phase 1 acceptance tests (WAF liveness)"
	@echo "  make test-phase2   Run Phase 2 acceptance tests (routing matrix)"
	@echo "  make test-phase3   Run Phase 3 acceptance tests (engine end-to-end)"
	@echo "  make test-phase4   Run Phase 4 acceptance tests (5 mutators × 100 payloads)"
	@echo "  make test-phase5   Run Phase 5 acceptance tests (analyzer + reporter)"
	@echo "  make test-phase6   Run Phase 6 acceptance tests (API + dashboard)"
	@echo "  make test-engine   Run engine unit tests (pytest)"
	@echo "  make curl-matrix   Probe every route through Traefik and print codes"
	@echo "  make ps            Show container status"
	@echo "  make logs SVC=<s>  Tail logs for service <s>"
	@echo "  make clean         Remove containers, volumes, and results"
	@echo "  make reset-wafs    Restart WAF services only"
	@echo "  make build-engine  Build the engine Docker image"
	@echo "  make run           Trigger an engine run (containerised)"
	@echo "  make run-host      Trigger an engine run from the host venv"
	@echo "  make shell-engine  Shell into a throw-away engine container"
	@echo "  make report        Regenerate MD/LaTeX report + CSVs + figures (containerised)"
	@echo "  make report-host   Same, but from the host venv"
	@echo "  make report-pdf    Compile report.tex → report.pdf via the latex sidecar"

up:
	$(COMPOSE) up -d --build --wait --wait-timeout 600 --remove-orphans

up-paranoia:
	$(COMPOSE) --profile paranoia-high up -d --build --wait --wait-timeout 600 --remove-orphans

up-ml:
	$(COMPOSE) --profile ml up -d --build --wait --wait-timeout 600 --remove-orphans

up-dashboard:
	$(COMPOSE) --profile dashboard up -d --build --wait --wait-timeout 600 --remove-orphans
	@echo ""
	@echo "Dashboard: http://127.0.0.1:$${DASHBOARD_PORT:-3000}"
	@echo "API:       http://127.0.0.1:$${API_PORT:-8001}/health"

down:
	$(COMPOSE) down

clean:
	$(COMPOSE) --profile paranoia-high --profile ml down -v --remove-orphans
	rm -rf results/raw/* results/processed/* results/figures/* results/reports/* 2>/dev/null || true

reset-wafs:
	$(COMPOSE) restart $$( $(COMPOSE) ps --services | grep -E '^(modsec|coraza|shadowd-)' )

config:
	@echo "[1/5] Default profile …"
	@$(COMPOSE) config --quiet && echo "    ok"
	@echo "[2/5] --profile paranoia-high …"
	@$(COMPOSE) --profile paranoia-high config --quiet && echo "    ok"
	@echo "[3/5] --profile ml …"
	@$(COMPOSE) --profile ml config --quiet && echo "    ok"
	@echo "[4/5] --profile engine …"
	@$(COMPOSE) --profile engine config --quiet && echo "    ok"
	@echo "[5/5] --profile dashboard …"
	@$(COMPOSE) --profile dashboard config --quiet && echo "    ok"

ps:
	$(COMPOSE) ps

logs:
	$(COMPOSE) logs -f --tail=100 $(SVC)

test-phase1:
	bash tests/phase1.sh

test-phase2:
	bash tests/phase2.sh

test-phase3:
	bash tests/phase3.sh

test-phase4:
	bash tests/phase4.sh

test-phase5:
	bash tests/phase5.sh

test-phase6:
	bash tests/phase6.sh

test-engine:
	@if [ ! -x engine/.venv/bin/python ]; then \
	   echo "creating engine/.venv …"; \
	   python3 -m venv engine/.venv && \
	   engine/.venv/bin/pip install -q -e 'engine/[dev]'; \
	fi
	engine/.venv/bin/python -m pytest engine/tests -q

build-engine:
	$(COMPOSE) --profile engine build engine

build-dashboard:
	$(COMPOSE) --profile dashboard build api dashboard

api-host:
	@if [ ! -x engine/.venv/bin/python ]; then \
	   echo "creating engine/.venv …"; \
	   python3 -m venv engine/.venv && \
	   engine/.venv/bin/pip install -q -e 'engine/[dev]'; \
	fi
	API_HOST=127.0.0.1 API_PORT=$${API_PORT:-8001} engine/.venv/bin/python -m wafeval.api

curl-matrix:
	@port=$${TRAEFIK_PORT:-8000}; \
	for waf in baseline modsec coraza shadowd; do \
	  for t in dvwa webgoat juiceshop; do \
	    code=$$(curl -sS -o /dev/null -w '%{http_code}' --max-time 6 \
	            -H "Host: $$waf-$$t.local" \
	            "http://127.0.0.1:$$port/"); \
	    printf '  %-28s → %s\n' "$$waf-$$t.local" "$$code"; \
	  done; \
	done

# ---- engine runners ----
# `run` executes the engine inside the waflab network so it resolves
# traefik by service name. `run-host` runs from a host venv against the
# loopback-published Traefik port — faster to iterate on mutator code.
run:
	$(COMPOSE) --profile engine run --rm engine run \
	  --classes $(CLASSES) --mutators $(MUTATORS) $(ENGINE_ARGS)

run-host:
	@if [ ! -x engine/.venv/bin/python ]; then \
	   echo "creating engine/.venv …"; \
	   python3 -m venv engine/.venv && \
	   engine/.venv/bin/pip install -q -e 'engine/[dev]'; \
	fi
	engine/.venv/bin/python -m wafeval run \
	  --traefik-url http://127.0.0.1:$${TRAEFIK_PORT:-8000} \
	  --classes $(CLASSES) --mutators $(MUTATORS) $(ENGINE_ARGS)

shell-engine:
	$(COMPOSE) --profile engine run --rm --entrypoint sh engine

# ---- Phase 5 reporter ----
# RUN_ID defaults to "latest under results/raw". Override with `RUN_ID=…` on CLI.
report:
	$(COMPOSE) --profile report run --rm reporter $(if $(RUN_ID),--run-id $(RUN_ID))

report-host:
	@if [ ! -x engine/.venv/bin/python ]; then \
	   echo "creating engine/.venv …"; \
	   python3 -m venv engine/.venv && \
	   engine/.venv/bin/pip install -q -e 'engine/[dev]'; \
	fi
	engine/.venv/bin/python -m wafeval report $(if $(RUN_ID),--run-id $(RUN_ID))

report-pdf:
	@if [ -z "$(RUN_ID)" ]; then \
	   echo "usage: make report-pdf RUN_ID=<run-id>"; exit 2; \
	fi
	$(COMPOSE) --profile report run --rm --entrypoint sh latex -c \
	  "cd $(RUN_ID) && pdflatex -interaction=nonstopmode report.tex && pdflatex -interaction=nonstopmode report.tex"

# ---- engine runner defaults ----
CLASSES  ?= sqli,xss
MUTATORS ?= lexical
