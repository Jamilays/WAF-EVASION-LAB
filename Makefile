SHELL := /usr/bin/env bash
COMPOSE := docker compose

.PHONY: help up up-paranoia up-ml down run report clean reset-wafs shell-engine config test-phase1 test-phase2 logs ps curl-matrix

help:
	@echo "WAF Evasion Lab — Make targets"
	@echo ""
	@echo "  make up            Start core stack (Traefik + 3 targets + 9 WAF×target)"
	@echo "  make up-paranoia   Start core + ModSec/Coraza paranoia-high variants"
	@echo "  make up-ml         Start core + open-appsec stubs (--profile ml)"
	@echo "  make down          Stop stack (keep volumes)"
	@echo "  make config        Validate docker-compose across all profiles"
	@echo "  make test-phase1   [legacy] Run Phase 1 acceptance tests"
	@echo "  make test-phase2   Run Phase 2 acceptance tests (routing matrix)"
	@echo "  make curl-matrix   Probe every route through Traefik and print codes"
	@echo "  make ps            Show container status"
	@echo "  make logs SVC=<s>  Tail logs for service <s>"
	@echo "  make clean         Remove containers, volumes, and results"
	@echo "  make reset-wafs    Restart WAF services only"
	@echo "  make run           [Phase 3+] Trigger engine test run"
	@echo "  make report        [Phase 5+] Regenerate report"

up:
	$(COMPOSE) up -d --build --wait --wait-timeout 600 --remove-orphans

up-paranoia:
	$(COMPOSE) --profile paranoia-high up -d --build --wait --wait-timeout 600 --remove-orphans

up-ml:
	$(COMPOSE) --profile ml up -d --build --wait --wait-timeout 600 --remove-orphans

down:
	$(COMPOSE) down

clean:
	$(COMPOSE) --profile paranoia-high --profile ml down -v --remove-orphans
	rm -rf results/raw/* results/processed/* results/figures/* results/reports/* 2>/dev/null || true

reset-wafs:
	$(COMPOSE) restart $$( $(COMPOSE) ps --services | grep -E '^(modsec|coraza|shadowd-)' )

config:
	@echo "[1/3] Default profile …"
	@$(COMPOSE) config --quiet && echo "    ok"
	@echo "[2/3] --profile paranoia-high …"
	@$(COMPOSE) --profile paranoia-high config --quiet && echo "    ok"
	@echo "[3/3] --profile ml …"
	@$(COMPOSE) --profile ml config --quiet && echo "    ok"

ps:
	$(COMPOSE) ps

logs:
	$(COMPOSE) logs -f --tail=100 $(SVC)

test-phase1:
	bash tests/phase1.sh

test-phase2:
	bash tests/phase2.sh

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

# ---- placeholders for later phases ----
run:
	@echo "[stub] engine runner — Phase 3 deliverable"

report:
	@echo "[stub] reporter — Phase 5 deliverable"

shell-engine:
	@echo "[stub] engine container — Phase 3 deliverable"
