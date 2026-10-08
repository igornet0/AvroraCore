.PHONY: help build avrora avrora-dev init invite sql sql-bg \
	ui-install ui-dev ui-build test test-slow bench stress clean

AVRORA_ADDR         ?= 127.0.0.1:18787
AVRORA_CONTROL_ADDR ?= 127.0.0.1:7432
DATA                ?= data/avrora.dbs.json
CONTROL_DIR         ?= data/control
SQL_ADDR            ?= 127.0.0.1:15432
SQL_DATA            ?= data/sql.dbs.json
SQL_MASTER_KEY      ?= data/sql.master.key
SQL_LOG             ?=
SQL_PID             ?=

AVRORA_BIN := target/debug/avrora
PGWIRE_BIN := target/debug/dmc-pgwire

help:
	@echo "Avrora — DataModelCore runtime"
	@echo ""
	@echo "  make build        Build avrora + dmc-pgwire (+ UI if needed)"
	@echo "  make init         First-time control plane (TLS + bootstrap token)"
	@echo "  avrora devo-init  Dev vault: root role/user (+ --demo for sample data)"
	@echo "  make avrora       Run management core on $(AVRORA_ADDR)"
	@echo "  make avrora-dev   API + Vite UI (hot reload)"
	@echo "  make sql          Run SQL pgwire DBMS on $(SQL_ADDR)"
	@echo "  make invite       Export localhost invite.json"
	@echo "  avrora menu       Interactive operator menu (serve, UI, vault, roles)"
	@echo "  avrora init|invite|serve|status|reset --yes|menu"
	@echo "  AVRORA_DEV=1 dmc serve --dev       # SQL Core IPC, dev only (plaintext unlock file)"
	@echo "  dmc serve --keypass-dir DIR        # SQL Core IPC, production (KeyPass, no plaintext)"
	@echo "  dmc backup create|verify|list|restore|recover|status"
	@echo "  make client-ui → __dmc.backup.create('daily-01')  # dev console after unlock"
	@echo "  make test         cargo test --workspace (skips slow #[ignore] tests)"
	@echo "  make test-slow    run slow acceptance tests only (~15 min debug)"
	@echo "  make bench        criterion benchmarks (dmc-bench)"
	@echo "  make stress       full stress test (--quick, writes report)"
	@echo "  make stress-full  heavy stress test with report"
	@echo "  make stress-report show latest markdown report"
	@echo "  make clean        cargo clean + remove UI dist"

build: ui-build
	@mkdir -p data
	cargo build -p dmc-core --bin avrora
	cargo build -p dmc-pgwire --bin dmc-pgwire

ui-install:
	cd crates/dmc-core/ui && npm install

ui-build:
	@if [ ! -d crates/dmc-core/ui/dist ]; then \
		$(MAKE) ui-install; \
		cd crates/dmc-core/ui && npm run build; \
	elif [ ! -d crates/dmc-core/ui/node_modules ]; then \
		$(MAKE) ui-install; \
	fi

ui-dev:
	cd crates/dmc-core/ui && npm run dev

init:
	@mkdir -p data "$(CONTROL_DIR)"
	@if [ -f "$(CONTROL_DIR)/tls/server.crt" ]; then \
		echo "control already initialized: $(CONTROL_DIR)"; \
	else \
		cargo run -p dmc-core --bin avrora -- init \
			--data-dir "$(CONTROL_DIR)" \
			--invite-host 127.0.0.1 \
			--invite-port $$(echo "$(AVRORA_CONTROL_ADDR)" | sed 's/.*://'); \
	fi

invite:
	cargo run -p dmc-core --bin avrora -- invite \
		--data-dir "$(CONTROL_DIR)" \
		--host 127.0.0.1 \
		--port $$(echo "$(AVRORA_CONTROL_ADDR)" | sed 's/.*://') \
		--write

avrora: build init
	@mkdir -p data
	AVRORA_DEV=$(AVRORA_DEV) \
	AVRORA_ADDR=$(AVRORA_ADDR) \
	AVRORA_CONTROL_ADDR=$(AVRORA_CONTROL_ADDR) \
	AVRORA_DATA=$(DATA) \
	AVRORA_CONTROL_DIR=$(CONTROL_DIR) \
	$(AVRORA_BIN) serve

avrora-dev: build init
	@mkdir -p data
	@echo "Starting Avrora API on $(AVRORA_ADDR)…"
	AVRORA_DEV=1 \
	AVRORA_ADDR=$(AVRORA_ADDR) \
	AVRORA_CONTROL_ADDR=$(AVRORA_CONTROL_ADDR) \
	AVRORA_DATA=$(DATA) \
	AVRORA_CONTROL_DIR=$(CONTROL_DIR) \
	$(AVRORA_BIN) serve & \
	API_PID=$$!; \
	trap 'kill $$API_PID 2>/dev/null' EXIT; \
	sleep 2; \
	cd crates/dmc-core/ui && npm install && npm run dev

# Create SQL DB on first run (saves master key); unlock on later runs.
sql: build
	@mkdir -p data "$$(dirname "$(SQL_DATA)")" "$$(dirname "$(SQL_MASTER_KEY)")"
	@if [ -f "$(SQL_DATA)" ] && [ -f "$(SQL_MASTER_KEY)" ]; then \
		echo "SQL unlock → $(SQL_ADDR)  data=$(SQL_DATA)"; \
		$(PGWIRE_BIN) --data "$(SQL_DATA)" --listen "$(SQL_ADDR)" --unlock-file "$(SQL_MASTER_KEY)"; \
	elif [ -f "$(SQL_DATA)" ]; then \
		echo "SQL data exists but master key file missing: $(SQL_MASTER_KEY)" >&2; \
		exit 1; \
	else \
		echo "SQL create → $(SQL_ADDR)  data=$(SQL_DATA)"; \
		echo "master key will be saved to $(SQL_MASTER_KEY)"; \
		$(PGWIRE_BIN) --data "$(SQL_DATA)" --listen "$(SQL_ADDR)" --create --master-key-out "$(SQL_MASTER_KEY)"; \
	fi

# Background helper used by root `make up` (sets SQL_LOG / SQL_PID).
sql-bg: build
	@test -n "$(SQL_LOG)" && test -n "$(SQL_PID)" || (echo "SQL_LOG and SQL_PID required" >&2; exit 1)
	@mkdir -p data "$$(dirname "$(SQL_DATA)")" "$$(dirname "$(SQL_MASTER_KEY)")" "$$(dirname "$(SQL_LOG)")"
	@if [ -f "$(SQL_DATA)" ] && [ -f "$(SQL_MASTER_KEY)" ]; then \
		nohup $(PGWIRE_BIN) --data "$(SQL_DATA)" --listen "$(SQL_ADDR)" \
			--unlock-file "$(SQL_MASTER_KEY)" \
			> "$(SQL_LOG)" 2>&1 & echo $$! > "$(SQL_PID)"; \
	elif [ -f "$(SQL_DATA)" ]; then \
		echo "SQL data exists but master key file missing: $(SQL_MASTER_KEY)" >&2; \
		exit 1; \
	else \
		nohup $(PGWIRE_BIN) --data "$(SQL_DATA)" --listen "$(SQL_ADDR)" --create \
			--master-key-out "$(SQL_MASTER_KEY)" \
			> "$(SQL_LOG)" 2>&1 & echo $$! > "$(SQL_PID)"; \
		for i in 1 2 3 4 5 6 7 8 9 10; do \
			if [ -f "$(SQL_MASTER_KEY)" ]; then \
				echo "master key saved to $(SQL_MASTER_KEY)"; \
				break; \
			fi; \
			sleep 0.5; \
		done; \
	fi

test:
	cargo test --workspace

test-slow:
	cargo test -p dmc-core dod_acceptance -- --ignored
	cargo test -p dmc-storage large_scan_batch -- --ignored --exact

bench:
	cargo bench -p dmc-bench

stress:
	cargo run -p dmc-bench --bin avrora-stress --release -- --quick

stress-full:
	cargo run -p dmc-bench --bin avrora-stress --release -- --ops 5000 --concurrency 8

stress-report:
	@ls -t target/stress-reports/*.md 2>/dev/null | head -1 | xargs -I{} sh -c 'echo {}; cat {}'

clean:
	cargo clean
	rm -rf crates/dmc-core/ui/dist
