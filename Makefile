SHELL := /usr/bin/env bash

MINIDROP_RUNTIME ?= $(HOME)/mini-drop-runtime
PYTHON ?= python3
PYTHONPATH := $(CURDIR)/analysis:$(CURDIR)/drop:$(CURDIR)/apiserver
PROFILE_ID ?= manual-001
JOB_ID ?= demo-agent
PENDING_JOB_ID ?=
DURATION ?= 10
FREQUENCY ?= 99
COLLECTOR ?= perf
API_HOST ?= 127.0.0.1
API_PORT ?= 8000
AGENT_ID ?= local-agent
HEARTBEAT_INTERVAL ?= 5
HEARTBEAT_COUNT ?= 1
POLL_INTERVAL ?= 2
MAX_JOBS ?= 0
MAX_PENDING_AGE ?= 300
MAX_CLAIM_ATTEMPTS ?= 3
DISABLE_PID_CHECK ?= 0
JOB_SOURCE ?= server
LEASE_SECONDS ?= 60
HOST_KERNEL ?= $(shell uname -r)
HOST_PERF_BIN ?= $(shell if [ -x /usr/lib/linux-tools-$(HOST_KERNEL)/perf ]; then echo /usr/lib/linux-tools-$(HOST_KERNEL)/perf; elif [ -x /usr/lib/linux-tools/$(HOST_KERNEL)/perf ]; then echo /usr/lib/linux-tools/$(HOST_KERNEL)/perf; else command -v perf; fi)
HOST_BPFTRACE_BIN ?= $(shell command -v bpftrace 2>/dev/null || true)
HOST_PY_SPY_BIN ?= $(shell command -v py-spy 2>/dev/null || true)
REQUIRE_DOCKER ?= 0
BASELINE ?=
CURRENT ?=
DIFF_OUTPUT ?= $(MINIDROP_RUNTIME)/profiles/ebpf-latency-diff.json
BASELINE_DELAY_US ?= 50
CURRENT_DELAY_US ?= 2000
EBPF_DEMO_RUN_AGENT ?= 1
DEMO_RUN_AGENT ?= 0

.PHONY: init setup-python check-tools doctor doctor-fix setup-sudoers build-workload build-io-workload build-latency-workload build-fusion-workload collect latency-diff agent-run agent-run-pending agent-heartbeat agent-daemon api-run api-maintenance test integration-test compose-config compose-up compose-down compose-logs clean-runtime demo local-demo e2e-demo ebpf-demo agent-demo python-demo

init:
	mkdir -p $(MINIDROP_RUNTIME)/builds
	mkdir -p $(MINIDROP_RUNTIME)/profiles
	mkdir -p $(MINIDROP_RUNTIME)/logs
	mkdir -p $(MINIDROP_RUNTIME)/data
	mkdir -p $(MINIDROP_RUNTIME)/tmp

check-tools:
	bash deploy/check_tools.sh

setup-python:
	$(PYTHON) -m pip install -r requirements.txt

doctor:
	MINIDROP_REQUIRE_DOCKER=$(REQUIRE_DOCKER) bash deploy/doctor.sh

setup-sudoers:
	@echo "This command configures passwordless sudo for perf, bpftrace, and py-spy."
	@echo "It writes /etc/sudoers.d/mini-drop-tools and requires your sudo password once."
	sudo env \
		MINIDROP_PERF_BIN="$(HOST_PERF_BIN)" \
		MINIDROP_BPFTRACE_BIN="$(HOST_BPFTRACE_BIN)" \
		MINIDROP_PY_SPY_BIN="$(HOST_PY_SPY_BIN)" \
		bash deploy/setup_sudoers.sh

doctor-fix: setup-sudoers
	$(MAKE) doctor

build-workload: init
	gcc -O2 -g -fno-omit-frame-pointer \
		-o $(MINIDROP_RUNTIME)/builds/cpu_hotspot \
		workloads/cpu_hotspot.c

build-io-workload: init
	gcc -O2 -g -fno-omit-frame-pointer \
		-o $(MINIDROP_RUNTIME)/builds/io_syscall_hotspot \
		workloads/io_syscall_hotspot.c

build-latency-workload: init
	gcc -O2 -g -fno-omit-frame-pointer -pthread \
		-o $(MINIDROP_RUNTIME)/builds/io_latency_hotspot \
		workloads/io_latency_hotspot.c

build-fusion-workload: init
	gcc -O2 -g -fno-omit-frame-pointer -pthread \
		-o $(MINIDROP_RUNTIME)/builds/cpu_io_hotspot \
		workloads/cpu_io_hotspot.c

collect:
	@if [ -z "$(PID)" ]; then echo "Usage: make collect PID=<target-pid> [DURATION=10] [FREQUENCY=99] [PROFILE_ID=name]"; exit 2; fi
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m minidrop_analysis collect \
		--pid $(PID) \
		--duration $(DURATION) \
		--frequency $(FREQUENCY) \
		--collector $(COLLECTOR) \
		--output $(MINIDROP_RUNTIME)/profiles/$(PROFILE_ID)

latency-diff:
	@if [ -z "$(BASELINE)" ] || [ -z "$(CURRENT)" ]; then echo "Usage: make latency-diff BASELINE=<baseline-json> CURRENT=<current-json> [DIFF_OUTPUT=path]"; exit 2; fi
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m minidrop_analysis compare-latency \
		--baseline $(BASELINE) \
		--current $(CURRENT) \
		--output $(DIFF_OUTPUT)

agent-run:
	@if [ -z "$(PID)" ]; then echo "Usage: make agent-run PID=<target-pid> [DURATION=10] [FREQUENCY=99] [JOB_ID=name]"; exit 2; fi
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m minidrop_agent run \
		--pid $(PID) \
		--duration $(DURATION) \
		--frequency $(FREQUENCY) \
		--job-id $(JOB_ID) \
		--runtime-dir $(MINIDROP_RUNTIME)

agent-run-pending:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m minidrop_agent run-pending \
		--runtime-dir $(MINIDROP_RUNTIME) \
		--max-pending-age $(MAX_PENDING_AGE) \
		$(if $(filter 1 true yes,$(DISABLE_PID_CHECK)),--disable-pid-check,) \
		$(if $(PENDING_JOB_ID),--job-id $(PENDING_JOB_ID),)

agent-heartbeat:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m minidrop_agent heartbeat \
		--server-url http://$(API_HOST):$(API_PORT) \
		--agent-id $(AGENT_ID) \
		--interval $(HEARTBEAT_INTERVAL) \
		--count $(HEARTBEAT_COUNT)

agent-daemon:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m minidrop_agent daemon \
		--runtime-dir $(MINIDROP_RUNTIME) \
		--server-url http://$(API_HOST):$(API_PORT) \
		--agent-id $(AGENT_ID) \
		--job-source $(JOB_SOURCE) \
		--heartbeat-interval $(HEARTBEAT_INTERVAL) \
		--poll-interval $(POLL_INTERVAL) \
		--max-jobs $(MAX_JOBS) \
		--max-pending-age $(MAX_PENDING_AGE) \
		--max-claim-attempts $(MAX_CLAIM_ATTEMPTS) \
		--lease-seconds $(LEASE_SECONDS) \
		$(if $(filter 1 true yes,$(DISABLE_PID_CHECK)),--disable-pid-check,)

api-run: init
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m minidrop_apiserver \
		--host $(API_HOST) \
		--port $(API_PORT) \
		--runtime-dir $(MINIDROP_RUNTIME)

api-maintenance:
	curl -s -X POST http://$(API_HOST):$(API_PORT)/api/maintenance/requeue-expired-leases \
		-H "Content-Type: application/json" \
		-d '{"max_claim_attempts": $(MAX_CLAIM_ATTEMPTS)}'

demo: build-workload build-latency-workload
	$(MAKE) doctor REQUIRE_DOCKER=1
	MINIDROP_RUNTIME=$(MINIDROP_RUNTIME) \
	PYTHON=$(PYTHON) \
	PYTHONPATH=$(PYTHONPATH) \
	API_HOST=$(API_HOST) \
	API_PORT=$(API_PORT) \
	DURATION=$(DURATION) \
	FREQUENCY=$(FREQUENCY) \
	AGENT_ID=$(AGENT_ID) \
	POLL_INTERVAL=$(POLL_INTERVAL) \
	LEASE_SECONDS=$(LEASE_SECONDS) \
	DIFF_OUTPUT=$(DIFF_OUTPUT) \
	BASELINE_DELAY_US=$(BASELINE_DELAY_US) \
	CURRENT_DELAY_US=$(CURRENT_DELAY_US) \
	DEMO_RUN_AGENT=$(DEMO_RUN_AGENT) \
	bash scripts/full_demo.sh

local-demo: build-workload
	@set -euo pipefail; \
	$(MINIDROP_RUNTIME)/builds/cpu_hotspot > $(MINIDROP_RUNTIME)/logs/cpu_hotspot.log 2>&1 & \
	pid=$$!; \
	echo "Started cpu_hotspot pid=$$pid"; \
	trap 'kill $$pid >/dev/null 2>&1 || true' EXIT; \
	sleep 1; \
	$(MAKE) collect PID=$$pid PROFILE_ID=demo DURATION=$(DURATION) FREQUENCY=$(FREQUENCY)

e2e-demo: build-workload
	MINIDROP_RUNTIME=$(MINIDROP_RUNTIME) \
	PYTHON=$(PYTHON) \
	PYTHONPATH=$(PYTHONPATH) \
	API_HOST=$(API_HOST) \
	API_PORT=$(API_PORT) \
	DURATION=$(DURATION) \
	FREQUENCY=$(FREQUENCY) \
	COLLECTOR=$(COLLECTOR) \
	AGENT_ID=$(AGENT_ID) \
	POLL_INTERVAL=$(POLL_INTERVAL) \
	LEASE_SECONDS=$(LEASE_SECONDS) \
	bash scripts/e2e_demo.sh

ebpf-demo: build-latency-workload
	MINIDROP_RUNTIME=$(MINIDROP_RUNTIME) \
	PYTHON=$(PYTHON) \
	PYTHONPATH=$(PYTHONPATH) \
	API_HOST=$(API_HOST) \
	API_PORT=$(API_PORT) \
	DURATION=$(DURATION) \
	FREQUENCY=$(FREQUENCY) \
	AGENT_ID=$(AGENT_ID) \
	POLL_INTERVAL=$(POLL_INTERVAL) \
	LEASE_SECONDS=$(LEASE_SECONDS) \
	DIFF_OUTPUT=$(DIFF_OUTPUT) \
	BASELINE_DELAY_US=$(BASELINE_DELAY_US) \
	CURRENT_DELAY_US=$(CURRENT_DELAY_US) \
	EBPF_DEMO_RUN_AGENT=$(EBPF_DEMO_RUN_AGENT) \
	bash scripts/ebpf_demo.sh

agent-demo: build-workload
	@set -euo pipefail; \
	$(MINIDROP_RUNTIME)/builds/cpu_hotspot > $(MINIDROP_RUNTIME)/logs/cpu_hotspot.log 2>&1 & \
	pid=$$!; \
	echo "Started cpu_hotspot pid=$$pid"; \
	trap 'kill $$pid >/dev/null 2>&1 || true' EXIT; \
	sleep 1; \
	$(MAKE) agent-run PID=$$pid JOB_ID=$(JOB_ID) DURATION=$(DURATION) FREQUENCY=$(FREQUENCY)

python-demo: init
	@set -euo pipefail; \
	$(PYTHON) workloads/python_hotspot.py > $(MINIDROP_RUNTIME)/logs/python_hotspot.log 2>&1 & \
	pid=$$!; \
	echo "Started python_hotspot pid=$$pid"; \
	trap 'kill $$pid >/dev/null 2>&1 || true' EXIT; \
	sleep 1; \
	$(MAKE) collect PID=$$pid PROFILE_ID=python-demo COLLECTOR=py_spy DURATION=$(DURATION) FREQUENCY=$(FREQUENCY)

test:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m pytest tests

integration-test:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m pytest tests/test_e2e_flows.py

compose-config:
	HOST_KERNEL=$(HOST_KERNEL) HOST_PERF_BIN=$(HOST_PERF_BIN) docker compose config

compose-up:
	HOST_KERNEL=$(HOST_KERNEL) HOST_PERF_BIN=$(HOST_PERF_BIN) docker compose up --build

compose-down:
	HOST_KERNEL=$(HOST_KERNEL) HOST_PERF_BIN=$(HOST_PERF_BIN) docker compose down

compose-logs:
	HOST_KERNEL=$(HOST_KERNEL) HOST_PERF_BIN=$(HOST_PERF_BIN) docker compose logs -f

clean-runtime:
	rm -rf $(MINIDROP_RUNTIME)/profiles/demo
	rm -rf $(MINIDROP_RUNTIME)/profiles/$(JOB_ID)
	rm -rf $(MINIDROP_RUNTIME)/jobs/$(JOB_ID)
