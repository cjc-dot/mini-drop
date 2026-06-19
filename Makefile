SHELL := /usr/bin/env bash

MINIDROP_RUNTIME ?= $(HOME)/mini-drop-runtime
PYTHON ?= python3
PYTHONPATH := $(CURDIR)/analysis:$(CURDIR)/drop:$(CURDIR)/apiserver
PROFILE_ID ?= manual-001
JOB_ID ?= demo-agent
PENDING_JOB_ID ?=
DURATION ?= 10
FREQUENCY ?= 99
API_HOST ?= 127.0.0.1
API_PORT ?= 8000
AGENT_ID ?= local-agent
HEARTBEAT_INTERVAL ?= 5
HEARTBEAT_COUNT ?= 1
POLL_INTERVAL ?= 2
MAX_JOBS ?= 0
MAX_PENDING_AGE ?= 300
DISABLE_PID_CHECK ?= 0

.PHONY: init build-workload collect agent-run agent-run-pending agent-heartbeat agent-daemon api-run test clean-runtime demo agent-demo

init:
	mkdir -p $(MINIDROP_RUNTIME)/builds
	mkdir -p $(MINIDROP_RUNTIME)/profiles
	mkdir -p $(MINIDROP_RUNTIME)/logs
	mkdir -p $(MINIDROP_RUNTIME)/data
	mkdir -p $(MINIDROP_RUNTIME)/tmp

build-workload: init
	gcc -O2 -g -fno-omit-frame-pointer \
		-o $(MINIDROP_RUNTIME)/builds/cpu_hotspot \
		workloads/cpu_hotspot.c

collect:
	@if [ -z "$(PID)" ]; then echo "Usage: make collect PID=<target-pid> [DURATION=10] [FREQUENCY=99] [PROFILE_ID=name]"; exit 2; fi
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m minidrop_analysis collect \
		--pid $(PID) \
		--duration $(DURATION) \
		--frequency $(FREQUENCY) \
		--output $(MINIDROP_RUNTIME)/profiles/$(PROFILE_ID)

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
		--heartbeat-interval $(HEARTBEAT_INTERVAL) \
		--poll-interval $(POLL_INTERVAL) \
		--max-jobs $(MAX_JOBS) \
		--max-pending-age $(MAX_PENDING_AGE) \
		$(if $(filter 1 true yes,$(DISABLE_PID_CHECK)),--disable-pid-check,)

api-run: init
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m minidrop_apiserver \
		--host $(API_HOST) \
		--port $(API_PORT) \
		--runtime-dir $(MINIDROP_RUNTIME)

demo: build-workload
	@set -euo pipefail; \
	$(MINIDROP_RUNTIME)/builds/cpu_hotspot > $(MINIDROP_RUNTIME)/logs/cpu_hotspot.log 2>&1 & \
	pid=$$!; \
	echo "Started cpu_hotspot pid=$$pid"; \
	trap 'kill $$pid >/dev/null 2>&1 || true' EXIT; \
	sleep 1; \
	$(MAKE) collect PID=$$pid PROFILE_ID=demo DURATION=$(DURATION) FREQUENCY=$(FREQUENCY)

agent-demo: build-workload
	@set -euo pipefail; \
	$(MINIDROP_RUNTIME)/builds/cpu_hotspot > $(MINIDROP_RUNTIME)/logs/cpu_hotspot.log 2>&1 & \
	pid=$$!; \
	echo "Started cpu_hotspot pid=$$pid"; \
	trap 'kill $$pid >/dev/null 2>&1 || true' EXIT; \
	sleep 1; \
	$(MAKE) agent-run PID=$$pid JOB_ID=$(JOB_ID) DURATION=$(DURATION) FREQUENCY=$(FREQUENCY)

test:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m pytest tests

clean-runtime:
	rm -rf $(MINIDROP_RUNTIME)/profiles/demo
	rm -rf $(MINIDROP_RUNTIME)/profiles/$(JOB_ID)
	rm -rf $(MINIDROP_RUNTIME)/jobs/$(JOB_ID)
