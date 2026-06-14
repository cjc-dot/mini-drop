SHELL := /usr/bin/env bash

MINIDROP_RUNTIME ?= $(HOME)/mini-drop-runtime
PYTHON ?= python3
PYTHONPATH := $(CURDIR)/analysis
PROFILE_ID ?= manual-001
DURATION ?= 10
FREQUENCY ?= 99

.PHONY: init build-workload collect test clean-runtime demo

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

demo: build-workload
	@set -euo pipefail; \
	$(MINIDROP_RUNTIME)/builds/cpu_hotspot > $(MINIDROP_RUNTIME)/logs/cpu_hotspot.log 2>&1 & \
	pid=$$!; \
	echo "Started cpu_hotspot pid=$$pid"; \
	trap 'kill $$pid >/dev/null 2>&1 || true' EXIT; \
	sleep 1; \
	$(MAKE) collect PID=$$pid PROFILE_ID=demo DURATION=$(DURATION) FREQUENCY=$(FREQUENCY)

test:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m pytest tests

clean-runtime:
	rm -rf $(MINIDROP_RUNTIME)/profiles/demo
