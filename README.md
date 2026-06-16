# Mini-Drop

Mini-Drop is a Linux profiling practice project. The current milestone provides a minimal CPU profiling path:

1. build a deterministic CPU hotspot workload;
2. collect stack samples with Linux `perf`;
3. convert `perf script` output into folded stacks;
4. render a simple flame graph SVG and a JSON summary.
5. run the same collector through a local Agent job state machine.
6. create and query profiling jobs through a minimal API server.

## Quick Start

```bash
cd ~/mini-drop
make init
make build-workload

~/mini-drop-runtime/builds/cpu_hotspot &
PID=$!

make collect PID=$PID DURATION=10 FREQUENCY=99
kill $PID
```

To run the local Agent wrapper:

```bash
make agent-demo JOB_ID=demo-agent DURATION=10 FREQUENCY=99
```

To run the API server:

```bash
make api-run
curl http://127.0.0.1:8000/api/health
```

After creating a job through the API, the local Agent can consume one pending job:

```bash
make agent-run-pending
```

The Agent can also report heartbeat status to the API server:

```bash
make agent-heartbeat AGENT_ID=local-agent HEARTBEAT_COUNT=1
curl http://127.0.0.1:8000/api/agents
```

Artifacts are written outside the repository by default:

```text
~/mini-drop-runtime/profiles/
~/mini-drop-runtime/jobs/
```

## Repository Layout

```text
analysis/      Python analysis and collector code
apiserver/     API server and file-backed job store
deploy/        Deployment and docker compose files
drop/          Agent-side job runner implementation
proto/         Cross-component interface definitions
tests/         Unit and integration tests
web_frontend/  Web UI implementation
workloads/     Demo programs used for profiling
```

Runtime data, logs, databases, build outputs, and profiling artifacts are intentionally not committed.
