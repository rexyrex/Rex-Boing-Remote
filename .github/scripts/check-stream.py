"""Checks an agent's stream output against PROTOCOL.md's basic rules."""
import json
import sys

lines = open(sys.argv[1], encoding="utf-8").read().splitlines()
assert lines, "the agent wrote nothing"
messages = [json.loads(line) for line in lines]
hello = messages[0]
assert hello["type"] == "hello", "the first line must be hello"
assert hello["protocol"] == 1, "protocol must be 1"
assert hello["agent"]["name"] == "rex-boing-agent"
samples = [m for m in messages if m["type"] == "sample"]
assert len(samples) >= 3, f"expected samples, got {len(samples)}"
for previous, sample in zip(samples, samples[1:]):
    assert sample["seq"] == previous["seq"] + 1, "seq must count up"
    assert sample["t"] >= previous["t"], "t must not go backwards"
full = [s for s in samples if s["detail"] == "full"]
assert full, "the full request was not honoured"
last = full[-1]
cpu = last["cpu"]
assert 0 <= cpu["total"] <= 1, "cpu.total must be a fraction"
assert last["memory"]["total"] > 0, "memory.total must be known"
if "processes" in last:
    rows = {row["pid"] for row in last["processes"]["rows"]}
    for metric, pids in last["processes"]["rank"].items():
        assert set(pids) <= rows, f"rank.{metric} names pids missing from rows"
for line in lines:
    assert len(line) < 1 << 20, "line too long"
print(f"ok: hello + {len(samples)} samples ({len(full)} full), host {hello['host'].get('hostname')}")
