# Amazon Connect Customer Posture Assessment Tool — Performance Guide

The tool runs with parallel execution enabled by default. This page covers what that means and how to tune it for your environment.

## Table of Contents

- [Default behaviour](#default-behaviour)
- [Tuning flags](#tuning-flags)
  - [Speed it up](#speed-it-up)
  - [Slow it down (rate-limited accounts)](#slow-it-down-rate-limited-accounts)
- [Which checks take the longest](#which-checks-take-the-longest)
- [Journey mapping tuning](#journey-mapping-tuning)
- [Configuration file approach](#configuration-file-approach)

---

## Default behaviour

When you run the module or the environment-local console entry point, the
parallel engine is active automatically. It uses
`min(32, CPU cores × 2)` worker threads unless configured otherwise.

Run time depends on instance count, enabled controls, resource counts, flow
size and branching, API latency, permissions, and throttling. Measure in your
own account before changing worker or traversal limits; this guide does not
claim portable benchmark numbers.

---

## Tuning flags

### Speed it up

```bash
# More workers (default: auto)
--max-workers 16

# Larger batch size (default: 10)
--batch-size 20

# Skip flow analysis, every flow-dependent control, and most flow-content API work
# This excludes res-hardcoded-routing-001 (use --list-checks as the dynamic source
# of truth)
--skip-flow-analysis

# Scope to a single instance
--instance-id <id>

# Scope to one pillar
--pillars security
```

Example — fastest possible run for a first look:
```bash
python -m amazon_connect_assessment.cli \
  --region us-east-1 \
  --instance-id <id> \
  --pillars security resilience \
  --severity critical high \
  --skip-flow-analysis \
  --max-workers 16
```

### Slow it down (rate-limited accounts)

If you see `ThrottlingException` errors:

```bash
# Fewer workers
--max-workers 4 --batch-size 5

# Longer retry delays
--retry-base-delay 2.0 --retry-max-delay 120.0

# Force sequential (no parallelism at all)
--sequential
```

---

## Which checks take the longest

Contact flow content checks (`--skip-flow-analysis` skips these) fetch flow
JSON and then parse and graph it. Flow analysis can dominate a run when an
instance has many or complex flows. The exact flow-dependent inventory can
change; use `python -m amazon_connect_assessment.cli --list-checks` rather than
hard-coding a count in automation.

The Agentic CX Designer checks in `checks/acxd_checks.py` reuse this parsed flow
data. They inspect only reachable Connect-side
`ConnectParticipantWithAgenticCX` actions and do not call Agentic CX Designer
APIs, so they add no Agentic CX service API round trips.

**Caller Journey Mapping** adds work proportional to the number of phone
numbers and the branching complexity of parsed flows. The pipeline:

- calls `ListPhoneNumbersV2` with pagination;
- builds a super-graph from already parsed flows in memory; and
- runs bounded iterative static enumeration from each phone-number entry point,
  with maximum depth 50, 200 paths per number, and 5,000 paths per instance.

Cycle edges are pruned per path, but the separate iterative structural closure
still reaches every statically resolvable node. Enumeration is marked incomplete
when it reaches a depth, path, or step cap or encounters a dynamic or unresolved
cross-flow target. This means clean partial evidence is not presented as
exhaustive proof, while a known structural defect remains reportable.

`--skip-flow-analysis` skips Journey mapping and excludes every control that
requires flow analysis, including `res-hardcoded-routing-001`. Instance-level
checks have different API costs, so use verbose logs and measured runs to
identify the slowest work in your environment rather than relying on fixed
timing estimates.

---

## Journey mapping tuning

The journey mapping pipeline has its own bounds independent of the parallel engine:

| Setting | Default | Effect |
|---|---|---|
| `journey_map.max_paths_per_did` | 200 | Max paths enumerated from a single phone number. Reduce to 50 for faster runs. |
| `journey_map.max_depth` | 50 | Max DFS depth per path. Reduce if your flows are known to be shallow. |
| `MAX_TOTAL_PATHS` | 5000 | Hard cap on paths across an instance's phone-number entry points. Bounds path enumeration for each instance, not graph construction or a multi-instance run. |

Configure via `assessment_config.yaml`:

```yaml
journey_map:
  max_paths_per_did: 100
  max_depth: 30
```

---

## Configuration file approach

For repeated runs with the same tuning, save settings to `config/assessment_config.yaml`:

```yaml
global_settings:
  parallel_execution: true
  max_workers: 12
  batch_size: 15
  timeout: 300
  max_retry_attempts: 5
  retry_base_delay: 1.0
  retry_max_delay: 60.0

journey_map:
  max_paths_per_did: 200
  max_depth: 50
```

Then run:
```bash
python -m amazon_connect_assessment.cli --config config/assessment_config.yaml
```
