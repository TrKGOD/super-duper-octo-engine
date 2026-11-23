# Agent evaluation benchmark

This benchmark measures the quality of **agent-produced finding decisions** against small, explicitly synthetic fixtures. It does not scan targets, execute payloads, or establish real-world detection performance.

## Dataset rules
- Every checked-in case is synthetic and safe to publish.
- Do not add client reports, private bug-bounty submissions, credentials, screenshots, or real target data.
- Positive cases describe the expected class and evidence contract, not a ready-made exploit.
- Negative cases are deliberate false-positive traps.

## Prediction format

Create a JSON file with a `predictions` array:

```json
{
  "predictions": [
    {
      "case_id": "SYN-BOLA-001",
      "detected": true,
      "vulnerability_type": "BOLA",
      "evidence_fields": [
        "request_identity",
        "object_owner_identity",
        "authorization_decision"
      ]
    }
  ]
}
```

Each case must appear exactly once. Unknown and duplicate IDs are errors. Missing cases count as missed predictions (FN for positive cases, TN for negative cases) only when `--allow-missing` is supplied; otherwise evaluation fails closed.

## Run

```bash
python scripts/evaluate_benchmark.py --cases benchmarks/cases --predictions benchmarks/predictions.example.json
python scripts/evaluate_benchmark.py --cases benchmarks/cases --predictions /path/to/predictions.json --json-out .local/benchmark-results.json
```

## Metrics
- Precision, recall, F1
- False-positive rate
- Evidence completeness: mean fraction of required evidence fields present on detected positive cases

The evaluator reports counts and percentages. It does **not** claim model accuracy from unit tests or from this tiny fixture set. Compare agent versions on the same cases and add reviewed cases before drawing conclusions.
