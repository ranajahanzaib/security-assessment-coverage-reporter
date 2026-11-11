# Completeness, execution, and findings

Security Assessment Coverage Reporter evaluates whether evidence supports a declared assessment. `COMPLETE` means all **required** checks met their stated criteria; it says nothing about unknown vulnerabilities. `INCOMPLETE` means at least one required check demonstrably failed, timed out, was skipped, was unsupported, was not run, or was partial. `INCONCLUSIVE` means required execution remains unknown without a definitive incomplete check. Optional checks appear in the receipt but do not block completeness.

Scanner process state and check state are separate. A zero exit code establishes process completion, not route, target, template, or authentication coverage. Findings count is a separate dimension: zero alerts is not evidence of execution. Findings policy may fail independently even when assessment completeness passes.

The manifest declares expectations. Scanner reports provide native observations. Execution and verification sidecars provide external attestations. All remain distinguishable in the receipt.
