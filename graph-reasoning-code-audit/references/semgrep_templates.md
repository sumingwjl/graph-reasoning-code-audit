# Semgrep Templates

These are starting points for generated rules. The agent should prefer producing
small target-specific rules from hypotheses instead of broad generic scans.

## IDOR / Missing Ownership Sketch

```yaml
rules:
  - id: poc-idor-resource-write
    languages: [generic]
    severity: WARNING
    message: Potential resource id reaches sensitive action; verify ownership guard.
    mode: taint
    pattern-sources:
      - pattern: $REQ.params.$ID
      - pattern: $REQ.body.$ID
      - pattern: $REQ.query.$ID
    pattern-sinks:
      - pattern: $MODEL.update(...)
      - pattern: $MODEL.delete(...)
      - pattern: $SERVICE.$ACTION(...)
    pattern-sanitizers:
      - pattern: requireOwner(...)
      - pattern: authorize(...)
      - pattern: canAccess(...)
```

## State Transition Sketch

```yaml
rules:
  - id: poc-state-write-without-state-check
    languages: [generic]
    severity: WARNING
    message: Potential state transition write without nearby state guard.
    patterns:
      - pattern-either:
          - pattern: $OBJ.status = $NEW
          - pattern: $MODEL.update(... status: $NEW ...)
      - pattern-not-inside: |
          if ($OBJ.status == $OLD) {
            ...
          }
```

## Replay / Double Submit Sketch

```yaml
rules:
  - id: poc-missing-idempotency
    languages: [generic]
    severity: WARNING
    message: Sensitive side effect in external entrypoint; verify idempotency.
    patterns:
      - pattern-either:
          - pattern: $PAYMENT.capture(...)
          - pattern: $ORDER.create(...)
          - pattern: $INVENTORY.decrement(...)
      - pattern-not: idempotency
      - pattern-not: eventId
      - pattern-not: requestId
```
