# Hypothesis Types

This taxonomy covers broad source-code audit concerns. Dependency and
configuration scanner results are SCA auxiliary context, not default source-code
hypothesis classes.

For `hypothesis_backlog.json`, favor broad but concrete coverage across the
repository. For shortlisted `hypotheses.json`, prefer fewer, higher-value
hypotheses. In both layers, do not emit broad checklist items without
entrypoints, sensitive actions, and evidence seeds.

## ARCH. Architecture and Control Plane Root Causes

Use for system-level missing security architecture that explains several
endpoint-, service-, or sink-level candidates. Keep these hypotheses only when
there is concrete source evidence of a missing global control, not as generic
hardening.

- `missing_authentication_architecture`: no backend authentication mechanism,
  principal creation, or session/token validation exists for sensitive backend
  entrypoints.
- `missing_authorization_architecture`: identities exist, but no backend
  authorization policy, ownership, role, or permission enforcement layer exists.
- `missing_tenant_isolation_architecture`: multi-tenant/workspace/account data
  exists, but no consistent tenant boundary is enforced.
- `missing_security_boundary`: a declared trust boundary is absent from backend
  code, such as no webhook signature model, no plugin sandbox, or no admin
  boundary.
- `missing_control_plane`: sensitive actions exist without any central guard,
  policy, workflow, quota, audit, or approval control plane.

Signals:

- `semantic_model.json` lists only anonymous/public roles while sensitive
  actions or private resources are reachable.
- All or most entrypoints have `auth_context: none`, no middleware, no
  principal propagation, and no service-level guard chain.
- Multiple A-H candidates share the same missing global control.
- Source search for framework-auth concepts, middleware, policy, session/JWT,
  guard, RBAC/ACL, or tenant enforcement returns no effective backend control.

When an ARCH hypothesis is true, still keep concrete endpoint-level hypotheses
when they help show exploit paths. Do not split away the architecture root cause
until it disappears.

## A. Identity and Access Control

Use for authn/authz/ownership failures.

- `auth_bypass`: backend-sensitive action reachable without required authentication.
- `idor`: user-controlled resource identifier reaches read/write without ownership or tenancy validation.
- `vertical_privilege`: normal user path reaches admin or privileged action.
- `frontend_only_check`: permission check appears only in UI/client code or route metadata, not backend enforcement.
- `alternate_entrypoint`: queue, job, RPC, debug route, legacy route, or secondary controller reaches same sensitive action with weaker guards.
- `tenant_isolation_bypass`: tenant, organization, workspace, project, or account boundary is missing or inconsistent.
- `role_confusion`: role, group, policy, share, service account, or impersonation context is confused or downgraded.

Signals:

- Route/controller/service split where auth middleware exists on one route but not another.
- Resource ids read from request parameters, body, query, headers, or path.
- Guard names such as `isOwner`, `canAccess`, `requireAdmin`, `tenantId`, `policy`, `permission`, `authorize`, `acl`, `rbac`.
- Sensitive sinks such as update/delete/export/approve/refund/admin mutation.

## B. Workflow and State Machine

Use for lifecycle transitions and workflow order issues.

- `state_skip`: a transition writes a later state without validating the current state.
- `state_reversal`: a transition writes a previous or forbidden state.
- `repeated_transition`: the same transition can be executed repeatedly and repeats side effects.
- `check_write_split`: state is checked and then written in separate operations without transaction, lock, CAS, or equivalent protection.

Signals:

- State fields such as `status`, `state`, `stage`, `phase`, `workflow`, `approvedAt`, `paidAt`, `shippedAt`.
- Transition methods such as approve, pay, cancel, refund, fulfill, activate, disable, publish, settle, close.
- Missing comparison against allowed `from` states.
- Side effects near transition writes: balance, points, inventory, email, webhook, payment capture/refund.

## C. Business Logic and Abuse

Use when code may violate an explicit or inferred business invariant.

- `invariant_violation`: a sensitive action may violate a business rule or cross-resource invariant.
- `replay`: an externally supplied event, callback, request id, payment id, or token can be reused.
- `double_submit`: repeated submission can create duplicate charge/order/approval/reward/inventory effects.
- `business_constraint_missing`: approval, payment, inventory, points, quota, entitlement, or limit constraints appear absent or inconsistently enforced.
- `rate_limit_missing`: sensitive action lacks rate, quota, velocity, or abuse guard.
- `economic_abuse`: discount, coupon, credit, refund, pricing, reward, quota, or entitlement math can be manipulated.
- `approval_bypass`: maker/checker, review, or approval workflow can be bypassed or self-approved.

Signals:

- Business counters or ledgers: balance, credits, points, stock, quota, usage, limit, amount, price.
- External event handlers: webhooks, callbacks, queues, retries.
- Idempotency terms: nonce, requestId, idempotencyKey, eventId, transactionId.
- Missing uniqueness constraints, dedupe records, locks, or transaction guards.

## D. Injection and Unsafe Interpretation

Use when attacker-controlled input may be interpreted as code, query, selector, template, expression, command, path, markup, or script.

- `sql_injection`
- `nosql_injection`
- `command_injection`
- `template_injection`
- `xss`
- `open_redirect`
- `unsafe_eval`
- `ldap_xpath_injection`

Signals:

- Raw query APIs, string concatenation around query fragments, `$where`, `$regex`, `exec`, `spawn`, `eval`, `Function`, template engines, render helpers.
- Sanitizers/encoders such as parameter binding, allowlists, escaping, DOMPurify, trusted types, URL validation.

## E. Data Exposure and Privacy

Use when sensitive data may be over-read, over-returned, logged, cached, exported, or exposed across trust boundaries.

- `sensitive_data_exposure`
- `overbroad_query`
- `logging_leak`
- `cache_leak`
- `debug_admin_exposure`

Signals:

- Response serializers, export endpoints, debug endpoints, logs, telemetry, caches, CDN headers, schema introspection, file download paths.
- Guards such as field-level permission checks, redaction, response filtering, cache key scoping, private cache headers.

## F. Secrets, Crypto, and Session Security

Use for cryptographic misuse, secret handling, token/session weaknesses, and authentication protocol issues.

- `hardcoded_secret`
- `weak_crypto`
- `jwt_misuse`
- `session_fixation`
- `csrf`
- `password_reset_flaw`

Signals:

- Crypto APIs, JWT libraries, password reset flows, cookie/session config, CORS/CSRF middleware, random/uuid generation, certificate/TLS options.

## G. External Boundaries, Files, and Network

Use when code crosses system boundaries: URLs, files, archives, parsers, uploads, webhooks, callbacks, object storage, email, queues, and third-party integrations.

- `ssrf`
- `path_traversal`
- `unsafe_file_upload`
- `unsafe_deserialization`
- `webhook_signature_missing`
- `xxe`
- `request_smuggling_proxy_trust`

Signals:

- HTTP clients, URL parsers, file APIs, storage drivers, upload handlers, archive extraction, XML/YAML/parsers, webhook controllers, proxy trust config.

## H. Concurrency, Consistency, and Resource Exhaustion

Use when simultaneous requests, retries, long-running work, or unbounded input can break security invariants or availability.

- `race_condition`
- `transaction_missing`
- `resource_exhaustion`
- `regex_dos`
- `queue_job_abuse`

Signals:

- Check-then-write patterns, missing transactions, unique constraints, locks, retries, batch operations, pagination limits, regex, parsers, queues, workers.
