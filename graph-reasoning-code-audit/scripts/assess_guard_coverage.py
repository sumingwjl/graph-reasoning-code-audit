#!/usr/bin/env python3
"""Assess whether hypotheses have deterministic source-backed guard coverage.

The built-in generic mode is intentionally conservative: it records `unknown`
coverage for each hypothesis so the source-validation pass can adjudicate it.
Project-specific guard adapters can provide stronger coverage only when they are
explicitly selected or when no hypotheses file is provided for the legacy demo.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig", errors="replace")


def line_ref(path: str, line: int, note: str) -> dict[str, Any]:
    return {"path": path, "line": line, "note": note}


def contains_all(text: str, values: list[str]) -> bool:
    return all(value in text for value in values)


def find_line(text: str, pattern: str) -> int | None:
    regex = re.compile(pattern)
    for idx, line in enumerate(text.splitlines(), 1):
        if regex.search(line):
            return idx
    return None


def normalize_kind(item: dict[str, Any]) -> str:
    metadata = item.get("metadata") or {}
    details = item.get("details") or {}
    return str(metadata.get("evidence_kind") or details.get("evidence_kind") or "")


def index_evidence(payload: Any) -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = {}
    if not isinstance(payload, dict):
        return index
    for item in payload.get("results", []):
        if not isinstance(item, dict):
            continue
        hid = item.get("hypothesis_id") or (item.get("metadata") or {}).get("hypothesis_id")
        if hid:
            index.setdefault(str(hid), []).append(item)
    return index


def load_hypotheses(path: Path) -> list[dict[str, Any]]:
    payload = load_json(path)
    if isinstance(payload, dict):
        return [item for item in payload.get("hypotheses", []) if isinstance(item, dict)]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


def generic_unknown_coverage(hypotheses: list[dict[str, Any]]) -> dict[str, Any]:
    coverage = []
    for hypothesis in hypotheses:
        hid = str(hypothesis.get("id") or "")
        if not hid:
            continue
        coverage.append(
            {
                "hypothesis_id": hid,
                "title": str(hypothesis.get("title") or hypothesis.get("type") or "Untitled hypothesis"),
                "coverage": "unknown",
                "reason": (
                    "No deterministic project-specific guard coverage adapter was selected for this hypothesis. "
                    "Use the source-validation packet and playbook for source-grounded adjudication."
                ),
                "request_accountability": {"coverage": "unknown", "guard_chain": []},
                "covered_sinks": [],
                "open_questions": [
                    "Trace entrypoint-to-sensitive-action reachability in source.",
                    "Check whether the expected guard or invariant dominates the sensitive action.",
                ],
                "evidence": [],
            }
        )
    return {
        "coverage": coverage,
        "summary": {
            "assessed": len(coverage),
            "covered": 0,
            "partial": 0,
            "unknown": len(coverage),
            "confirmed_missing_guard": 0,
        },
    }


def evidence_locations(items: list[dict[str, Any]], kind: str | None = None) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for item in items:
        if kind and normalize_kind(item) != kind:
            continue
        if isinstance(item.get("locations"), list):
            for loc in item["locations"]:
                if isinstance(loc, dict):
                    output.append(loc)
        elif item.get("path"):
            output.append({"path": item.get("path"), "line": item.get("line")})
    return output


def assess(repo_root: Path, semgrep: dict[str, Any], joern: dict[str, Any]) -> dict[str, Any]:
    permissions_controller = read_text(repo_root / "api/src/controllers/permissions.ts")
    users_controller = read_text(repo_root / "api/src/controllers/users.ts")
    app = read_text(repo_root / "api/src/app.ts")
    authenticate = read_text(repo_root / "api/src/middleware/authenticate.ts")
    get_accountability = read_text(repo_root / "api/src/utils/get-accountability-for-token.ts")
    default_accountability = read_text(repo_root / "api/src/permissions/utils/create-default-accountability.ts")
    permissions_service = read_text(repo_root / "api/src/services/permissions.ts")
    users_service = read_text(repo_root / "api/src/services/users.ts")
    items_service = read_text(repo_root / "api/src/services/items.ts")
    process_payload = read_text(repo_root / "api/src/permissions/modules/process-payload/process-payload.ts")
    fetch_accountability_access = read_text(
        repo_root
        / "api/src/permissions/modules/fetch-accountability-collection-access/fetch-accountability-collection-access.ts"
    )
    collab = read_text(repo_root / "api/src/websocket/collab/collab.ts")
    collab_verify_permissions = read_text(repo_root / "api/src/websocket/collab/verify-permissions.ts")
    websocket_base = read_text(repo_root / "api/src/websocket/controllers/base.ts")
    websocket_authenticate = read_text(repo_root / "api/src/websocket/authenticate.ts")
    graphql_controller = read_text(repo_root / "api/src/controllers/graphql.ts")
    graphql_system = read_text(repo_root / "api/src/services/graphql/resolvers/system.ts")
    graphql_system_admin = read_text(repo_root / "api/src/services/graphql/resolvers/system-admin.ts")

    semgrep_index = index_evidence(semgrep)
    joern_index = index_evidence(joern)

    permissions_extends_items = "export class PermissionsService extends ItemsService" in permissions_service
    users_extends_items = "export class UsersService extends ItemsService" in users_service
    controllers_pass_accountability = "accountability: req.accountability" in permissions_controller
    users_controller_passes_accountability = "accountability: req.accountability" in users_controller
    authenticate_before_permissions = app.find("app.use(authenticate)") < app.find("app.use('/permissions', permissionsRouter)")
    authenticate_before_users = app.find("app.use(authenticate)") < app.find("app.use('/users', usersRouter)")
    authenticate_before_graphql = app.find("app.use(authenticate)") < app.find("app.use('/graphql', graphqlRouter)")
    authenticate_sets_accountability = contains_all(
        authenticate,
        [
            "const defaultAccountability: Accountability = createDefaultAccountability",
            "req.accountability = await getAccountabilityForToken(req.token, defaultAccountability)",
        ],
    )
    default_accountability_is_object = contains_all(
        default_accountability,
        ["role: null", "user: null", "roles: []", "admin: false", "app: false"],
    )
    token_helper_returns_default = contains_all(
        get_accountability,
        ["if (!accountability)", "accountability = createDefaultAccountability()", "return accountability"],
    )
    request_accountability_covered = all(
        [
            authenticate_before_permissions,
            authenticate_before_users,
            authenticate_sets_accountability,
            default_accountability_is_object,
            token_helper_returns_default,
        ]
    )
    graphql_request_accountability_covered = all(
        [
            authenticate_before_graphql,
            authenticate_sets_accountability,
            default_accountability_is_object,
            token_helper_returns_default,
        ]
    )

    websocket_accountability_covered = contains_all(
        websocket_base,
        [
            "if (this.authentication.mode === 'strict' || query['access_token'] || cookies[sessionCookieName])",
            "await this.handleTokenUpgrade(context, token)",
            "if (!token || !accountability || !accountability.user)",
            "await this.handleHandshakeUpgrade(context)",
            "accountability: createDefaultAccountability(accountabilityOverrides)",
            "client.accountability = accountability",
        ],
    ) and contains_all(
        websocket_authenticate,
        [
            "const defaultAccountability = createDefaultAccountability(accountabilityOverrides)",
            "authenticationState.accountability = await getAccountabilityForToken(access_token, defaultAccountability)",
        ],
    )

    create_guard = contains_all(
        items_service,
        [
            "async createOne",
            "this.accountability",
            "processPayload(",
            "action: 'create'",
            "collection: this.collection",
        ],
    ) and contains_all(
        process_payload,
        [
            "if (!options.accountability.admin)",
            "fetchPolicies(options.accountability",
            "fetchPermissions(",
            "action: options.action",
            "collections: [options.collection]",
            "throw createCollectionForbiddenError",
            "throw createFieldsForbiddenError",
        ],
    )

    update_guard = contains_all(
        items_service,
        [
            "async updateMany",
            "await validateAccess(",
            "action: 'update'",
            "collection: this.collection",
            "primaryKeys: keys",
            "fields: Object.keys(payloadAfterHooks)",
        ],
    )

    delete_guard = contains_all(
        items_service,
        [
            "async deleteMany",
            "await validateAccess(",
            "action: 'delete'",
            "collection: this.collection",
            "primaryKeys: keysAfterHooks",
        ],
    )

    update_one_delegates = contains_all(items_service, ["async updateOne", "await this.updateMany([key], data, opts)"])
    delete_one_delegates = contains_all(items_service, ["async deleteOne", "await this.deleteMany([key], opts)"])
    update_by_query_delegates = contains_all(items_service, ["async updateByQuery", "return keys.length ? await this.updateMany(keys, data, opts)"])
    delete_by_query_delegates = contains_all(items_service, ["async deleteByQuery", "return keys.length ? await this.deleteMany(keys, opts)"])

    h001_sinks = evidence_locations(semgrep_index.get("H-001", []), "mutation_sink") or evidence_locations(
        joern_index.get("H-001", []), "mutation_sink"
    )
    h002_access_hits = evidence_locations(semgrep_index.get("H-002", [])) or evidence_locations(
        joern_index.get("H-002", [])
    )
    h003_param_sinks = evidence_locations(semgrep_index.get("H-003", []), "route_param_sink") or evidence_locations(
        joern_index.get("H-003", []), "route_param_sink"
    )
    h004_collab_hits = evidence_locations(semgrep_index.get("H-004", [])) or evidence_locations(
        joern_index.get("H-004", [])
    )
    h005_graphql_hits = evidence_locations(semgrep_index.get("H-005", [])) or evidence_locations(
        joern_index.get("H-005", [])
    )

    h001_covered = all(
        [
            permissions_extends_items,
            controllers_pass_accountability,
            create_guard,
            update_guard,
            delete_guard,
            update_one_delegates,
            delete_one_delegates,
            update_by_query_delegates,
            delete_by_query_delegates,
            request_accountability_covered,
        ]
    )

    h003_covered = all(
        [
            users_extends_items,
            users_controller_passes_accountability,
            update_guard,
            delete_guard,
            update_one_delegates,
            delete_one_delegates,
            request_accountability_covered,
        ]
    )

    permissions_me_guard = contains_all(
        permissions_controller,
        [
            "router.get(",
            "'/me'",
            "if (!req.accountability?.user && !req.accountability?.role && !req.accountability?.share)",
            "throw new ForbiddenError()",
            "fetchAccountabilityCollectionAccess(req.accountability",
        ],
    )

    permissions_me_summary_access = contains_all(
        fetch_accountability_access,
        [
            "export async function fetchAccountabilityCollectionAccess",
            "if (accountability.admin)",
            "const policies = await fetchPolicies(accountability, context)",
            "const permissions = await fetchPermissions({ policies, accountability }, context)",
            "const infos: CollectionAccess = {}",
            "return infos",
        ],
    )

    h002_covered = all([request_accountability_covered, permissions_me_guard, permissions_me_summary_access])

    collab_join_read_guard = contains_all(
        collab,
        [
            "async onJoin(client: WebSocketClient, message: JoinMessage)",
            "if (client.accountability?.share)",
            "await validateItemAccess(",
            "accountability: client.accountability!",
            "action: 'read'",
            "if (!accessAllowed) throw new ForbiddenError()",
            "await room.join(client, message.color)",
        ],
    )

    collab_update_field_guard = contains_all(
        collab,
        [
            "await this.checkFieldsAccess(client, room, message.field, 'update'",
            "private async checkFieldsAccess(",
            "const allowedFields = await this.getAllowedFields(client, room, knex, schema)",
            "throw new ForbiddenError",
            "verifyPermissions(client.accountability, room.collection, room.item, 'read'",
            "verifyPermissions(client.accountability, room.collection, room.item, 'update'",
            "return intersection(read, update)",
        ],
    )

    collab_verify_guard = contains_all(
        collab_verify_permissions,
        [
            "if (!accountability) return []",
            "if (!schema.collections[collection]) return []",
            "if (accountability.admin) return ['*']",
            "const policies = await fetchPolicies(accountability",
            "const rawPermissions = await fetchPermissions(",
            "allowedFields = (await validateItemAccess(validationContext",
            "allowedFields = await fetchAllowedFields({ accountability, action, collection }",
            "permissionCache.getInvalidationCount() === startInvalidationCount",
        ],
    )

    h004_covered = all([websocket_accountability_covered, collab_join_read_guard, collab_update_field_guard, collab_verify_guard])

    graphql_system_route = contains_all(
        graphql_controller,
        [
            "router.use(",
            "'/system'",
            "const service = new GraphQLService({",
            "accountability: req.accountability",
            "scope: 'system'",
        ],
    )

    graphql_admin_resolver_wired = contains_all(
        graphql_system,
        [
            "import { resolveSystemAdmin } from './system-admin.js'",
            "resolveSystemAdmin(gql, schema, schemaComposer)",
        ],
    )

    graphql_admin_guard = contains_all(
        graphql_system_admin,
        [
            "export function resolveSystemAdmin(",
            "if (!gql.accountability?.admin)",
            "return",
            "schemaComposer.Mutation.addFields",
            "accountability: gql.accountability",
        ],
    )

    h005_covered = all(
        [graphql_request_accountability_covered, graphql_system_route, graphql_admin_resolver_wired, graphql_admin_guard]
    )

    coverage_items = [
        {
            "hypothesis_id": "H-001",
            "covered": h001_covered,
        },
        {
            "hypothesis_id": "H-002",
            "covered": h002_covered,
        },
        {
            "hypothesis_id": "H-003",
            "covered": h003_covered,
        },
        {
            "hypothesis_id": "H-004",
            "covered": h004_covered,
        },
        {
            "hypothesis_id": "H-005",
            "covered": h005_covered,
        },
    ]

    return {
        "coverage": [
            {
                "hypothesis_id": "H-001",
                "title": "Permission CRUD endpoints service-level authorization coverage",
                "coverage": "covered" if h001_covered else "partial",
                "reason": (
                    "Permission controller mutation sinks delegate to PermissionsService, which extends ItemsService. "
                    "Create/update/delete service paths have permission-processing or validateAccess guards. app.ts mounts "
                    "authenticate before /permissions, and authenticate creates default accountability before resolving any token, "
                    "so service-level this.accountability should be present for these routes."
                ),
                "request_accountability": {
                    "coverage": "covered" if request_accountability_covered else "unknown",
                    "guard_chain": [
                        "app.ts mounts authenticate before /permissions and /users routes",
                        "authenticate creates default accountability for every request",
                        "getAccountabilityForToken returns that accountability when no token is provided",
                        "invalid credentials/token throw before controller execution",
                    ],
                },
                "covered_sinks": [
                    {
                        "sink_family": "createOne/createMany",
                        "coverage": "covered" if create_guard and request_accountability_covered else "unknown",
                        "guard_chain": [
                            "controllers/permissions.ts passes req.accountability into PermissionsService",
                            "PermissionsService extends ItemsService",
                            "ItemsService.createOne calls processPayload(action='create') when this.accountability is present",
                            "processPayload fetches policies/permissions and rejects missing collection or fields",
                        ],
                    },
                    {
                        "sink_family": "updateOne/updateMany/updateBatch/updateByQuery",
                        "coverage": "covered" if update_guard and request_accountability_covered else "unknown",
                        "guard_chain": [
                            "updateOne delegates to updateMany",
                            "updateByQuery resolves keys then delegates to updateMany",
                            "ItemsService.updateMany calls validateAccess(action='update', primaryKeys=keys, fields=...) before DB update",
                        ],
                    },
                    {
                        "sink_family": "deleteOne/deleteMany/deleteByQuery",
                        "coverage": "covered" if delete_guard and request_accountability_covered else "unknown",
                        "guard_chain": [
                            "deleteOne delegates to deleteMany",
                            "deleteByQuery resolves keys then delegates to deleteMany",
                            "ItemsService.deleteMany calls validateAccess(action='delete', primaryKeys=keysAfterHooks) before DB delete",
                        ],
                    },
                ],
                "open_questions": [
                    "Are any mutation calls made outside this controller with service instances that intentionally omit accountability?",
                    "Can extensions or custom authenticate filters replace accountability with a weaker custom object?",
                ],
                "evidence": [
                    *h001_sinks,
                    line_ref("api/src/app.ts", find_line(app, r"app\.use\(authenticate\)") or 1, "authenticate middleware mounted before protected routes"),
                    line_ref("api/src/app.ts", find_line(app, r"app\.use\('/permissions'") or 1, "permissions router mounted after authenticate"),
                    line_ref("api/src/middleware/authenticate.ts", find_line(authenticate, r"createDefaultAccountability") or 1, "authenticate creates default accountability"),
                    line_ref("api/src/middleware/authenticate.ts", find_line(authenticate, r"req\.accountability = await getAccountabilityForToken") or 1, "authenticate assigns req.accountability"),
                    line_ref("api/src/utils/get-accountability-for-token.ts", find_line(get_accountability, r"return accountability") or 1, "token helper returns default accountability when no token exists"),
                    line_ref("api/src/services/permissions.ts", find_line(permissions_service, r"extends ItemsService") or 1, "PermissionsService extends ItemsService"),
                    line_ref("api/src/services/items.ts", find_line(items_service, r"processPayload\(") or 1, "create path calls processPayload"),
                    line_ref("api/src/services/items.ts", find_line(items_service, r"action: 'update'") or 1, "update validateAccess action"),
                    line_ref("api/src/services/items.ts", find_line(items_service, r"action: 'delete'") or 1, "delete validateAccess action"),
                    line_ref("api/src/permissions/modules/process-payload/process-payload.ts", find_line(process_payload, r"fetchPermissions") or 1, "processPayload fetches permissions"),
                ],
            },
            {
                "hypothesis_id": "H-002",
                "title": "permissions/me effective access exposure coverage",
                "coverage": "covered" if h002_covered else "partial",
                "reason": (
                    "The /permissions/me route requires user, role, or share accountability before returning data. It calls "
                    "fetchAccountabilityCollectionAccess, which derives a collection/action access summary from policies and "
                    "permissions instead of returning raw permission records. The route is mounted after authenticate, so "
                    "req.accountability is populated before this controller runs."
                ),
                "request_accountability": {
                    "coverage": "covered" if request_accountability_covered else "unknown",
                    "guard_chain": [
                        "app.ts mounts authenticate before /permissions",
                        "authenticate creates default accountability for every request",
                        "permissions/me explicitly rejects requests without user, role, or share accountability",
                    ],
                },
                "covered_sinks": [
                    {
                        "sink_family": "GET /permissions/me",
                        "coverage": "covered" if permissions_me_guard and permissions_me_summary_access else "unknown",
                        "guard_chain": [
                            "controller rejects anonymous accountability",
                            "controller calls fetchAccountabilityCollectionAccess",
                            "fetchAccountabilityCollectionAccess fetches policies and permissions for the current accountability",
                            "response is a CollectionAccess summary keyed by collection/action, not raw permission rows",
                        ],
                    }
                ],
                "open_questions": [
                    "Is the summarized CollectionAccess shape intended to be visible to share-based accountability?",
                    "Should product policy hide field-level access metadata from low-trust clients even when technically authorized?",
                ],
                "evidence": [
                    *h002_access_hits,
                    line_ref("api/src/controllers/permissions.ts", find_line(permissions_controller, r"router\.get\(") or 1, "permissions controller defines routes"),
                    line_ref("api/src/controllers/permissions.ts", find_line(permissions_controller, r"req\.accountability\?\.share") or 1, "permissions/me accountability guard"),
                    line_ref("api/src/controllers/permissions.ts", find_line(permissions_controller, r"fetchAccountabilityCollectionAccess") or 1, "permissions/me uses summarized access helper"),
                    line_ref(
                        "api/src/permissions/modules/fetch-accountability-collection-access/fetch-accountability-collection-access.ts",
                        find_line(fetch_accountability_access, r"fetchPolicies") or 1,
                        "access helper fetches current-accountability policies",
                    ),
                    line_ref(
                        "api/src/permissions/modules/fetch-accountability-collection-access/fetch-accountability-collection-access.ts",
                        find_line(fetch_accountability_access, r"fetchPermissions") or 1,
                        "access helper fetches current-accountability permissions",
                    ),
                    line_ref(
                        "api/src/permissions/modules/fetch-accountability-collection-access/fetch-accountability-collection-access.ts",
                        find_line(fetch_accountability_access, r"return infos") or 1,
                        "access helper returns summarized CollectionAccess data",
                    ),
                ],
            },
            {
                "hypothesis_id": "H-003",
                "title": "users/:pk mutation IDOR service-level authorization coverage",
                "coverage": "covered" if h003_covered else "partial",
                "reason": (
                    "The /me update paths use req.accountability.user directly, while /:pk paths pass req.params['pk'] into UsersService. "
                    "UsersService extends ItemsService, and ItemsService update/delete paths validate the same target primary keys before mutation. "
                    "app.ts mounts authenticate before /users, and authenticate guarantees req.accountability is populated with either resolved token "
                    "accountability or default public accountability before controller execution."
                ),
                "request_accountability": {
                    "coverage": "covered" if request_accountability_covered else "unknown",
                    "guard_chain": [
                        "app.ts mounts authenticate before /users route",
                        "authenticate creates default accountability for every request",
                        "getAccountabilityForToken returns that accountability when no token is provided",
                        "invalid credentials/token throw before controller execution",
                    ],
                },
                "covered_sinks": [
                    {
                        "sink_family": "PATCH /me",
                        "coverage": "covered",
                        "guard_chain": [
                            "users controller checks req.accountability.user",
                            "users/me update uses req.accountability.user rather than route/body user id",
                        ],
                    },
                    {
                        "sink_family": "PATCH /:pk",
                        "coverage": "covered" if update_guard and request_accountability_covered else "unknown",
                        "guard_chain": [
                            "users/:pk update reaches UsersService.updateOne(req.params['pk'], ...)",
                            "UsersService extends ItemsService",
                            "ItemsService.updateOne delegates to updateMany([key])",
                            "ItemsService.updateMany validates action='update' with primaryKeys=keys before DB update",
                        ],
                    },
                    {
                        "sink_family": "DELETE /:pk",
                        "coverage": "covered" if delete_guard and request_accountability_covered else "unknown",
                        "guard_chain": [
                            "users/:pk delete reaches UsersService.deleteOne(req.params['pk'])",
                            "UsersService extends ItemsService",
                            "ItemsService.deleteOne delegates to deleteMany([key])",
                            "ItemsService.deleteMany validates action='delete' with primaryKeys=keysAfterHooks before DB delete",
                        ],
                    },
                ],
                "open_questions": [
                    "Are any UsersService mutation calls made outside this controller with a service instance that omits accountability?",
                    "Can extensions or custom authenticate filters replace accountability with a weaker custom object?",
                ],
                "evidence": [
                    *h003_param_sinks,
                    line_ref("api/src/app.ts", find_line(app, r"app\.use\(authenticate\)") or 1, "authenticate middleware mounted before protected routes"),
                    line_ref("api/src/app.ts", find_line(app, r"app\.use\('/users'") or 1, "users router mounted after authenticate"),
                    line_ref("api/src/middleware/authenticate.ts", find_line(authenticate, r"createDefaultAccountability") or 1, "authenticate creates default accountability"),
                    line_ref("api/src/middleware/authenticate.ts", find_line(authenticate, r"req\.accountability = await getAccountabilityForToken") or 1, "authenticate assigns req.accountability"),
                    line_ref("api/src/controllers/users.ts", find_line(users_controller, r"req\.accountability\?\.user") or 1, "users/me requires accountability.user"),
                    line_ref("api/src/controllers/users.ts", find_line(users_controller, r"updateOne\(req\.accountability\.user") or 1, "users/me update uses self id"),
                    line_ref("api/src/services/users.ts", find_line(users_service, r"extends ItemsService") or 1, "UsersService extends ItemsService"),
                    line_ref("api/src/services/items.ts", find_line(items_service, r"await this\.updateMany\(\[key\]") or 1, "updateOne delegates to updateMany"),
                    line_ref("api/src/services/items.ts", find_line(items_service, r"await this\.deleteMany\(\[key\]") or 1, "deleteOne delegates to deleteMany"),
                    line_ref("api/src/services/items.ts", find_line(items_service, r"primaryKeys: keys") or 1, "update validation uses target keys"),
                    line_ref("api/src/services/items.ts", find_line(items_service, r"primaryKeys: keysAfterHooks") or 1, "delete validation uses target keys"),
                ],
            },
            {
                "hypothesis_id": "H-004",
                "title": "collaborative WebSocket item and field permission coverage",
                "coverage": "covered" if h004_covered else "partial",
                "reason": (
                    "Collaborative editing joins validate item read access before joining a room, reject share accountability, "
                    "and field updates/focus changes require both read and update permission checks. The verification helper uses "
                    "the same policy and permission libraries as REST authorization, denies missing accountability/unknown collections, "
                    "and avoids caching stale permissions when invalidation happens during async evaluation."
                ),
                "request_accountability": {
                    "coverage": "covered" if websocket_accountability_covered else "unknown",
                    "guard_chain": [
                        "WebSocket token and handshake modes authenticate before connection use",
                        "public mode creates default accountability",
                        "client.accountability is attached to the WebSocket client and reused by collab handlers",
                    ],
                },
                "covered_sinks": [
                    {
                        "sink_family": "collab join",
                        "coverage": "covered" if collab_join_read_guard else "unknown",
                        "guard_chain": [
                            "onJoin rejects share accountability",
                            "onJoin calls validateItemAccess(action='read') for the target collection/item",
                            "room.join happens only after accessAllowed is not false",
                        ],
                    },
                    {
                        "sink_family": "collab update/focus fields",
                        "coverage": "covered" if collab_update_field_guard and collab_verify_guard else "unknown",
                        "guard_chain": [
                            "update/focus calls checkFieldsAccess",
                            "checkFieldsAccess obtains allowed fields through verifyPermissions for read and update",
                            "allowed fields are intersected before permitting field operations",
                            "verifyPermissions fetches policies/permissions and falls back to validateItemAccess or fetchAllowedFields",
                        ],
                    },
                ],
                "open_questions": [
                    "Does deployment configuration ever enable collab in public WebSocket mode where public role permissions are broader than intended?",
                    "Are extension-provided websocket.authenticate filters allowed to return custom accountability that weakens the expected policy model?",
                ],
                "evidence": [
                    *h004_collab_hits,
                    line_ref("api/src/websocket/controllers/base.ts", find_line(websocket_base, r"handleTokenUpgrade") or 1, "WebSocket token upgrade path"),
                    line_ref("api/src/websocket/controllers/base.ts", find_line(websocket_base, r"handleHandshakeUpgrade") or 1, "WebSocket handshake auth path"),
                    line_ref("api/src/websocket/controllers/base.ts", find_line(websocket_base, r"client\.accountability = accountability") or 1, "WebSocket client stores accountability"),
                    line_ref("api/src/websocket/collab/collab.ts", find_line(collab, r"async onJoin") or 1, "collab join handler"),
                    line_ref("api/src/websocket/collab/collab.ts", find_line(collab, r"validateItemAccess") or 1, "join validates read permission"),
                    line_ref("api/src/websocket/collab/collab.ts", find_line(collab, r"checkFieldsAccess") or 1, "field operations pass through checkFieldsAccess"),
                    line_ref("api/src/websocket/collab/collab.ts", find_line(collab, r"verifyPermissions\(client\.accountability") or 1, "read/update field permission checks"),
                    line_ref("api/src/websocket/collab/verify-permissions.ts", find_line(collab_verify_permissions, r"fetchPolicies") or 1, "collab verifier fetches policies"),
                    line_ref("api/src/websocket/collab/verify-permissions.ts", find_line(collab_verify_permissions, r"fetchPermissions") or 1, "collab verifier fetches permissions"),
                    line_ref("api/src/websocket/collab/verify-permissions.ts", find_line(collab_verify_permissions, r"permissionCache\.getInvalidationCount") or 1, "cache invalidation guard"),
                ],
            },
            {
                "hypothesis_id": "H-005",
                "title": "GraphQL system admin resolver coverage",
                "coverage": "covered" if h005_covered else "partial",
                "reason": (
                    "The /graphql/system route passes req.accountability into GraphQLService and is mounted after authenticate. "
                    "System resolvers wire resolveSystemAdmin, and resolveSystemAdmin returns before adding admin mutation/query "
                    "fields unless gql.accountability.admin is true."
                ),
                "request_accountability": {
                    "coverage": "covered" if graphql_request_accountability_covered else "unknown",
                    "guard_chain": [
                        "app.ts mounts authenticate before /graphql",
                        "graphql/system creates GraphQLService with req.accountability",
                        "system resolver passes GraphQLService accountability into resolveSystemAdmin",
                    ],
                },
                "covered_sinks": [
                    {
                        "sink_family": "GraphQL system admin fields",
                        "coverage": "covered" if graphql_admin_guard else "unknown",
                        "guard_chain": [
                            "resolveSystemAdmin checks gql.accountability?.admin",
                            "non-admin execution returns before schemaComposer fields are added",
                            "admin field resolvers reuse gql.accountability when constructing services",
                        ],
                    }
                ],
                "open_questions": [
                    "Are there non-admin system GraphQL fields outside resolveSystemAdmin whose service-level authorization should be reviewed separately?",
                    "Can schema generation or introspection reveal admin-only field names to non-admin users even when resolvers are absent?",
                ],
                "evidence": [
                    *h005_graphql_hits,
                    line_ref("api/src/app.ts", find_line(app, r"app\.use\('/graphql'") or 1, "graphql router mounted after authenticate"),
                    line_ref("api/src/controllers/graphql.ts", find_line(graphql_controller, r"'/system'") or 1, "graphql/system route"),
                    line_ref("api/src/controllers/graphql.ts", find_line(graphql_controller, r"accountability: req\.accountability") or 1, "GraphQLService receives request accountability"),
                    line_ref("api/src/controllers/graphql.ts", find_line(graphql_controller, r"scope: 'system'") or 1, "system scope selected"),
                    line_ref("api/src/services/graphql/resolvers/system.ts", find_line(graphql_system, r"resolveSystemAdmin") or 1, "system resolver wires admin resolver"),
                    line_ref("api/src/services/graphql/resolvers/system-admin.ts", find_line(graphql_system_admin, r"if \(!gql\.accountability\?\.admin\)") or 1, "admin resolver guard"),
                    line_ref("api/src/services/graphql/resolvers/system-admin.ts", find_line(graphql_system_admin, r"schemaComposer\.Mutation\.addFields") or 1, "admin fields added after guard"),
                ],
            },
        ],
        "summary": {
            "assessed": len(coverage_items),
            "covered": sum(1 for item in coverage_items if item["covered"]),
            "partial": sum(1 for item in coverage_items if not item["covered"]),
            "unknown": 0,
            "confirmed_missing_guard": 0,
        },
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = ["# Guard Coverage", ""]
    summary = payload.get("summary", {})
    lines.extend(
        [
            "## Summary",
            "",
            f"- Assessed: {summary.get('assessed', 0)}",
            f"- Covered: {summary.get('covered', 0)}",
            f"- Partial: {summary.get('partial', 0)}",
            f"- Unknown: {summary.get('unknown', 0)}",
            f"- Confirmed missing guard: {summary.get('confirmed_missing_guard', 0)}",
            "",
        ]
    )
    for item in payload.get("coverage", []):
        lines.extend(
            [
                f"## {item['hypothesis_id']} - {item['title']}",
                "",
                f"- Coverage: `{item['coverage']}`",
                f"- Reason: {item['reason']}",
                "",
                "Covered sinks:",
            ]
        )
        for sink in item.get("covered_sinks", []):
            chain = " -> ".join(sink.get("guard_chain", []))
            lines.append(f"- `{sink['sink_family']}`: `{sink['coverage']}` - {chain}")
        request_accountability = item.get("request_accountability")
        if request_accountability:
            chain = " -> ".join(request_accountability.get("guard_chain", []))
            lines.extend(["", f"Request accountability: `{request_accountability.get('coverage')}` - {chain}"])
        lines.extend(["", "Open questions:"])
        for question in item.get("open_questions", []):
            lines.append(f"- {question}")
        lines.extend(["", "Evidence:"])
        for ev in item.get("evidence", [])[:20]:
            line = ev.get("line")
            path = ev.get("path")
            note = ev.get("note", "")
            lines.append(f"- `{path}:{line}` {note}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--semgrep", required=True, type=Path)
    parser.add_argument("--joern", required=True, type=Path)
    parser.add_argument(
        "--hypotheses",
        type=Path,
        help="When provided, emit conservative generic coverage for these hypotheses unless a project adapter is added.",
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--markdown", type=Path)
    args = parser.parse_args()

    if args.hypotheses and args.hypotheses.exists():
        payload = generic_unknown_coverage(load_hypotheses(args.hypotheses))
    else:
        payload = assess(args.repo_root, load_json(args.semgrep), load_json(args.joern))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(render_markdown(payload), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
