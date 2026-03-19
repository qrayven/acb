# Access Controller Bridge: Architectural Proposal

## Integrating Hierarchies, Audit Trails, and Future Components via a Universal Authorization Pattern

**Status**: Proposal
**Date**: 2026-03-19
**Scope**: IOTA Trust Framework — cross-component authorization architecture

---

## Table of Contents

1. [Problem Statement](#1-problem-statement)
2. [Current State Analysis](#2-current-state-analysis)
3. [Architectural Critique](#3-architectural-critique)
4. [Guiding Principles](#4-guiding-principles)
5. [Proposed Solution: The Authorization Receipt Pattern](#5-proposed-solution-the-authorization-receipt-pattern)
6. [Detailed Design](#6-detailed-design)
7. [Authority Source Adapters](#7-authority-source-adapters)
8. [Impact on Existing Components](#8-impact-on-existing-components)
9. [Account Abstraction Considerations](#9-account-abstraction-considerations)
10. [Migration Path](#10-migration-path)
11. [Trade-offs and Alternatives Considered](#11-trade-offs-and-alternatives-considered)
12. [Conclusion](#12-conclusion)

---

## 1. Problem Statement

The IOTA Trust Framework consists of multiple components — Hierarchies, Notarization (including Audit Trails), Identity, and future additions — each of which needs some form of authorization to control who can perform which operations.

Currently these components solve authorization independently:

- **Hierarchies** manages delegated trust through federations, accreditations, and attestations — answering "who is authorized to make claims about which properties."
- **Audit Trails** embeds a full RBAC system (`RoleMap` from `tf_components`) inside each trail object — answering "who can perform which operations on this trail."
- **Notarization** (base) relies on Move's native object ownership — the owner controls the object entirely.

There is no mechanism for these authorization models to communicate. Hierarchies cannot influence audit trail permissions. An entity accredited by a federation still needs a separately-issued Capability from the trail's embedded RoleMap to add a record. The two authorization systems exist in parallel, disconnected.

**The goal**: Define a universal pattern — an "access controller bridge" — that allows any component requiring authorization to accept proof of authorization from any authority source, including but not limited to hierarchies.

---

## 2. Current State Analysis

### 2.1 Hierarchies (`hierarchies::main`)

The Federation is a **shared object** that implements hierarchical trust delegation:

```text
Root Authority
  └─> Accreditor (accreditation_to_accredit)
        └─> Attester (accreditation_to_attest)
              └─> validates property claims
```

**Authorization model**: Identity-centric. The federation checks `ctx.sender().to_id()` against its accreditation maps. Authorization is expressed as "entity X can attest/accredit properties Y with values Z."

**Capability objects**: `RootAuthorityCap` and `AccreditCap` are Move objects transferred to authorized addresses. They carry a `federation_id` for scoping.

**Key characteristic**: Hierarchies is an **authority source** — it determines who is authorized to do what within its domain (property-based claims). But it has no way to project that authority into other components.

### 2.2 Audit Trails (`audit_trail::main`)

The AuditTrail is a **shared object** that stores sequential records with role-based access control:

```move
public struct AuditTrail<D: store + copy> has key, store {
    id: UID,
    records: LinkedTable<u64, Record<D>>,      // DATA
    roles: RoleMap<Permission, RecordTags>,     // GOVERNANCE (embedded)
    // ...
}
```

**Authorization model**: Capability-centric. Every protected operation requires presenting a `tf_components::Capability` that is validated against the trail's embedded `RoleMap`. The `RoleMap` maps roles to permission sets (an enum of 17 permissions: `AddRecord`, `DeleteRecord`, `UpdateMetadata`, etc.).

**Key characteristic**: The audit trail is both the **resource** (data records) and the **governor** (its embedded RoleMap decides who gets access). Authorization is fully self-contained per trail.

### 2.3 Notarization (`iota_notarization::notarization`)

The Notarization object is an **owned object** (not shared) that stores immutable or mutable data:

**Authorization model**: Object ownership. If you own the `Notarization<D>` object, you can update/destroy it. Time-based restrictions (`TimeLock`) add temporal constraints but no identity-based authorization.

**Key characteristic**: The simplest and most Move-native authorization model. No custom RBAC needed because single-owner semantics handle it.

### 2.4 Product-Core (`tf_components`)

The shared library provides reusable primitives:

- **`Capability`**: A transferable token with `target_key` (scoped object), `role`, temporal validity (`valid_from`/`valid_until`), and optional address binding (`issued_to`).
- **`RoleMap<P, D>`**: Generic RBAC mapping roles to custom permission type `P`. Creates an initial admin role with a Capability. Supports role lifecycle, capability issuance/revocation, and denylist for revoked capabilities.
- **`TimeLock`**: Time-based restrictions (`UnlockAt`, `UntilDestroyed`, `Infinite`, `None`).

**Key characteristic**: These are the right primitives, but `Capability` creation is gated through `RoleMap` (the `new_capability` function requires an existing admin Capability validated by the RoleMap). There is no way for an external authority to issue Capabilities independently.

---

## 3. Architectural Critique

### 3.1 The Audit Trail Embeds Governance Inside the Resource

This is the central architectural issue. The `RoleMap` living inside `AuditTrail` means:

**Every trail is a permission silo.** There is no way to express "entity X is authorized across all trails of type Y." Each trail creates its own admin, its own roles, its own capabilities from scratch. Cross-trail authorization requires manual, out-of-band capability delegation for each individual trail.

**Permission management is entangled with data lifecycle.** The same object stores records (which may need to persist for decades in compliance scenarios) and authorization rules (which change as organizations evolve). Deleting the trail deletes its governance. Migrating the trail means migrating governance too.

**It reinvents what hierarchies already solves.** Hierarchies exists precisely to manage "who is authorized to do what" through delegated trust. Yet the audit trail ignores hierarchies entirely and builds its own parallel authorization system.

**It is not composable.** IOTA's strength is programmable transaction blocks (PTBs) that compose operations across packages. But the audit trail's authorization is closed — you cannot route authorization through an external system within a PTB.

### 3.2 The Analogy

In the real world, a notary's authority to notarize does not come from the stamp — it comes from a state licensing body. A doctor's ability to prescribe medicine comes from their medical license, not from the prescription pad.

Currently, the audit trail is like a prescription pad that decides who can use it. It should instead be like a prescription pad that verifies you hold a valid medical license — issued by an authority external to the pad itself.

### 3.3 Why Notarization Gets It Right (For Its Scope)

The base Notarization module uses Move's native object ownership. This is the correct choice for single-owner objects: the owner controls it, no custom authorization needed. It doesn't try to reinvent governance.

The audit trail can't use this approach because it's a shared object (multi-party access). But the solution isn't to embed a full governance system — it's to accept governance from external sources.

### 3.4 The `tf_components` Capability Is the Right Token, But Issuance Is Too Restricted

`tf_components::Capability` is already a good universal authorization token: scoped to a target, role-based, time-bounded, address-bindable. The problem is that only a `RoleMap` admin can issue Capabilities. There is no mechanism for an external authority (like hierarchies) to produce Capabilities or equivalent authorization proof independently.

---

## 4. Guiding Principles

The proposed solution is guided by principles drawn from IOTA's network philosophy and general blockchain design hygiene:

### 4.1 Separation of Concerns

Components should define **what operations are possible** (permission types) but not **who is authorized** (governance). Governance is a separate concern that should be pluggable.

### 4.2 Composability via PTBs

IOTA's programmable transaction blocks allow multiple package calls within a single atomic transaction. Authorization should work within this model: obtain authorization proof in one call, use it in the next, all within one PTB.

### 4.3 Move-Native Idioms

The solution should use established Move patterns — hot potatoes (types without `drop`), witness pattern, phantom types — rather than inventing novel mechanisms. The closest existing precedent is the **Kiosk TransferPolicy** pattern in IOTA/Sui.

### 4.4 Component Agnosticism

The pattern must work for any component that needs authorization, not just audit trails. Identity, future data registries, credential stores — any shared object with protected operations should be able to use the same pattern.

### 4.5 Authority Source Agnosticism

The pattern must work with any authority source: hierarchies federations today, direct RBAC for simple cases, Account Abstraction tomorrow, DAO governance in the future. No authority source should be privileged or hardcoded.

### 4.6 No New Concepts

The solution should not invent new authorization paradigms. It should apply existing blockchain patterns (specifically IOTA's TransferPolicy pattern) to the authorization domain.

---

## 5. Proposed Solution: The Authorization Receipt Pattern

### 5.1 Core Idea

Define two hot-potato types in `tf_components` (the shared library):

- **`ActionRequest<P>`** — created by a component before a protected operation. Declares what permission is needed. Has no `drop` ability — it MUST be consumed, enforcing that authorization cannot be skipped.

- **`ActionApproval<P>`** — produced by an authority source after verifying authorization. Also no `drop` — it MUST be consumed by the component to complete the operation.

The phantom type parameter `P` is the component's permission type (e.g., `audit_trail::permission::Permission`), ensuring type-safe matching between requests and approvals.

### 5.2 The Flow

Within a single PTB:

```text
1. Component.request_action()  →  ActionRequest<P>     (hot potato created)
2. AuthorityAdapter.approve()  →  ActionApproval<P>     (hot potato created)
3. Component.execute_action()  ←  consumes both          (hot potatoes destroyed)
```

If step 2 fails (unauthorized), the `ActionRequest` cannot be consumed, and the PTB aborts. Authorization cannot be bypassed.

### 5.3 Why Hot Potatoes

The hot potato pattern (types without `drop` ability) is Move's native enforcement mechanism:

- **Cannot be ignored**: If created, must be consumed. No way to "skip" authorization.
- **Cannot be stored**: No `store` ability means approvals can't be saved and replayed — they're single-use within a transaction.
- **Type-safe**: `ActionApproval<audit_trail::Permission>` cannot satisfy a request for `ActionApproval<identity::Permission>`.
- **Verifiable**: The creation and consumption happen on-chain in a single transaction — fully auditable.

### 5.4 Precedent: IOTA Kiosk TransferPolicy

This pattern is not new. IOTA (inherited from Sui) uses exactly this for kiosk transfers:

```text
Kiosk.list()        →  TransferRequest    (hot potato: "I want to transfer item X")
Rule.check()        →  Receipt added       (rule verifies conditions)
Policy.confirm()    ←  consumes request    (transfer completes)
```

The proposed pattern generalizes this from "transfer authorization" to "any operation authorization."

---

## 6. Detailed Design

### 6.1 Core Types (in `tf_components::authorization`)

```move
module tf_components::authorization;

use std::type_name::TypeName;

/// Created by a component at the start of a protected operation.
/// Hot potato: no `drop` — MUST be consumed.
public struct ActionRequest<phantom P: drop> {
    /// The shared object being acted upon
    target: ID,
    /// The component-specific permission required
    required_permission: P,
    /// The address requesting the action
    requester: address,
}

/// Produced by an authority source after verifying authorization.
/// Hot potato: no `drop` — MUST be consumed by the component.
public struct ActionApproval<phantom P: drop> {
    /// Must match the ActionRequest's target
    target: ID,
    /// Must match the ActionRequest's required_permission
    approved_permission: P,
    /// Identifies which authority source produced this approval
    authority: TypeName,
}

/// Create a new action request (called by components)
public fun new_request<P: drop>(
    target: ID,
    required_permission: P,
    requester: address,
): ActionRequest<P> {
    ActionRequest { target, required_permission, requester }
}

/// Verify that an approval matches a request and consume both.
/// Called by the component to gate the protected operation.
public fun verify_and_consume<P: drop>(
    request: ActionRequest<P>,
    approval: ActionApproval<P>,
) {
    let ActionRequest { target, required_permission: _, requester: _ } = request;
    let ActionApproval { target: approved_target, approved_permission: _, authority: _ } = approval;
    assert!(target == approved_target);
    // Both hot potatoes are consumed (destructured).
    // The operation may proceed.
}

/// Accessor: get the target from a request
public fun request_target<P: drop>(request: &ActionRequest<P>): ID {
    request.target
}

/// Accessor: get the required permission from a request
public fun request_permission<P: drop>(request: &ActionRequest<P>): &P {
    &request.required_permission
}

/// Accessor: get the requester address
public fun request_requester<P: drop>(request: &ActionRequest<P>): address {
    request.requester
}
```

### 6.2 How a Component Uses It (Audit Trail Example)

```move
module audit_trail::main;

use tf_components::authorization::{Self, ActionRequest, ActionApproval};

/// Create an authorization request for adding a record.
/// Returns a hot potato that must be fulfilled by an authority source.
public fun request_add_record<D: store + copy>(
    trail: &AuditTrail<D>,
    ctx: &TxContext,
): ActionRequest<Permission> {
    authorization::new_request(
        trail.id(),
        permission::add_record(),
        ctx.sender(),
    )
}

/// Add a record with externally-provided authorization.
/// Consumes both the request and approval hot potatoes.
public fun add_record_authorized<D: store + copy>(
    trail: &mut AuditTrail<D>,
    request: ActionRequest<Permission>,
    approval: ActionApproval<Permission>,
    stored_data: D,
    record_metadata: Option<String>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert!(trail.version == PACKAGE_VERSION, EPackageVersionMismatch);
    assert!(!locking::is_write_locked(&trail.locking_config, clock), ETrailWriteLocked);

    // Verify authorization and consume hot potatoes
    authorization::verify_and_consume(request, approval);

    // Pure data operation — no embedded RBAC check
    let caller = ctx.sender();
    let timestamp = clock::timestamp_ms(clock);
    let trail_id = trail.id();
    let seq = trail.sequence_number;

    let record = record::new(
        stored_data,
        record_metadata,
        seq,
        caller,
        timestamp,
        record::new_correction(),
    );

    linked_table::push_back(&mut trail.records, seq, record);
    trail.sequence_number = trail.sequence_number + 1;

    event::emit(RecordAdded {
        trail_id,
        sequence_number: seq,
        added_by: caller,
        timestamp,
    });
}
```

### 6.3 How an Authority Source Produces Approvals

Each authority source provides an adapter module:

```move
module hierarchies_bridge::adapter;

use hierarchies::main::{Federation, AccreditCap};
use hierarchies::property_name::PropertyName;
use tf_components::authorization::{Self, ActionRequest, ActionApproval};
use std::type_name;

/// Shared object mapping federation properties to component permissions.
/// Created once per federation-component pairing.
/// Example: "entities accredited for property 'RecordWriter' in federation F
///           are authorized for Permission::AddRecord on trail T"
public struct PermissionMapping<phantom P: drop> has key, store {
    id: UID,
    federation_id: ID,
    target_id: ID,
    mappings: VecMap<PropertyName, P>,
}

/// Approve an action request based on hierarchies accreditation.
///
/// Checks that the requester has a valid accreditation in the federation
/// for a property that maps to the requested permission.
public fun approve<P: drop + copy>(
    federation: &Federation,
    cap: &AccreditCap,
    mapping: &PermissionMapping<P>,
    request: &ActionRequest<P>,
    clock: &Clock,
    ctx: &TxContext,
): ActionApproval<P> {
    // 1. Verify the mapping matches the request's target
    assert!(mapping.target_id == authorization::request_target(request));
    assert!(mapping.federation_id == federation.federation_id());

    // 2. Find which property maps to the required permission
    //    and verify the requester has accreditation for it
    let required_permission = authorization::request_permission(request);
    // ... verify accreditation covers the required permission ...

    // 3. Produce approval
    ActionApproval {
        target: authorization::request_target(request),
        approved_permission: *required_permission,
        authority: type_name::get<PermissionMapping<P>>(),
    }
}
```

---

## 7. Authority Source Adapters

The pattern's power comes from supporting multiple authority sources through thin adapter modules. Each adapter translates its authority model into the universal `ActionApproval`.

### 7.1 Hierarchies Adapter

**Input**: Federation accreditation (property-based)
**Logic**: "If the requester is accredited for property X in federation F, and property X maps to permission P for target T, approve."
**Use case**: Organizational trust delegation — a federation root authority controls who can write to which audit trails.

### 7.2 RBAC Adapter (Backward Compatibility)

**Input**: `tf_components::Capability` + `RoleMap`
**Logic**: "If the presented Capability is valid in the RoleMap and carries the required permission, approve."
**Use case**: Simple, self-contained authorization for components that don't need external governance. Provides backward compatibility during migration.

```move
module rbac_bridge::adapter;

use tf_components::capability::Capability;
use tf_components::role_map::RoleMap;
use tf_components::authorization::{Self, ActionRequest, ActionApproval};

/// Approve based on existing RBAC Capability.
/// This adapter allows the current Capability-based system to produce
/// ActionApprovals, enabling gradual migration.
public fun approve<P: drop + copy, D: store>(
    role_map: &RoleMap<P, D>,
    cap: &Capability,
    request: &ActionRequest<P>,
    clock: &Clock,
    ctx: &TxContext,
): ActionApproval<P> {
    let required_permission = authorization::request_permission(request);
    role_map.assert_capability_valid(cap, required_permission, clock, ctx);

    ActionApproval {
        target: authorization::request_target(request),
        approved_permission: *required_permission,
        authority: type_name::get<RoleMap<P, D>>(),
    }
}
```

### 7.3 Account Abstraction Adapter (Future)

**Input**: `AuthContext` from AA framework
**Logic**: "If the AI Account's authenticator has already validated the transaction with claims that cover the required permission, approve."
**Use case**: Programmable authentication — the account itself encodes authorization rules (multisig, spending limits, time-locks, DAO governance).

```move
module aa_bridge::adapter;

/// Approve based on Account Abstraction authentication context.
/// The AI Account's AuthenticatorFunction has already validated
/// the transaction; this adapter extracts authorization claims.
public fun approve<P: drop + copy>(
    auth_context: &AuthContext,
    request: &ActionRequest<P>,
): ActionApproval<P> {
    // Extract authorization claims from the authenticated context
    // Verify they cover the required permission
    // ...
}
```

### 7.4 Composite Adapter (Multi-Authority)

For scenarios requiring authorization from multiple sources (e.g., both hierarchies accreditation AND a time-based condition):

```move
/// Require approvals from multiple authority sources.
/// Uses a collector pattern within a single PTB.
public fun begin_composite(request: &ActionRequest<P>): CompositeCollector<P> { ... }
public fun add_approval(collector: &mut CompositeCollector<P>, approval: ActionApproval<P>) { ... }
public fun finalize(collector: CompositeCollector<P>): ActionApproval<P> { ... }
```

---

## 8. Impact on Existing Components

### 8.1 Audit Trail

**What changes**: The `roles: RoleMap<Permission, RecordTags>` field is decoupled from the `AuditTrail` struct. Protected functions gain `_authorized` variants that accept `ActionRequest`/`ActionApproval` instead of checking the embedded RoleMap.

**Backward compatibility**: The existing `add_record(trail, cap, ...)` API can be preserved as a convenience wrapper that internally creates a request, approves it via the RBAC adapter, and executes — maintaining full backward compatibility while the ecosystem migrates.

**What the trail becomes**: A pure data structure with locking constraints. Authorization is fully external.

### 8.2 Hierarchies

**What changes**: Minimal. Hierarchies gains an adapter module (`hierarchies_bridge::adapter`) that translates federation accreditations into `ActionApproval` objects. The core hierarchies package remains unchanged.

**New artifact**: `PermissionMapping<P>` shared objects that define how federation properties map to component permissions. These are created and managed by federation root authorities.

### 8.3 Notarization (Base)

**No change needed.** Notarization objects are owned, not shared. Move's native object ownership is the correct and sufficient authorization model. The ActionRequest/Approval pattern is for shared objects with multi-party access.

### 8.4 tf_components (Product-Core)

**What changes**: A new `authorization` module is added containing `ActionRequest`, `ActionApproval`, and the `verify_and_consume` function. The existing `Capability` and `RoleMap` modules remain unchanged — the RBAC adapter bridges them into the new pattern.

---

## 9. Account Abstraction Considerations

The upcoming Account Abstraction (IIP discussion #35) introduces AI Accounts with programmable authentication via `AuthenticatorFunction`. This changes the landscape:

### 9.1 Authentication vs. Authorization

AA addresses **authentication** — "is this transaction from who it claims to be from?" It replaces cryptographic signature verification with custom Move logic.

The ActionRequest/Approval pattern addresses **authorization** — "is this authenticated entity allowed to perform this specific operation?" These are orthogonal concerns:

```text
AA (AuthenticatorFunction)    →  "This is genuinely Alice"
ActionRequest/Approval        →  "Alice is allowed to add records to trail X"
```

### 9.2 How AA Complements the Pattern

With AA, an AI Account's authenticator can embed authorization checks:

- **Multi-factor**: Require both a signature AND a hierarchies accreditation check
- **Delegated signing**: An employee's AI Account authenticates via the company's federation
- **Spending limits / scoped access**: The authenticator restricts which operations the account can perform

The AA adapter translates these authenticated claims into `ActionApproval` objects, making AA just another authority source in the universal pattern.

### 9.3 New Patterns AA Enables

- **Implicit authorization**: Instead of explicitly routing through hierarchies in the PTB, the AI Account's authenticator checks federation accreditation as part of authentication. The PTB becomes simpler.
- **Account-level policies**: Authorization rules live in the account definition rather than in external mapping objects, reducing on-chain state.
- **Recovery and rotation**: Authority delegation survives key rotation because it's tied to the account (a persistent object with stable address), not to a specific key.

---

## 10. Migration Path

### Phase 1: Define Core Types

Add `tf_components::authorization` module with `ActionRequest`, `ActionApproval`, `new_request`, `verify_and_consume`. This is a purely additive change with no impact on existing code.

### Phase 2: RBAC Adapter

Create the RBAC adapter that bridges existing `Capability` + `RoleMap` into the new pattern. This proves the pattern works with the existing authorization model and provides backward compatibility.

### Phase 3: Dual API on Audit Trail

Add `_authorized` variants of protected functions alongside existing ones. The existing functions become wrappers:

```move
// New: explicit external authorization
public fun add_record_authorized(trail, request, approval, data, ...) { ... }

// Existing: backward-compatible, delegates to RBAC adapter internally
public fun add_record(trail, cap, data, ...) {
    let request = request_add_record(trail, ctx);
    let approval = rbac_adapter::approve(&trail.roles, cap, &request, clock, ctx);
    add_record_authorized(trail, request, approval, data, ...);
}
```

### Phase 4: Hierarchies Adapter

Create the hierarchies adapter with `PermissionMapping` objects. Federation root authorities can now map accreditations to audit trail permissions. This is the core "bridge" deliverable.

### Phase 5: Decouple RoleMap from AuditTrail

Move `roles: RoleMap` out of the `AuditTrail` struct into a standalone shared object. The RBAC adapter references this external object. The audit trail becomes a pure data container.

This is the most disruptive change and should be done when the ecosystem is ready. It can be deferred or skipped if backward compatibility constraints require keeping the embedded RoleMap.

### Phase 6: AA Integration

When Account Abstraction ships, create the AA adapter. AI Accounts can then authorize component operations through their custom authenticators.

---

## 11. Trade-offs and Alternatives Considered

### 11.1 Alternative: Hierarchies Issues Capabilities Directly

**Idea**: Instead of a new pattern, have hierarchies issue `tf_components::Capability` objects for audit trail RoleMaps.

**Why rejected**: This makes hierarchies an admin of each trail's embedded RoleMap — it doesn't change the architecture, just adds a delegation path. The audit trail is still its own governance silo. Cross-component authorization still requires per-trail setup. And it couples hierarchies to the specific RoleMap implementation.

### 11.2 Alternative: Generic Authorization Policy Object

**Idea**: A `Policy<P>` shared object that dispatches to different authorization backends at runtime.

**Why rejected**: Move doesn't have dynamic dispatch or trait objects. A generic policy would require enumerating all possible backends at compile time, which isn't extensible. The hot potato pattern achieves the same goal through composition rather than dispatch.

### 11.3 Alternative: Keep Embedded RBAC, Add Hierarchies as Another Admin

**Idea**: Don't change the architecture. Just give hierarchies a way to manage the audit trail's embedded RoleMap.

**Why rejected**: This is the least disruptive but doesn't solve the fundamental problem. Every component still embeds its own governance. Cross-component policies still require per-component setup. The pattern doesn't generalize to future components or authority sources.

### 11.4 Trade-off: PTB Complexity

The proposed pattern requires more steps in a PTB: create request, route to authority, consume approval. The current pattern is simpler: call function with Capability.

**Mitigation**: Convenience wrappers (Phase 3) hide this complexity for common cases. SDK-level helpers can compose the PTB steps. The added explicitness is a feature in security-sensitive contexts — authorization flow is visible and auditable.

### 11.5 Trade-off: Additional On-Chain Objects

`PermissionMapping` objects add on-chain state. Each federation-component pairing needs a mapping.

**Mitigation**: These are small, infrequently modified objects. The storage cost is negligible compared to the records stored in audit trails. They can be frozen (made immutable) once established to avoid future transaction costs.

### 11.6 Trade-off: Breaking Change vs. Backward Compatibility

The full vision (Phase 5: decoupling RoleMap) is a breaking change for the audit trail.

**Mitigation**: The phased approach allows incremental adoption. The RBAC adapter ensures existing Capability-based workflows continue to work. Components can opt into external authorization at their own pace.

---

## 12. Conclusion

The current IOTA Trust Framework components each solve authorization independently, resulting in disconnected governance silos. The audit trail embeds a full RBAC system that cannot communicate with hierarchies — the very component designed to manage delegated authority.

The proposed solution applies IOTA's existing **TransferPolicy pattern** (authorization receipts via hot potatoes) to the general authorization domain:

1. **Components** define what operations exist (permission types) and create `ActionRequest` hot potatoes for protected operations.
2. **Authority sources** (hierarchies, RBAC, Account Abstraction, future systems) verify authorization and produce `ActionApproval` hot potatoes.
3. **Components** consume both to execute the operation.

This pattern is:

- **Not a new invention** — it is the established Kiosk TransferPolicy pattern generalized to any authorization domain.
- **Move-native** — hot potatoes, phantom types, PTB composability.
- **Component-agnostic** — any shared object can use it.
- **Authority-agnostic** — any authorization system can produce approvals.
- **Future-proof** — Account Abstraction becomes just another authority source adapter.

The bridge is not a single module or package. **The bridge is the protocol** — the `ActionRequest<P>` and `ActionApproval<P>` types that flow between components and authority sources within a PTB. Adapters are thin translation layers. The pattern connects any component to any authority source, now and in the future.

---

## Appendix A: Visual Architecture

```text
                    ┌─────────────────────────────────────┐
                    │    tf_components::authorization       │
                    │                                       │
                    │   ActionRequest<P>   ActionApproval<P>│
                    │   (the universal protocol)            │
                    └──────────────┬────────────────────────┘
                                   │
                ┌──────────────────┼──────────────────────┐
                │                  │                      │
       ┌────────▼────────┐  ┌─────▼────────────┐  ┌──────▼───────────┐
       │   Hierarchies    │  │   RBAC (legacy)   │  │   AA Accounts    │
       │   Adapter        │  │   Adapter          │  │   Adapter        │
       │                  │  │                    │  │   (future)       │
       │   Federation     │  │   RoleMap +        │  │   AuthContext →  │
       │   Accreditation  │  │   Capability →     │  │   Approval       │
       │   → Approval     │  │   Approval         │  │                  │
       └─────────────────┘  └────────────────────┘  └──────────────────┘
                │                  │                      │
                └──────────────────┼──────────────────────┘
                                   │
                ┌──────────────────┼──────────────────────┐
                │                  │                      │
       ┌────────▼────────┐  ┌─────▼────────────┐  ┌──────▼───────────┐
       │   Audit Trail    │  │   Identity        │  │   Future          │
       │   (records)      │  │   (credentials)   │  │   Component X     │
       │                  │  │                    │  │                   │
       │   ActionRequest  │  │   ActionRequest    │  │   ActionRequest   │
       │   <Permission>   │  │   <IdPermission>   │  │   <XPermission>   │
       └─────────────────┘  └────────────────────┘  └───────────────────┘
```

## Appendix B: Comparison Table

| Aspect | Current State | Proposed State |
| --- | --- | --- |
| Authorization location | Embedded in each component | External, pluggable authority sources |
| Permission definition | Component-specific | Component-specific (unchanged) |
| Permission granting | Component's embedded RoleMap only | Any adapter: Hierarchies, RBAC, AA |
| Cross-component authorization | Impossible | Natural (same federation governs multiple components) |
| Pattern | Custom per component | Universal ActionRequest/Approval protocol |
| Move idiom | Capability checked internally | Hot potato consumed in PTB |
| Existing precedent | None (ad hoc) | Kiosk TransferPolicy pattern |
| Account Abstraction readiness | Not considered | First-class adapter slot |

## Appendix C: Referenced Materials

- **IOTA Network**: <https://docs.iota.org/>
- **Move Book (Object Model, Storage)**: <https://move-book.com/object/> , <https://move-book.com/storage/>
- **Hierarchies**: <https://github.com/iotaledger/hierarchies> , <https://docs.iota.org/developer/iota-hierarchies/>
- **Notarization**: <https://github.com/iotaledger/notarization> , <https://docs.iota.org/developer/iota-notarization/>
- **Product-Core (tf_components)**: <https://github.com/iotaledger/product-core/tree/feat/tf-compoenents-dev-revoked-caps/components_move>
- **Account Abstraction IIP**: <https://github.com/iotaledger/IIPs/discussions/35>
- **IOTA Kiosk TransferPolicy pattern**: <https://docs.iota.org/developer/standards/kiosk/>
