# Firezone Self-Hosted Unlock & Enterprise Feature Plan

> Status: **living document**. Phase 1 in progress.
> Goal: deliver the full feature set requested in `active_requests.md#1` for a self-hosted Firezone build — remove all plan limits, unlock all gated enterprise features, then build the genuinely net-new capabilities.

## 0. Executive summary

Reconnaissance (3 parallel codebase sweeps, 2026-06-12) found that **~80% of the requested features already exist** in Firezone. They are not missing — they are gated behind:

1. **`Portal.Billing` plan limits** (`elixir/lib/portal/billing.ex`) — seat/count caps on users, service accounts, sites, admins, API clients/tokens. Driven by `Portal.Accounts.Limits` (embedded) + denormalized `*_limit_exceeded` boolean flags on the account.
2. **`Portal.Account.<feature>_enabled?` feature flags** (`elixir/lib/portal/account.ex`) — each gated by BOTH a global config flag (`:portal, :enabled_features`) AND a per-account embed (`Portal.Accounts.Features`).
3. **`client_to_client`** — a third, separate path gated by a global `features` DB-table row AND the per-account embed.

Therefore the work splits cleanly:

- **Phase 1 (this session): the unlock.** One config toggle that short-circuits both chokepoints. Delivers the bulk of the request, fully reviewable and testable, zero new schema.
- **Phases 2–6: the greenfield.** ~9 genuinely net-new capabilities spanning Rust data plane + Elixir control plane + 4 client platforms.

### What already exists (unlocked by Phase 1)

| Requested capability | Where it lives | Phase-1 action |
|---|---|---|
| Unlimited users / service accounts / sites / admins | `Portal.Billing` limit checks | Short-circuit → always allow |
| Unlimited API clients / tokens | `Portal.Billing` | Short-circuit |
| Unlimited policies / resources | (no count limit exists) | None needed |
| Directory sync — Entra, Google, Okta (users+groups+memberships) | `lib/portal/{entra,google,okta}/` | Unlock `idp_sync` |
| Conditional access (time-of-day, geo/region, IP/CIDR, auth-provider, client-verified) | `lib/portal/policies/condition.ex` + `evaluator.ex` | Unlock `policy_conditions` |
| Traffic restrictions (port/protocol filters per resource) | `lib/portal/resource.ex` `embeds_many :filters` | Unlock `traffic_filters` |
| Full tunnel / route-all (Internet Resource → `0.0.0.0/0`,`::/0`) | `connlib` + `Portal.Resource :internet` | Unlock `internet_resource` |
| REST API | `lib/portal_api/` | Unlock `rest_api` |
| Client-to-client | `channel.ex` + `features` table | Unlock `client_to_client` |
| SSO — Entra / Google / Okta / generic OIDC | `lib/portal/auth_provider.ex` adapters | Already on; no gate |
| Manual group / user creation in UI | `lib/portal_web/live/groups.ex`, `actors*` | Already on |
| Managed vs static vs IdP-synced groups | `lib/portal/group.ex` | Already on |
| Split DNS (portal-driven search domain + upstream selection) | `connlib` `dns_config.rs` | Already on |
| Manual client/device verification (`client_verified` condition) | `lib/portal/device.ex` `verified_at` + evaluator | Already on |
| Sites + geo load-balancing / failover | `lib/portal/site.ex`, `device.ex` `load_balance_gateways` | Already on |
| Resource access logs / audit (`policy_authorizations`) | `lib/portal/policy_authorization.ex` | Already on |
| MDM managed config (account slug, auth/api URL, connect-on-start, hide admin menu, …) | `policy-templates/` + `gui-client/src-tauri/src/settings.rs` | Already on |
| Custom account slug | MDM `accountSlug` key | Already on |

### What is genuinely net-new (Phases 2–6)

| Requested capability | Why net-new | Phase |
|---|---|---|
| Automated **device posture checks** (OS version, disk encryption, AV, patch level) | Only manual `client_verified` exists; no posture engine on client or condition props on server | 2 |
| **Always-on VPN** + lock UI / VPN on-off lock / disconnect-prevention (MDM-enforced) | No `always_on` / kill-switch anywhere in clients | 3 |
| **Bypass code** with timeframe + logging (temporary always-on override) | Depends on Phase 3 | 3 |
| **Client interface lock** (hide/lock settings via MDM) | Partial: `hideAdminPortalMenuItem`, `hideResourceList` exist; full lock net-new | 3 |
| **PKI for client certificates** (cert-based client identity / mTLS enrolment) | Client identity is token-based; no x509/PKI anywhere | 4 |
| **Cryptographically signed policy delivery** + signature verification on client | Policy push is unsigned Phoenix channel cache updates | 4 |
| **Division of policies into client- vs user-policies**; rules by client AND user | Policies bind group→resource; no client-scoped axis | 5 |
| **URL allow/deny lists / zones** (website allowed/denied per client/user) | DNS resources match domains but no allow/deny zone abstraction or per-identity website policy | 5 |
| **Client app DNS forcing** (force VPN-tunnel DNS, block local DNS) | Split-DNS is portal-driven; no client-forced DNS lock | 5 |
| **SAML SSO** | Only OIDC/OAuth adapters exist | 6 |
| **JumpCloud / generic-OIDC directory sync** | Only Entra/Google/Okta sync; OIDC is auth-only | 6 |
| **Custom client icon push** from admin UI to clients | No branding/asset push channel | 6 |
| **UDP hole-punching** | ALREADY EXISTS (`snownet` ICE) — no work, listed for completeness | — |
| **Zero-trust, "client always connects to mgmt but no traffic without rules"** | ALREADY the architecture (deny-by-default policies) — config/doc only | — |

---

## 1. Phase 1 — The Unlock (Elixir control plane)

**Mechanism (per user decision): single config toggle `FIREZONE_SELF_HOSTED_UNLOCKED`, default `true`.**
One documented flag that short-circuits the limit + feature chokepoints. Survives Stripe webhook events (logic-level, not data-level), self-documents intent, fully reversible (set `false` to restore commercial gating), one source of truth.

### 1.1 Config plumbing
- `config/config.exs` — add `config :portal, :self_hosted_unlocked, true` (compile default).
- `config/runtime.exs` — add `config :portal, :self_hosted_unlocked, env_var_to_config!(:self_hosted_unlocked)`.
- `lib/portal/config/definitions.ex` — `defconfig(:self_hosted_unlocked, :boolean, default: true)` with doc.
- `lib/portal/config.ex` — `def self_hosted_unlocked?, do: fetch_env!(:portal, :self_hosted_unlocked)`.

### 1.2 Limits chokepoint — `lib/portal/billing.ex`
Add `defp unlocked?, do: Portal.Config.self_hosted_unlocked?()` and short-circuit each predicate:
- `any_limit_exceeded?/1` → `false` when unlocked.
- `users_limit_exceeded?/2`, `seats_limit_exceeded?/2`, `service_accounts_limit_exceeded?/2`, `sites_limit_exceeded?/2`, `admins_limit_exceeded?/2`, `api_clients_limit_exceeded?/2`, `api_tokens_limit_exceeded?/2` → `false` when unlocked.
- `can_create_users?/1`, `can_create_service_accounts?/1`, `can_create_sites?/1`, `can_create_admin_users?/1`, `can_create_api_clients?/1`, `can_create_api_tokens?/2` → `true` when unlocked. **Bonus:** bypasses the `account.limits.<field>` deref, which fixes a latent crash for self-hosted accounts that have `nil` limits (never Stripe-provisioned).
- `client_sign_in_restricted?/1`, `client_connect_restricted?/1` → `false` when unlocked.

The `CheckAccountLimits` worker and `evaluate_account_limits/1` then naturally clear all `*_limit_exceeded` flags on their next run because every `*_limit_exceeded?` returns false.

### 1.3 Features chokepoint — `lib/portal/account.ex`
Modify the generated `<feature>_enabled?` body (the `for feature <- Features.__schema__(:fields)` block) to:
```elixir
Config.self_hosted_unlocked?() or
  (Config.global_feature_enabled?(unquote(feature)) and account_feature_enabled?(...))
```
Unlocks `policy_conditions`, `traffic_filters`, `idp_sync`, `rest_api`, `internet_resource`, `client_to_client` regardless of per-account embed or global config.

### 1.4 client_to_client second path
- `lib/portal_api/client/channel.ex` `Database.client_to_client_enabled?/1` → `Portal.Config.self_hosted_unlocked?() or (existing DB+embed check)`.
- `lib/portal_web/live/resources/components.ex` duplicate `client_to_client_enabled?/1` → same.

### 1.5 Admin UI reflects unlocked state — `lib/portal_web/live/settings/account.ex`
- `feature_enabled?/2` → also true when `Portal.Config.self_hosted_unlocked?()`, so the Plan Features panel shows everything enabled.
- (Optional polish, deferred) badge: "Self-hosted — all features unlocked".

### 1.6 Verification
- `mix compile --warnings-as-errors` (or at least clean compile) + `mix format`.
- Trace each chokepoint: unlocked path returns permissive value before any `account.limits` deref.
- Existing tests in `test/portal/billing_test.exs` assume gating — run them; where they now (correctly) see unlocked behaviour because the default flips, set `self_hosted_unlocked: false` in the test env so the commercial suite stays valid. (Test env override via `Portal.Config.put_env_override/3`.)
- Add focused tests: with unlocked `true`, every `can_create_*?` is true on a zero-limit account; every `<feature>_enabled?` is true with empty features.

### 1.7 Phase 1 file list
```
config/config.exs                                   (+1 line)
config/runtime.exs                                  (+1 line)
lib/portal/config/definitions.ex                    (+doc+defconfig)
lib/portal/config.ex                                (+helper)
lib/portal/billing.ex                               (+guard, ~14 fns)
lib/portal/account.ex                               (generated-fn body)
lib/portal_api/client/channel.ex                    (client_to_client)
lib/portal_web/live/resources/components.ex         (client_to_client)
lib/portal_web/live/settings/account.ex             (UI reflect)
config/test.exs or test setup                       (lock for commercial suite)
test/portal/self_hosted_unlock_test.exs             (new)
```

---

## 2. Phase 2 — Device posture checks — IMPLEMENTED (2026-06-12)

Status: **code-complete, syntax-verified** (all edited Elixir parses via `Code.string_to_quoted`; Rust statically reviewed — could not run `cargo`/`mix compile`/`mix test`: this box's TLS layer blocks `mix deps.get`, and no Rust toolchain. Compile + tests owed on an unrestricted box.)

Six posture conditions added, all reported by the client and **fail closed** (missing signal = violation):
`client_os_type`, `client_os_version`, `client_disk_encryption`, `client_firewall`, `client_antivirus`, `client_app_version`.

### Server (Elixir)
- **`lib/portal/policies/posture.ex`** (new) — `Portal.Policies.Posture`: `normalize/1` (accepts decoded map OR JSON-string wire form, retains only the 6 recognized keys, drops the rest), `compare_versions/2` + `version_at_least?/2` (dotted-numeric, not SemVer — OS versions aren't SemVer), `os_types/0`.
- **`lib/portal/policies/condition.ex`** — 6 posture properties + `is_version_greater_than_or_equal` operator; `valid_operators_for_property/1` + `validate_operator/1` branches; `validate_posture_version/2`.
- **`lib/portal/policies/evaluator.ex`** — `fetch_conformation_expiration/4` clauses for each posture property reading `session.posture`; helpers `posture_value/2`, `posture_version_at_least/3`, `posture_bool_is/2`. All fail closed.
- **`lib/portal/client_session.ex`** — `:posture, :map` field + `@type`. Available at every `ensure_conforms` call site (in-memory on the live channel path; re-fetched whole on the reauth path).
- **`priv/repo/migrations/20260219000000_add_client_sessions_posture.exs`** — `add(:posture, :map)`.
- **`lib/portal_api/client/socket.ex`** — `do_connect` reads `attrs["posture"]`, `Posture.normalize/1`, threads into `build_session/6` → `ClientSession.posture`.
- **UI `lib/portal_web/live/policies/components.ex`** — posture in both condition registries (`@all_conditions`, `available_conditions/1`); `condition_short_label`/`condition_type_label`/`condition_type_badge_class`/`condition_values_display`/`condition/1` clauses (+ a defensive `condition_type_label(_)` catch-all); one generic `posture_condition_form` covering all 6 (bool select / OS multi-checkbox / version text) wired into `conditions_form`.

### Client (Rust)
- **`rust/libs/bin-shared/src/posture.rs`** (new) — `PostureReport` (Serialize; field names match the server normalizer) + `collect()` with per-OS `cfg` probes: Windows (`cmd ver`, BitLocker via PowerShell, NetFirewallProfile, SecurityCenter2 AV), macOS (`sw_vers`, `fdesetup`, ALF globalstate, `spctl`), Linux (`uname`, `lsblk` crypt, `ufw`), plus a non-big-three fallback (all `None`). Every probe degrades to `None` on failure → never blocks connect. `to_param()` → compact JSON.
- **`rust/libs/bin-shared/src/lib.rs`** — `pub mod posture;`.
- **`rust/libs/connlib/phoenix-channel/src/login_url.rs`** — `DeviceInfo.posture: Option<String>`; appended as the `posture` connect query param (matches the existing `device_serial`/`device_uuid` pattern).
- **`rust/headless-client/src/main.rs`** + **`rust/gui-client/src-tauri/src/service.rs`** — set `posture: bin_shared::posture::collect().to_param()`.

### Tests (new, parse-checked)
- `test/portal/policies/posture_test.exs` — normalize (incl. JSON-string + key-stripping), version comparison, fail-closed.
- `test/portal/policies/condition/evaluator_posture_test.exs` — every property, both pass and fail-closed; violated-properties aggregation.
- `test/portal/policies/condition_test.exs` — posture validation branches appended.
- `rust/libs/bin-shared/src/posture.rs` `#[cfg(test)]` — JSON round-trip, BitLocker/count parsers.

### Known follow-ups (not blockers)
- **Trust model:** posture is client-reported advisory signal, not attestation — a rooted device can spoof it. Real attestation (TPM/Secure Enclave) is a separate, larger effort; documented intentionally as fail-closed advisory.
- **`client_app_version` source:** the Rust collector reports `bin_shared`'s `CARGO_PKG_VERSION`, which may differ from the app crate version. Alternative: evaluate `client_app_version` against the existing `ClientSession.version` (user-agent-derived, the real app version) instead of posture. Decide before shipping.
- **Re-evaluation cadence:** posture is captured at connect only. Periodic re-collection + push (re-auth on drift) is a follow-up.
- **Compile/test:** run `mix compile`, `mix test test/portal/policies/`, and `cargo test -p bin-shared` (+ `cargo clippy`) on a box without the TLS/toolchain restriction.

## 3. Phase 3 — Always-on VPN, UI/VPN lock, bypass codes — IMPLEMENTED (2026-06-12)

Status: **code-complete, syntax-verified.**

- **MDM keys** added across `MdmSettings` (`settings.rs`), the Windows loader (`settings/windows.rs`), the ADMX + ADML (`policy-templates/windows/`), and the macOS plist: `alwaysOn`, `lockTunnel`, `lockSettings`, `allowBypassCode`.
- **Client enforcement** (`gui-client/src-tauri/src/controller.rs`): `always_on()` forces connect at launch (`maybe_start_session`) and auto-reconnects on unexpected non-auth drops (`OnDisconnect`); `tunnel_locked()` blocks user sign-out/disconnect (auth-driven disconnects still apply).
- **Bypass code** (server): `Portal.BypassCode` schema (salted-hash, time-boxed, use-capped, revocable) + `Portal.BypassCodes` context (`issue`/`redeem`/`revoke`, every action logged for audit) + migration `20260220` + tests.
- **Follow-ups:** client-side bypass-code redemption UI; macOS/Linux MDM loaders reading the new keys (Windows ADMX is wired); `lockSettings` disabling the settings form; kill-switch (block traffic when tunnel down) — currently reconnect, not hard block.

## 4. Phase 4 — Signed policy delivery + PKI groundwork — IMPLEMENTED (2026-06-12)

Status: **code-complete, syntax-verified; signature verification is warn-only pending encoding parity.**

- **Account Ed25519 keypair**: `signing_public_key` / `signing_private_key` (redacted) on `Portal.Account` + migration `20260221` + `Account.ensure_signing_keypair_changeset/1`; generated at sign-up.
- **Crypto**: `Portal.Crypto.generate_signing_keypair/0`, `sign_message/2`, `verify_message/3` (Erlang `:crypto` eddsa/ed25519; never raises).
- **Signing**: `Portal.Policies.SignedDelivery` signs the `init` resources payload; the channel sends `resources_signature` + `signing_public_key` (`channel.ex` `init/3`).
- **Client**: `InitClient` carries the two new fields; `client-shared/src/signed_delivery.rs` verifies (Ed25519 via new `ed25519-dalek` dep) with full unit tests; the eventloop records receipt.
- **Follow-ups (security-critical):** verification is **warn-only** until the client reconstructs the portal's exact `Jason.encode!` canonical bytes (cross-language parity) — then flip to enforcement (reject on bad signature). Full **PKI client certs** (per-account CA, CSR enrolment, mTLS at the WSS transport) remain a separate effort; threat-model review owed per `docs/SECURITY.md`. **New dependency `ed25519-dalek` requires maintainer review.**

## 5. Phase 5 — Client vs user policies, URL zones, forced DNS — IMPLEMENTED (2026-06-12)

Status: **code-complete, syntax-verified.**

- **Policy scope**: `Portal.Policy.scope` `Ecto.Enum [:all, :user, :client]` (default `:all`) + migration `20260222`; enforced in `Portal.Cache.Client.Database.all_policies_for_actor_id!/2` (a policy applies when `:all`, or `:user`+human actor, or `:client`+service-account/api-client); added to all four policy cast sites; tests.
- **Forced DNS**: `force_tunnel_dns` on `Portal.Accounts.Config` → serialized in the client `Interface` view → new `force_tunnel_dns` field on the Rust `Interface` message + `ClientState` (threaded through `update_interface_config`; the 6 `Interface` test literals updated).
- **URL deny zones**: `Portal.Resource.kind` `Ecto.Enum [:allow, :deny]` (default `:allow`) + migration `20260223` + API cast — a `:deny` wildcard-DNS resource models a website deny-list.
- **Follow-ups:** OS-level enforcement of `force_tunnel_dns` (suppress system resolvers in `dns_control`); client-side blocking of `:deny` resources in the stub resolver; admin UI for scope/kind selectors (API-authorable now).

## 6. Phase 6 — SAML SSO, JumpCloud dir-sync, custom client icon — IMPLEMENTED (2026-06-12)

Status: **code-complete, syntax-verified (registration + schema scaffolding; adapter internals are follow-ups).**

- **Custom client icon** (fully wired): `icon_url` (https-validated) on `Portal.Accounts.Config` → `Interface` view → pushed to clients via the existing `init` / `config_changed` paths (no channel changes). Client-side rendering of the icon is the remaining client task.
- **SAML adapter**: `Portal.SAML.AuthProvider` schema (IdP SSO URL, entity ID, signing cert, SP entity ID, email attribute) + registered in `Portal.AuthProvider` (`@provider_types`, enum, `has_one`) + `Account` assoc + migration `20260224` (table + type-check-constraint update).
- **JumpCloud directory**: `Portal.JumpCloud.Directory` schema (API-key auth, mirroring Okta) + registered in `Portal.Directory` enum + `has_one` + `Account` assoc + migration `20260225`.
- **Follow-ups:** SAML web controller (AuthnRequest → ACS assertion validation, reusing the OIDC identity/session tail) + a SAML lib (`:esaml`/`Samly`) + router routes; JumpCloud `api_client`/`scheduler`/`sync`/`error_handler` (mirror Okta's, reuse the shared batch-upsert pipeline) + Oban crontab/queue config; admin UI forms for both.

---

## 8. Verification & toolchain note (all phases)

- **Elixir**: every touched file (47 across all phases) passes `Code.string_to_quoted` (real syntax validation). `mix compile`/`mix test`/`mix format` could **not** run on the dev box — its endpoint-security layer TLS-resets `erl.exe`, blocking `mix deps.get` (`.formatter.exs` needs `import_deps`). Run on an unrestricted box:
  `mix compile --warnings-as-errors && mix format --check-formatted && mix test`.
- **Rust**: statically reviewed (struct/cfg/type/borrow); no `cargo` on the box. Run: `cargo check`, `cargo test -p bin-shared -p client-shared`, `cargo clippy`. New dep: `ed25519-dalek` (Phase 4) — flag for review.
- **New schema** (run migrations): `client_sessions.posture`, `bypass_codes`, `accounts.signing_*`, `policies.scope`, `resources.kind`, `saml_auth_providers`, `jumpcloud_directories`.

---

## 7. Sequencing & risk

1. **Phase 1 first** — unblocks the majority of the request, no schema risk, reversible. ← in progress.
2. Phase 2 (posture) and Phase 6 (SAML/JumpCloud) are independent and parallelizable.
3. Phase 4 (PKI/signed delivery) is the highest-risk, security-critical work — schedule a dedicated threat-model review before coding.
4. Phase 3 (always-on/lock) and Phase 5 (forced DNS) share client-MDM surface — batch the ADMX/plist/Tauri/Swift/Kotlin changes.

**Upstream-divergence note:** every phase diverges from `firezone/main`. Keep changes guarded by the `self_hosted_unlocked` flag or clearly-scoped modules to ease rebasing onto upstream.
