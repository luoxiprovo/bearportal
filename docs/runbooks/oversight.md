# Oversight sessions and operation policy

Grok Build is the selected harness integration, but **live generation is disabled**. The working SSH installer is deterministic backend code; it does not depend on a running model loop.

## Runtime boundary

[../../packages/operations/src/harness.ts](../../packages/operations/src/harness.ts) can construct `HarnessAgent` with `permissionMode: "allow-all"` and one wrapped tool, `read_deployment_state`. It does not invoke generation. `assertLiveHarnessDisabled` throws even with a dedicated `BEARPORTAL_XAI_API_KEY` or `BEARPORTAL_AI_GATEWAY_API_KEY`. An inherited generic developer API key is not control-plane authorization.

The oversight API does not import the harness module to start a model at API startup. Session, assessment, usage and gateway endpoints record and validate requests; they are not a supplied live runner/worker service.

## Registry and gateway

The catalog fixes operation key, version, capability, handler identifier, state and digest. The current digest hashes those metadata identifiers, not executable handler contents. Unknown, withdrawn or mismatched releases are refused.

The gateway tool catalog includes state reads, connection validation, DNS inspection, health probes, assignment reconciliation, checkpoint requests, repair proposals, human actions and diagnoses. Tenant/job/server authority comes from the server, not submitted tool arguments. Accepted requests can remain pending; an accepted operation is not host execution.

Unregistered shell/code, secret access, mailbox-body reads, cloud operations, self-approval and allocation/plan overrides are rejected. The gateway's `dns.write` ban applies to agent requests; trusted DNS credential forms and the installer still publish their defined records.

## Limits

Policy permits up to five minutes and 20 tool requests per invocation, with three invocations per failing checkpoint. Approvals last 30 minutes and bind to a plan hash. Human waits do not consume a live model loop, and unknown usage remains unknown.

These are enforced policy/recording limits. They do not establish measured model cost, a running watchdog service or an executed recovery action. Review [../../packages/operations/src/gateway.ts](../../packages/operations/src/gateway.ts) and [../../apps/api/src/oversight.ts](../../apps/api/src/oversight.ts) for actual completion checks.
