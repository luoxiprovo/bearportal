# Execution and capability manifest

Guided setup uses the API’s persistent onboarding queue to wait for capacity and authenticate the mail service. The live installation executor is `liveMailInstall`: fixed SSH/SCP argument arrays, staged credentials and the downloaded Bearmail installer. The operation gateway, compatibility host-command catalog and actual SSH runner are separate layers.

## SSH operations

Readiness uses six fixed sudo commands for OS/init/capacity/data-directory inspection. Installation creates private directories under `/var/lib/bearportal/install`, copies files, sets permissions, invokes `bearmail-install` for dry-run/apply, changes result ownership, fetches the result and removes staging. SSH arguments are checked for shell characters; callers cannot supply arbitrary shell text through that plan.

The remote login requires sudo privileges. Fixed application argument construction is not proof of an OS-enforced restricted-shell account. The operator must review SSH/network/sudo configuration independently.

## Compatibility host commands

Inventory names are `probe_readiness`, `probe_services`, `serve_ip_proof`, each with empty parameters.

Tenant names `install_release` and `upgrade_release` take `{ releaseId }`. Empty-parameter tenant names are `configure_relay`, `sync_mailboxes`, `set_mailbox_credential`, `read_mail_state`, `prepare_snapshot`, `resume_after_snapshot`, `stop_mail_services`, `resume_services`, `rotate_admin_credential`.

The catalog validates names and parameter shape; tenant authority is checked against assignment/job context. Current dispatch records `delivered: false` and opens no secret-delivery channel. These command names do not prove a host worker performs them. The upgrade-plan route does not execute `upgrade_release`.

## Agent restrictions

The registry/gateway rejects cloud VM/firewall/disk/region actions, arbitrary DNS writes, message-body reads, shell execution, IAM grants, secret reads, self-approval and allocation/plan overrides. `permissionMode: allow-all` in the disabled harness does not create those workers.

Trusted customer DNS forms can publish Brevo verification records and the remote installer can publish mail DNS; those are not agent-requested arbitrary DNS tools. The registry digest currently verifies metadata identifiers rather than executable bytes.

## Endpoint roles

New defaults are `mail.<domain>` for Stalwart/BearOS and `bearmail.<domain>` for Bearmail's human UI. Intended public mail ports are 25/465/993 plus HTTPS 443 and certificate HTTP 80. Relay SMTP is outbound 587. HTTP MCP and internal web/engine listeners stay on loopback under the installer configuration. Displayed ports are configuration, not a live reachability test.

Sources: [../../packages/servers/src/commands.ts](../../packages/servers/src/commands.ts), [../../packages/servers/src/ssh-install.ts](../../packages/servers/src/ssh-install.ts), [../../packages/operations/src/registry.ts](../../packages/operations/src/registry.ts).
