# Clean a domain's DNS while keeping @ and www A records

This standalone command deletes other **editable** DNS records from one zone. It is separate from `reset:test-data:all` and does not modify BearPortal's database, subscriptions, Google users, cloud VMs or Brevo accounts.

It preserves every IPv4 A record at the bare domain (`@`, an empty name, or the domain itself) and `www`, with their existing addresses and TTLs. It also retains apex NS/SOA authority records. It removes other A records and AAAA, CNAME, MX, TXT, CAA, SRV and other supported editable records. A `www` **CNAME** is selected for deletion; only `www` **A** records are kept. Missing A records are not created or converted.

## Preview

Run from the BearPortal checkout in an interactive terminal:

```bash
pnpm dns:cleanup
```

Or provide the zone domain up front:

```bash
pnpm dns:cleanup --domain example.com
```

The command prints numbered steps for choosing the domain, detecting its provider, entering credentials, reviewing records, confirming deletion, saving a backup, deleting/verifying records, and completion. Each prompt explains what to enter and when to press Enter. Token prompts intentionally show no characters while typing or pasting. Blank credential entries are requested again; a blank deletion confirmation cancels. Ctrl+C at a prompt cancels cleanly without requesting DNS deletion.

The command resolves nameservers and detects **Name.com, Hostinger or GoDaddy**. Detection follows the DNS host, which may differ from the registrar. Unknown or mixed nameservers stop the command before credentials are requested. Enter the zone domain itself, rather than a URL or a hostname that is not a separately delegated DNS zone.

Depending on the detected provider, it prompts for:

| Provider | Credentials |
| --- | --- |
| Name.com | API username and API token |
| Hostinger | API bearer token from hPanel → profile → API |
| GoDaddy | Personal access token with domain DNS read/update access |

Tokens are entered with echo disabled, never accepted as command-line arguments, and never saved. Terminal input history is disabled. Use a token authorized to list and delete DNS records for this domain. The command does not read saved customer credentials from BearPortal.

Review the `KEEP` and `DELETE` rows. This default mode only lists records; it does not modify DNS or create a backup.

## Apply

Pause BearPortal setups and any other tools writing DNS for this domain. If using systemd, stop BearPortal **after any active installation has finished**:

```bash
sudo systemctl stop bearportal-api
```

Then run:

```bash
pnpm dns:cleanup --domain example.com --apply
```

Enter the requested credentials, review the fresh preview and type the exact domain when prompted. Entering anything else cancels without deleting records.

The command rechecks nameservers and the zone snapshot, writes a private `.data/backups/dns-cleanup-DOMAIN-*/zone-backup-and-receipt.json`, then deletes the selected records. The snapshot retains record IDs, original names, values, TTLs, priority and other provider fields. Each completed delete request is recorded. The provider API is read again to check that no selected records remain and that the preserved records are unchanged; automatic SOA serial changes are allowed. DNS caches can retain old answers until their TTL expires.

Afterward, restart BearPortal if you stopped it:

```bash
sudo systemctl start bearportal-api
```

Do not resume an old setup that will immediately republish records you intended to remove. For a complete test reset, combine this separate DNS step with the [test reset procedure](test-reset.md).

## Failures and limitations

A per-domain `.data/dns-cleanup-DOMAIN.lock` prevents simultaneous runs of this cleanup command. It does not lock provider dashboards or other DNS writers. If a process was killed, inspect `owner.json` and verify that process is no longer running before removing a stale lock.

Provider operations are not one transaction. On any error, earlier deletions can remain applied. A timeout can mean a request succeeded without acknowledgement. Inspect the printed backup/receipt, check the provider's current zone and rerun the preview before retrying. No automatic restore or blind replay is performed. To restore, recreate the required records through the provider using the private snapshot; record IDs may change.

GoDaddy's v1 delete endpoint supports A, AAAA, CAA, CNAME, MX, SRV and TXT. If the selected list contains another type, such as a delegated subdomain NS record, this command refuses the whole deletion before the first write; handle that record manually first. Provider-managed authority records remain. Unsupported response formats, incomplete pagination, credentials rejected by the provider or changed records stop the command rather than assuming the zone is empty.

## API references

- [Name.com v4 DNS list/get/delete](https://www.name.com/api-docs/dns)
- [Hostinger DNS get](https://docs.hostinger.com/api-reference/endpoints/dns/zone/get-dns-records), [delete](https://docs.hostinger.com/api-reference/endpoints/dns/zone/delete-dns-records) and [OpenAPI specification](https://developers.hostinger.com/openapi/openapi.json)
- [GoDaddy DNS list](https://developer.godaddy.com/en/docs/references/rest/domains/v1/record-get) and [delete by type/name](https://developer.godaddy.com/en/docs/references/rest/domains/v1/record-delete-type-name)
