# SC4013 — Capital One SSRF case reconstruction

A multi-container, local-only case-study lab. It gives you two separate HTTPS endpoints:

- **Victim site:** <https://northstar.localhost:8443> — a fictional production-style financial client portal backed by an in-memory SQLite database of synthetic PII.
- **Attacker PC:** <https://localhost:7681> — a minimal Kali Linux container with an interactive Bash shell over HTTPS (`ttyd`), plus Nmap, ffuf, curl, grep, jq and AWS CLI.

These are separate containers, not two panels in one app. The Kali container has no desktop GUI and no Internet route. Its reachable app endpoints are the victim's HTTPS listener and the HTTPS mock S3 service. It cannot resolve or reach the metadata container.

## Compile and run

Requirements: Docker Engine + Compose, OpenSSL, and an x86-64 host (the pinned ttyd binary is x86-64).

From a terminal on the Docker host:

```sh
cd /home/kur0/Documents/SC4013-PoC
./scripts/generate-certs.sh
docker compose build
docker compose up -d
docker compose ps
```

`docker compose build` compiles the victim, mock services, Kali workstation, and TLS gateway images. `docker compose up -d` starts the containers in the background; `docker compose ps` should show five healthy services. For a one-command rebuild and launch, use `docker compose up --build -d` instead of the separate build/start commands.

Open the two HTTPS endpoints in your browser:

- Victim: <https://northstar.localhost:8443>
- Attacker Kali terminal: <https://localhost:7681>

Keep the victim portal and its observer feed open in separate tabs:

- Client portal: <https://northstar.localhost:8443>
- Sanitized live event feed: <https://northstar.localhost:8443/security/audit>
- Attacker Kali terminal: <https://localhost:7681>

The local lab certificate is self-signed. On first visit, accept the browser's warning for these loopback-only demo pages (or trust `/home/kur0/Documents/SC4013-PoC/.certs/lab.crt`). In the Kali terminal, run:

```sh
./run-kill-chain.sh
```

The terminal transcript uses real `nmap`, `ffuf`, `curl`, `jq`, `aws` commands. In an interactive terminal it pauses once after route discovery, then runs the authenticated request chain. It registers or reuses the fixed synthetic client account without printing that account's email/password, signs in, tests a normal preview, and sends the metadata URL through the SSRF feature. The fake role credential JSON is shown as the metadata response; the script then loads those values into the AWS CLI environment and runs `aws sts get-caller-identity` against the mock endpoint to verify the identity. It uses `aws s3 ls` and `aws s3 sync` to enumerate and download the synthetic export. The observer tab shows account creation, login, preview requests, WAF decisions, role discovery and credential return, while redacting session cookies and secrets from its audit feed.


Stop and remove the lab containers/networks with:

```sh
docker compose down
```

No host data volumes are mounted. The attacker `loot` directory and victim SQLite database are ephemeral; they are discarded when the containers are removed.

## Mock credentials (local simulation only)

The attacker run uses two separate credential sets:

**Fictional client-portal account.** The attack script uses this fixed pair on every build/run, so it is easy to present and reuse:

- Email: `demo.attacker@example.invalid`
- Password: `NorthstarDemo-2026!`

The script registers the account on the first run after the victim container starts, then reuses it on later runs. The victim's in-memory SQLite database stores only a salted password hash; recreating the victim container clears the account and the script registers the same pair again. To replay the account-creation event with the same credentials, reset the lab with `docker compose down && docker compose up -d` before running the script again. The app assigns a user ID when it creates the account; that ID may change after a container recreation.

**Mock workload-role credentials** (returned only by the private metadata mock):

```text
Role:              waf-demo-role
AccessKeyId:       SIMAKIA-NORTHSTAR-DEMO
SecretAccessKey:   SIMULATED-ONLY-NOT-AWS-SECRET-8B31
Session Token:     SIMULATED-ONLY-NOT-AWS-SESSION-9F42
Expiration:        2030-01-01T01:00:00Z
```

These are fixed teaching values, not valid AWS credentials. The mock S3 service accepts them only inside this Docker lab; never configure them for a real AWS account or service.

## Attack path

1. **Recon:** Kali inspects the victim's TLS service and public application surface. Nmap uses a TCP-connect scan limited to HTTPS port 443.
2. **Create or reuse the demo account:** the attacker registers the fixed synthetic `@example.invalid` portal account if it is not present, then signs in and receives an HttpOnly session cookie. The victim database stores only a salted password hash; the same pair is reused on later runs.
3. **Exploit:** using that authenticated session, the attacker submits the Capital One-style metadata URL to the document-preview endpoint:
   `http://169.254.169.254/latest/meta-data/iam/security-credentials/`

   In this lab the request is a JSON `POST` over HTTPS to the fictional victim endpoint; the vulnerable victim handler, not Kali, resolves the metadata URL to a private mock service:
   ```sh
   curl --cacert /certs/lab.crt \
     -H 'Cookie: ns_session=<redacted-session>' \
     -H 'Content-Type: application/json' \
     --data-binary '{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}' \
     https://victim/api/document-preview
   ```
   The original Capital One request format and vulnerable route are not disclosed. This is the lab's representative SSRF request, not the historical payload. The same JSON request can be replayed manually with browser developer tools or a proxy such as Burp Repeater; use only the isolated `https://victim` endpoint in this lab.
4. **Metadata access:** the script sends the request using `curl` with an authenticated JSON body containing the standard metadata role path. The victim's intentionally vulnerable handler maps only the exact metadata role paths to the private mock metadata container. The observer records the request, WAF decision, role discovery and simulated credential return; secret values remain redacted in audit events. The real link-local address is never contacted.
5. **Credential validation and S3 access:** the script exports only the synthetic metadata response values into the AWS CLI environment, then runs `aws sts get-caller-identity` against the local mock endpoint. It enumerates accessible buckets and objects with `aws s3 ls`, then uses `aws s3 sync` to download the synthetic client export. The sample output identifies a mock role/account only; no AWS account or public cloud API is contacted. Successful list and sync calls demonstrate this mock role's effective bucket-list, object-list and object-read access; the incident sources do not publish an exact IAM policy or show that the attacker used an IAM policy simulation command.

The account-creation step is a fictional demo setup so the presentation can show a logged-in attacker using the vulnerable feature; it is not a claim that the Capital One attacker created a customer account. The AWS CLI does not have an interactive `login` command for this temporary role: the script supplies the retrieved credentials through environment variables, and `aws sts get-caller-identity` is the authenticated identity check. The four exfiltrated records are invented names, `.invalid` email addresses, reserved example phone numbers, demo account IDs, and `$0.00` balances. No host-to-host lateral movement is claimed; the cloud pivot shown is from the simulated WAF role to the S3 data the role can read. The victim SQLite DB and mock bucket are seeded from the same fictional sample set.

## Network and safety boundaries

- The only host-published service is the loopback-bound TCP gateway: IPv4 and IPv6 loopback ports `8443` tunnel TLS to the victim's port 443, and `7681` tunnel TLS to ttyd. The gateway does not terminate TLS. Metadata and mock S3 have no host-published ports.
- `edge` and `backend` are separate Docker networks, both `internal: true`. Kali, the victim, the gateway, and mock S3 use `edge`; metadata is reachable only on `backend` from the victim and mock S3. The gateway also joins a dedicated `ingress` bridge with IP masquerading disabled, solely so Docker can publish its two loopback ports; it runs as non-root and forwards only those fixed TCP destinations.
- All attacker-to-victim and attacker-to-mock-S3 traffic is TLS on port 443. The metadata API is plain HTTP only on the isolated backend network and is unreachable from Kali.
- The victim SSRF route accepts only the exact two metadata paths for the demo role; all other destinations are denied. The URL is converted to a fixed internal mock-service URL before any request is made. `POLICY_MODE=protected` denies metadata access while the fixed safe sample preview remains usable.
- The mock S3 server checks the fake access key and SigV4-shaped header, but does not implement AWS cryptographic signature verification. No AWS SDK endpoint, AWS account, public site, or external host is contacted.
- Containers run as non-root users, with read-only root filesystems, dropped capabilities (only bind-to-443 capability where required), `no-new-privileges`, internal Docker networking, and bounded temporary filesystems. The demo TLS key is self-signed and is generated locally under ignored `.certs/`.

## Policy modes

Vulnerable teaching mode is the default:

```sh
docker compose up --build -d
```

To run the protected variant instead:

```sh
POLICY_MODE=protected docker compose up --build -d
```

In protected mode the same SSRF attempt is denied by the victim and no mock metadata credentials are returned. Recreate the default mode with `POLICY_MODE=vulnerable docker compose up --build -d`.

## Tests

```sh
python3 -m unittest discover -s tests -v
python3 -m py_compile victim_service.py mock_metadata.py mock_s3.py gateway.py
bash -n attacker/run-kill-chain.sh
docker compose config -q
```

## Incident-source caveat

This is a **report-informed technical reconstruction**, not a claim to reproduce the exact production exploit. The public DOJ affidavit describes the misconfigured firewall/WAF, retrieval of a redacted WAF-role credential, bucket enumeration, and data copying, but it does not disclose the exact SSRF request, application route, WAF rule, or exploit code. The metadata-service-to-role-credentials-to-S3 route is presented in secondary technical reconstructions and used here as a representative teaching chain.

Sources:
1. U.S. v. Paige Thompson, complaint/affidavit, ¶¶10–12 (primary source): <https://www.justice.gov/media/1019711/dl?inline>
2. MIT Sloan, *The Capital One Data Breach* (technical reconstruction): <https://cams.mit.edu/wp-content/uploads/capitalonedatapaper.pdf>
3. Zscaler, *The Capital One Data Breach* (secondary analysis): <https://www.zscaler.com/resources/white-papers/capital-one-data-breach.pdf>
