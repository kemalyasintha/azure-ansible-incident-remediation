# Azure Ansible Incident Remediation Lab

A production-style DevOps incident-response lab built with Azure, Ansible, Nginx, ASP.NET Core, Azure Application Gateway, and Azure Key Vault.

## Architecture

Internet traffic enters through Azure Application Gateway over HTTPS.

Application Gateway terminates TLS and load-balances traffic across two Ubuntu backend VMs.

Each VM runs:

- Nginx reverse proxy on port 80
- ASP.NET Core API on port 5000
- systemd service for API process management
- `/health` endpoint for Application Gateway health probes

Ansible manages backend configuration and automated remediation.

## Architecture Flow

```text
                         Internet
                            |
                        HTTPS :443
                            |
                            v
                +-----------------------+
                | Azure Application     |
                | Gateway               |
                | TLS termination       |
                | Health probes         |
                +-----------+-----------+
                            |
                   Load Balancing
                            |
                 +----------+----------+
                 |                     |
                 v                     v
          +-------------+       +-------------+
          |    VM01     |       |    VM02     |
          | 10.10.2.4   |       | 10.10.2.5   |
          +------+------+       +------+------+
                 |                     |
              Nginx :80             Nginx :80
                 |                     |
                 v                     v
          ASP.NET Core API      ASP.NET Core API
              :5000                 :5000
```

## Incident Scenario 1 - Configuration Drift

A manual configuration change is introduced on one backend VM.

The correct Nginx configuration:

```text
proxy_pass http://127.0.0.1:5000;
```

is deliberately changed to:

```text
proxy_pass http://127.0.0.1:5001;
```

The ASP.NET Core application remains healthy on port 5000, but Nginx can no longer reach it and returns `502 Bad Gateway`.

Application Gateway health probes detect the unhealthy backend and remove it from active traffic.

Traffic continues through the remaining healthy VM.

Ansible can then restore the declared Nginx configuration, restart/reload the required service, validate the health endpoint, and return the repaired VM to service.

## Incident Scenario 2 - TLS Certificate Lifecycle Remediation

The Application Gateway TLS certificate is monitored for expiration.

The Ansible remediation workflow:

1. Reads the certificate currently served by Application Gateway.
2. Extracts its expiration date.
3. Calculates the number of days remaining.
4. Compares the remaining lifetime with a configurable warning threshold.
5. Retrieves the PFX password from Azure Key Vault when remediation is required.
6. Generates a replacement private key and certificate.
7. Packages the replacement certificate into PFX format.
8. Updates the Application Gateway SSL certificate.
9. Polls the live HTTPS endpoint until the new certificate is served.
10. Verifies the deployed certificate expiration date.

This provides a complete:

```text
Detect -> Evaluate -> Remediate -> Verify
```

automation cycle.

## TLS Remediation Flow

```text
Application Gateway
        |
        v
Read live TLS certificate
        |
        v
Calculate days remaining
        |
        v
Is certificate near expiry?
        |
     +--+--+
     |     |
    No    Yes
     |     |
     |     v
     |  Azure Key Vault
     |     |
     |     v
     |  Retrieve PFX password
     |     |
     |     v
     |  Generate replacement certificate
     |     |
     |     v
     |  Create PFX
     |     |
     |     v
     |  Update Application Gateway
     |     |
     |     v
     |  Poll live HTTPS endpoint
     |     |
     |     v
     |  Verify replacement certificate
     |     |
     +-----+
        |
        v
      Healthy
```

## Azure Key Vault Integration

Sensitive certificate credentials are not hard-coded in the playbook.

The PFX password is stored in Azure Key Vault and retrieved only when certificate remediation is required.

Example secret:

```text
Key Vault:
kv-incident-api-lab

Secret:
incident-api-pfx-password
```

This separates secret management from automation code.

## Security Controls

The repository is configured to avoid committing sensitive or environment-specific files.

Examples excluded from source control include:

- Private SSH keys
- `.pfx` certificate files
- `.p12` certificate files
- `.pem` private-key material
- Generated TLS certificates
- Local Ansible inventory
- Build artifacts
- Environment files
- Temporary remediation artifacts

No certificate password is stored directly in the committed Ansible playbook.

## Ansible Playbooks

### `backend.yml`

Configures the backend Linux servers, including:

- Nginx
- ASP.NET Core application hosting
- systemd service configuration
- Nginx reverse proxy configuration
- API deployment
- service startup
- health validation

### `check-tls.yml`

Inspects the certificate presented by the production HTTPS endpoint and reports its expiration status.

### `remediate-tls.yml`

Implements automated TLS certificate remediation.

The playbook performs conditional remediation only when the certificate lifetime falls below the configured threshold.

For testing, the warning threshold can be overridden:

```bash
ansible-playbook -i localhost, remediate-tls.yml \
  -e "warning_days=400"
```

This forces the remediation path without having to wait for a real certificate to approach expiration.

## Repository Structure

```text
azure-ansible-incident-remediation/
|
|-- .gitignore
|-- ansible.cfg
|-- backend.yml
|-- check-tls.yml
|-- inventory.example.ini
|-- remediate-tls.yml
|
`-- templates/
    |-- incident-api-nginx.j2
    `-- incident-api.service.j2
```

`inventory.example.ini` contains placeholder backend addresses rather than environment-specific production values.

## Technologies Used

- Microsoft Azure
- Azure Application Gateway
- Azure Key Vault
- Azure Virtual Network
- Network Security Groups
- Azure CLI
- Ubuntu Linux
- Ansible
- Nginx
- ASP.NET Core 8
- systemd
- OpenSSL
- Git
- GitHub

## DevOps Concepts Demonstrated

This lab demonstrates:

- Infrastructure and application troubleshooting
- Configuration management
- Configuration drift remediation
- Declarative server configuration
- Reverse proxy configuration
- Application health checks
- Load-balancer health probes
- Backend failover
- TLS termination
- TLS certificate lifecycle management
- Azure Key Vault secret management
- Conditional Ansible execution
- Automated remediation
- Retry and polling patterns
- Post-remediation verification
- Source-control security
- Git-based infrastructure automation

## Failure and Recovery Model

The lab demonstrates an important production principle:

```text
Failure
   |
   v
Detection
   |
   v
Traffic Protection
   |
   v
Automated Remediation
   |
   v
Verification
   |
   v
Service Recovery
```

The objective is not simply to deploy infrastructure, but to demonstrate how infrastructure can detect failures, protect application traffic, remediate known failure conditions, and verify recovery.

## Project Status

Implemented and tested:

- Two-node backend architecture
- ASP.NET Core API deployment
- Nginx reverse proxy
- Application Gateway load balancing
- HTTPS/TLS termination
- Application Gateway health probes
- Backend failure simulation
- Automatic unhealthy-node removal
- Ansible configuration remediation
- TLS expiration detection
- Conditional TLS remediation
- Azure Key Vault secret retrieval
- Replacement certificate generation
- Application Gateway certificate update
- Live certificate verification
- Git source control

## Next Steps

Planned improvements include:

- GitHub Actions validation
- Ansible linting
- Automated syntax checks
- CI quality gates
- Architecture documentation
- Additional incident-remediation scenarios
