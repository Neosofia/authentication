# Bootstrap

Creates the AWS resources that all other OpenTofu environments depend on:

| Resource | Name | Purpose |
|---|---|---|
| KMS key | `alias/pdc-tofu` | Encrypts S3 state objects and Secrets Manager secrets |
| S3 bucket | `pdc-tofu-state` | Versioned, KMS-encrypted remote state store |
| DynamoDB table | `pdc-tofu-locks` | State locking |

Run **once per AWS account**. The bootstrap cannot use the S3 backend it creates,
so it uses local state (`terraform.tfstate`).

## Why the state file is not committed

This is a public, operator-agnostic template repo. The local `terraform.tfstate`
contains your account's resource IDs (KMS ARN, bucket name, table ARN) — it is
operator-specific and must not be committed. Anyone forking this repo to deploy
their own infrastructure will run their own bootstrap and generate their own state.

The `.gitignore` excludes `*.tfstate` intentionally.

## Back up the bootstrap state

Because the bootstrap cannot use remote state, you are responsible for keeping
`terraform.tfstate` safe. Recommended options (pick one):

- Copy it into a password manager attachment (1Password, Bitwarden, etc.)
- Store it in an existing private S3 bucket or encrypted volume
- Keep it on the operator workstation and treat it like a credential

If you lose it, see [Recovering lost bootstrap state](#recovering-lost-bootstrap-state) below.

## First-time setup

```bash
# Prerequisites: AWS CLI configured, OpenTofu >= 1.7
cd infra/tofu/bootstrap
tofu init
tofu apply

# Save backend configs for each env (gitignored; regenerate any time from outputs)
tofu output -raw backend_config_staging > ../envs/staging/backend.conf
tofu output -raw backend_config_prod    > ../envs/prod/backend.conf
```

Then initialise each environment:

```bash
cd ../envs/staging
cp terraform.tfvars.example terraform.tfvars   # fill in your values
tofu init -backend-config=backend.conf
tofu apply
```

## Regenerating backend.conf

The `backend.conf` files are gitignored because they are derived outputs, not
source. If you have a healthy state file, regenerate them at any time:

```bash
cd infra/tofu/bootstrap
tofu output -raw backend_config_staging > ../envs/staging/backend.conf
tofu output -raw backend_config_prod    > ../envs/prod/backend.conf
```

## Recovering lost bootstrap state

If `terraform.tfstate` is lost, reconstruct it by importing the existing AWS
resources. This assumes the resources still exist in AWS.

### 1. Find your resource identifiers

```bash
# KMS key ID (the GUID, not the alias)
aws kms describe-key --key-id alias/pdc-tofu \
  --query 'KeyMetadata.KeyId' --output text

# S3 bucket (just the name)
aws s3api head-bucket --bucket pdc-tofu-state && echo "exists"

# DynamoDB table
aws dynamodb describe-table --table-name pdc-tofu-locks \
  --query 'Table.TableName' --output text
```

### 2. Re-initialise with empty state

```bash
cd infra/tofu/bootstrap
tofo init
```

### 3. Import each resource

```bash
# KMS key — use the GUID from step 1, not the alias
tofu import aws_kms_key.tofu <key-id>

# KMS alias
tofu import aws_kms_alias.tofu alias/pdc-tofu

# S3 bucket
tofu import aws_s3_bucket.state pdc-tofu-state

# S3 sub-resources (bucket ID is always the bucket name)
tofu import aws_s3_bucket_versioning.state pdc-tofu-state
tofu import aws_s3_bucket_server_side_encryption_configuration.state pdc-tofu-state
tofu import aws_s3_bucket_public_access_block.state pdc-tofu-state

# DynamoDB table
tofu import aws_dynamodb_table.locks pdc-tofu-locks
```

### 4. Verify — plan should show no changes

```bash
tofu plan
```

A clean plan (`No changes`) confirms state is consistent with reality.
Regenerate `backend.conf` files as above and you are back in business.
