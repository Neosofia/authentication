# IAM resources for the auth service CT to read its own secret bundle.
#
# Creates a least-privilege IAM user + access key scoped to:
#   - secretsmanager:GetSecretValue on the bundle secret only
#   - kms:Decrypt on the KMS key used to encrypt it
#
# The access key is written into the CT alongside the env file (aws.env).
# On Fargate (prod) this user/key is NOT used — the ECS task role takes over.

resource "aws_iam_user" "ct_reader" {
  name = "pdc-auth-${var.environment}-ct-reader"
  path = "/pdc/authentication/"
  tags = {
    Project     = "pdc"
    Service     = "authentication"
    Environment = var.environment
    ManagedBy   = "opentofu"
  }
}

resource "aws_iam_access_key" "ct_reader" {
  user = aws_iam_user.ct_reader.name
}

data "aws_iam_policy_document" "ct_reader" {
  statement {
    sid    = "ReadSecretBundle"
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
    ]
    resources = [aws_secretsmanager_secret.bundle.arn]
  }

  statement {
    sid    = "DecryptWithKms"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
    ]
    resources = [data.aws_kms_alias.tofu.target_key_arn]
  }
}

resource "aws_iam_user_policy" "ct_reader" {
  name   = "pdc-auth-${var.environment}-ct-reader-policy"
  user   = aws_iam_user.ct_reader.name
  policy = data.aws_iam_policy_document.ct_reader.json
}
