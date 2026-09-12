# Correct Terraform: HTTPS to the world, SSH only from the VPN, encrypted
# private database, public access blocked, scoped IAM.
resource "aws_security_group_rule" "https" {
  type        = "ingress"
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "ssh_vpn" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["10.8.0.0/16"]
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_db_instance" "main" {
  engine              = "postgres"
  storage_encrypted   = true
  publicly_accessible = false
  kms_key_id          = aws_kms_key.db.arn
}

resource "aws_iam_policy" "reader" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "arn:aws:s3:::app-assets/*"
    }]
  })
}
