# EXPECT: gen_iac_open_ingress
# EXPECT: gen_iac_public_storage
# EXPECT: gen_iac_public_database
# EXPECT: gen_iac_unencrypted_storage
# EXPECT: gen_iac_wildcard_iam
resource "aws_security_group_rule" "ssh_world" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_s3_bucket" "dumps" {
  bucket = "prod-db-dumps"
  acl    = "public-read"
}

resource "aws_db_instance" "main" {
  engine              = "postgres"
  storage_encrypted   = false
  publicly_accessible = true
}

resource "aws_iam_policy" "god" {
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}
