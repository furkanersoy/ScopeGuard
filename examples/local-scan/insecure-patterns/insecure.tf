# Synthetic Terraform patterns for ScopeGuard's offline checks only.
resource "aws_security_group" "training_public" {
  name = "scopeguard-training"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket_acl" "training_public" {
  bucket = "scopeguard-training-only"
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "training" {
  bucket                  = "scopeguard-training-only"
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_db_instance" "training" {
  identifier         = "scopeguard-training-only"
  publicly_accessible = true
  storage_encrypted   = false
}
