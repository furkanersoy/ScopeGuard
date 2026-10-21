# Safe comparison fixture for supported Terraform heuristics.
resource "aws_security_group" "training_private" {
  name = "scopeguard-private"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.20.0.0/16"]
  }
}

resource "aws_s3_bucket_public_access_block" "training" {
  bucket                  = "scopeguard-private-only"
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_db_instance" "training" {
  identifier          = "scopeguard-private-only"
  publicly_accessible = false
  storage_encrypted   = true
}
