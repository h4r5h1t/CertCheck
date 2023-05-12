terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "4.64.0"
    }
  }
}

provider "aws" {
  # Configuration options
}

resource "aws_s3_bucket" "first-tf-bucket-tst" {
  bucket = "my-tf-tst-bucket-radom-1234567890"
  acl    = "private"
  #Ensure the S3 bucket has access logging enabled
  logging {
    target_bucket = "my-tf-tst-bucket-radom-1234567890"
    target_prefix = "logs/"
  }
  #Ensure that S3 buckets are encrypted with KMS by default"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }
  #Ensure all data stored in the S3 bucket have versioning enabled
  versioning {
    enabled = true
  }

  #Ensure that an S3 bucket has a lifecycle configuration
  lifecycle_rule {
    id      = "log"
    enabled = true
    prefix  = "log/"
    tags = {
      "rule" = "log"
    }
    transition {
      days          = 30
      storage_class = "GLACIER"
    }
    expiration {
      days = 90
    }
  }
  #Ensure that S3 bucket has cross-region replication enabled
  replication_configuration {
    role = "arn:aws:iam::123456789012:role/replication-role"
    rules {
      id     = "replication-rule"
      prefix = "log/"
      status = "Enabled"
      destination {
        bucket        = "arn:aws:s3:::my-tf-tst-bucket-radom-1234567890"
        storage_class = "STANDARD"
      }
    }
  }
}
resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = aws_s3_bucket.first-tf-bucket-tst.id

  topic {
    topic_arn     = "arn:aws:sqs:us-east-1:123456789012:my-tf-tst-bucket-radom-1234567890"
    events        = ["s3:ObjectCreated:*"]
    filter_suffix = ".log"
  }
}
resource "aws_s3_bucket_public_access_block" "example" {
  bucket = aws_s3_bucket.first-tf-bucket-tst.id

  block_public_acls       = false
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}