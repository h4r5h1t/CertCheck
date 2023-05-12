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
}

resource "aws_s3_bucket_public_access_block" "example" {
  bucket = aws_s3_bucket.first-tf-bucket-tst.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# resource "aws_s3_bucket_policy" "bucket_policy" {
#   bucket = aws_s3_bucket.first-tf-bucket-tst.id
#   policy = data.aws_iam_policy_document.allow_public_access.json
# }

# data "aws_iam_policy_document" "allow_public_access" {
#   statement {
#     principals {
#       type        = "AWS"
#       identifiers = ["*"]
#     }

#     actions = ["*"]

#     resources = [
#       "${aws_s3_bucket.first-tf-bucket-tst.arn}/*",
#     ]
#   }
}
