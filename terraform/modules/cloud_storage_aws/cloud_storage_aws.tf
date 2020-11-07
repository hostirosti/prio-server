variable "environment" {
  type = string
}

variable "data_share_processor_gcp_sa_id" {
  type = string
}

variable "ingestor_gcp_service_account_id" {
  type        = string
  description = "Numeric ID of GCP SA used by ingestor to write content to ingestion buckets"
}

variable "resource_prefix" {
  type        = string
  description = "Prefix to apply to AWS resources, which are not namespaced by project as in GCP, and so must have unique names."
}

variable "ingestion_bucket_name" {
  type = string
}

variable "local_peer_validation_bucket_name" {
  type = string
}

variable "role_arn_assumed_by_remote_dsp" {
  type = string
}

# This is the AWS IAM role our GCP workloads assume in order to access S3
# buckets. It is configured to allow assumption by the GCP service account for
# this data share processor to assu via Web Identity Federation
# https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc.html
resource "aws_iam_role" "bucket_reader" {
  name = "${var.resource_prefix}-bucket-reader"
  # Since azp is set in the auth token Google generates, we must check oaud in
  # the role assumption policy, and the value must match what we request when
  # requesting tokens from the GKE metadata service in
  # S3Transport::new_with_client
  # https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html
  assume_role_policy = <<ROLE
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "accounts.google.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "accounts.google.com:sub": "${var.data_share_processor_gcp_sa_id}",
          "accounts.google.com:oaud": "prio-bucket-access"
        }
      }
    }
  ]
}
ROLE

  tags = {
    environment = "prio-${var.environment}"
  }
}

# This is the AWS IAM role used by ingestion servers to write to ingestion S3
# buckets. It is configured to allow assumption by a GCP service account that
# the ingestor is assumed to advertise.
resource "aws_iam_role" "ingestion_bucket_writer" {
  name               = "${var.resource_prefix}-ingestion-bucket-writer"
  assume_role_policy = <<ROLE
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "accounts.google.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "accounts.google.com:sub": "${var.ingestor_gcp_service_account_id}"
        }
      }
    }
  ]
}
ROLE

  tags = {
    environment = "prio-${var.environment}"
  }
}

# The S3 ingestion bucket. It is configured to allow writes from the AWS IAM
# role assumed by the ingestor and reads from the AWS IAM role assumed by this
# data share processor.
resource "aws_s3_bucket" "ingestion_bucket" {
  bucket = var.ingestion_bucket_name
  # Force deletion of bucket contents on bucket destroy.
  force_destroy = true
  policy        = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "${aws_iam_role.ingestion_bucket_writer.arn}"
      },
      "Action": [
        "s3:AbortMultipartUpload",
        "s3:PutObject",
        "s3:ListMultipartUploadParts",
        "s3:ListBucketMultipartUploads"
      ],
      "Resource": [
        "arn:aws:s3:::${var.ingestion_bucket_name}/*",
        "arn:aws:s3:::${var.ingestion_bucket_name}"
      ]
    },
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "${aws_iam_role.bucket_reader.arn}"
      },
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::${var.ingestion_bucket_name}/*",
        "arn:aws:s3:::${var.ingestion_bucket_name}"
      ]
    }
  ]
}
POLICY

  tags = {
    environment = "prio-${var.environment}"
  }
}

# The peer validation bucket for this data share processor, configured to permit
# the peer share processor to write to it.
resource "aws_s3_bucket" "local_peer_validation_bucket" {
  bucket = var.local_peer_validation_bucket_name
  # Force deletion of bucket contents on bucket destroy.
  force_destroy = true
  policy        = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "${var.role_arn_assumed_by_remote_dsp}"
      },
      "Action": [
        "s3:AbortMultipartUpload",
        "s3:PutObject",
        "s3:ListMultipartUploadParts",
        "s3:ListBucketMultipartUploads"
      ],
      "Resource": [
        "arn:aws:s3:::${var.local_peer_validation_bucket_name}/*",
        "arn:aws:s3:::${var.local_peer_validation_bucket_name}"
      ]
    },
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "${aws_iam_role.bucket_reader.arn}"
      },
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::${var.local_peer_validation_bucket_name}/*",
        "arn:aws:s3:::${var.local_peer_validation_bucket_name}"
      ]
    }
  ]
}
POLICY

  tags = {
    environment = "prio-${var.environment}"
  }
}

output "bucket_reader_role" {
  value = aws_iam_role.bucket_reader.arn
}
