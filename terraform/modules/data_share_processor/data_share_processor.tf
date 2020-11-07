variable "ingestor" {
  type = string
}

variable "data_share_processor_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "use_aws" {
  type = bool
}

variable "aws_region" {
  type = string
}

variable "gcp_project" {
  type = string
}

variable "gcp_region" {
  type = string
}

variable "kubernetes_namespace" {
  type = string
}

variable "packet_decryption_key_kubernetes_secret" {
  type = string
}

variable "certificate_domain" {
  type = string
}

variable "ingestor_manifest_base_url" {
  type = string
}

variable "ingestor_gcp_service_account_id" {
  type = string
}

variable "ingestor_gcp_service_account_email" {
  type = string
}

variable "identity_for_writing_to_remote_storage" {
  type = string
}

variable "remote_dsp_gcp_service_account_id" {
  type = string
}

variable "remote_dsp_gcp_service_account_email" {
  type = string
}

variable "remote_dsp_manifest_base_url" {
  type = string
}

variable "role_arn_assumed_by_remote_dsp" {
  type = string
}

variable "own_manifest_base_url" {
  type = string
}

variable "sum_part_bucket_service_account_email" {
  type = string
}

variable "portal_server_manifest_base_url" {
  type = string
}

variable "test_peer_environment" {
  type        = map(string)
  default     = {}
  description = "See main.tf for discussion."
}

variable "is_first" {
  type = bool
}

locals {
  resource_prefix         = "prio-${var.environment}-${var.data_share_processor_name}"
  is_env_with_ingestor    = lookup(var.test_peer_environment, "env_with_ingestor", "") == var.environment
  is_env_without_ingestor = lookup(var.test_peer_environment, "env_without_ingestor", "") == var.environment
  # There are three supported cases for who is writing to this data share
  # processor's ingestion bucket, listed in the order we check for them:
  #
  # 1 - This is a test environment that creates fake ingestors. The fake
  #     ingestors use this data share processor's GCP service account, so grant
  #     that SA write permissions on the ingestion bucket.
  # 2 - This is a test environment that does _not_ create fake ingestors. The
  #     peer test env's global manifest advertises a GCP SA that is meant for
  #     writing to validation buckets, and we grant it access to the ingestion
  #     bucket, too.
  # 3 - This is a non-test environment for an ingestor that advertises a GCP
  #     service account. We grant that SA write access to the ingestion bucket.
  #
  # The case we do not support here is granting access to an ingestor with an
  # AWS account. We assume all ingestors have a GCP service account.
  ingestion_bucket_writer_gcp_service_account = local.is_env_with_ingestor ? (
    {
      id    = module.kubernetes.service_account_unique_id
      email = module.kubernetes.service_account_email
    }
    ) : local.is_env_without_ingestor ? (
    {
      id    = var.remote_dsp_gcp_service_account_id
      email = var.remote_dsp_gcp_service_account_email
    }
    ) : (
    {
      id    = var.ingestor_gcp_service_account_id
      email = var.ingestor_gcp_service_account_email
    }
  )
  ingestion_bucket_name = "${local.resource_prefix}-ingestion"
  ingestion_bucket_url = var.use_aws ? (
    "s3://${var.aws_region}/${local.ingestion_bucket_name}"
    ) : (
    "gs://${local.ingestion_bucket_name}"
  )
  local_peer_validation_bucket_name = "${local.resource_prefix}-peer-validation"
  local_peer_validation_bucket_url = var.use_aws ? (
    "s3://${var.aws_region}/${local.local_peer_validation_bucket_name}"
    ) : (
    "gs://${local.local_peer_validation_bucket_name}"
  )
  # If this environment creates fake ingestors, we assume that the other test
  # environment follows our naming convention and make an educated guess about
  # the name of their ingestion bucket so our fake ingestors can write ingestion
  # batches to them.
  test_peer_ingestion_bucket = local.is_env_with_ingestor ? (
    "s3://${var.test_peer_environment.aws_region}/prio-${var.test_peer_environment.env_without_ingestor}-${var.data_share_processor_name}-ingestion"
  ) : ""
  # If this environment creates fake ingestors, we make a guess about the ARN of
  # the role the other test env will have permitted to write to its ingestor
  # buckets. We also assume they use the same AWS account as we do.
  sample_maker_role = local.is_env_with_ingestor ? (
    "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/prio-${var.test_peer_environment.env_without_ingestor}-${var.data_share_processor_name}-ingestion-bucket-writer"
  ) : ""
  bucket_reader_aws_role = local.is_env_without_ingestor ? (
    module.cloud_storage_aws[0].bucket_reader_role
  ) : ""
}
data "aws_caller_identity" "current" {}

# For test purposes, we support creating the ingestion and peer validation
# buckets in AWS S3, even though all ISRG storage is in Google Cloud Storage. We
# only create the ingestion bucket and peer validation bucket these, so that we
# can exercise the parameter exchange and authentication flows.
# https://github.com/abetterinternet/prio-server/issues/68
module "cloud_storage_aws" {
  count                             = var.use_aws ? 1 : 0
  source                            = "../../modules/cloud_storage_aws"
  environment                       = var.environment
  resource_prefix                   = local.resource_prefix
  data_share_processor_gcp_sa_id    = module.kubernetes.service_account_unique_id
  ingestion_bucket_name             = local.ingestion_bucket_name
  ingestor_gcp_service_account_id   = local.ingestion_bucket_writer_gcp_service_account.id
  local_peer_validation_bucket_name = local.local_peer_validation_bucket_name
  role_arn_assumed_by_remote_dsp    = var.role_arn_assumed_by_remote_dsp
}

# In real ISRG deployments, all of our storage is in GCS.
module "cloud_storage_gcp" {
  count                                            = var.use_aws ? 0 : 1
  source                                           = "../../modules/cloud_storage_gcp"
  gcp_region                                       = var.gcp_region
  data_share_processor_gcp_sa_email                = module.kubernetes.service_account_email
  ingestion_bucket_name                            = local.ingestion_bucket_name
  ingestion_bucket_writer_gcp_sa_email             = local.ingestion_bucket_writer_gcp_service_account.email
  local_peer_validation_bucket_name                = local.local_peer_validation_bucket_name
  local_peer_validation_bucket_writer_gcp_sa_email = var.remote_dsp_gcp_service_account_email
}

# Besides the validation bucket owned by the peer data share processor, we write
# validation batches into a bucket we control so that we can be certain they
# be available when we perform the aggregation step.
resource "google_storage_bucket" "own_validation_bucket" {
  provider = google-beta
  name     = "${local.resource_prefix}-own-validation"
  location = var.gcp_region
  # Force deletion of bucket contents on bucket destroy. Bucket contents would
  # be re-created by a subsequent deploy so no reason to keep them around.
  force_destroy               = true
  uniform_bucket_level_access = true
}

# Permit the workflow manager and facilitator service account to manage the
# bucket
resource "google_storage_bucket_iam_binding" "own_validation_bucket_admin" {
  bucket = google_storage_bucket.own_validation_bucket.name
  role   = "roles/storage.objectAdmin"
  members = [
    "serviceAccount:${module.kubernetes.service_account_email}"
  ]
}

module "kubernetes" {
  source                                  = "../../modules/kubernetes/"
  data_share_processor_name               = var.data_share_processor_name
  ingestor                                = var.ingestor
  gcp_project                             = var.gcp_project
  environment                             = var.environment
  kubernetes_namespace                    = var.kubernetes_namespace
  ingestion_bucket                        = local.ingestion_bucket_url
  ingestion_bucket_identity               = local.bucket_reader_aws_role
  ingestor_manifest_base_url              = var.ingestor_manifest_base_url
  packet_decryption_key_kubernetes_secret = var.packet_decryption_key_kubernetes_secret
  remote_dsp_manifest_base_url            = var.remote_dsp_manifest_base_url
  local_peer_validation_bucket            = local.local_peer_validation_bucket_url
  local_peer_validation_bucket_identity   = local.bucket_reader_aws_role
  remote_peer_validation_bucket_identity  = var.identity_for_writing_to_remote_storage
  own_validation_bucket                   = google_storage_bucket.own_validation_bucket.name
  own_manifest_base_url                   = var.own_manifest_base_url
  sum_part_bucket_service_account_email   = var.sum_part_bucket_service_account_email
  portal_server_manifest_base_url         = var.portal_server_manifest_base_url
  is_env_with_ingestor                    = local.is_env_with_ingestor
  sample_maker_role                       = local.sample_maker_role
  test_peer_ingestion_bucket              = local.test_peer_ingestion_bucket
  is_first                                = var.is_first
}

output "data_share_processor_name" {
  value = var.data_share_processor_name
}

output "kubernetes_namespace" {
  value = var.kubernetes_namespace
}

output "certificate_fqdn" {
  value = "${var.kubernetes_namespace}.${var.certificate_domain}"
}

output "service_account_email" {
  value = module.kubernetes.service_account_email
}

output "specific_manifest" {
  value = {
    format                 = 1
    ingestion-bucket       = local.ingestion_bucket_url,
    peer-validation-bucket = local.local_peer_validation_bucket_url,
    batch-signing-public-keys = {
      (module.kubernetes.batch_signing_key) = {
        public-key = ""
        expiration = ""
      }
    }
    packet-encryption-certificates = {
      (var.packet_decryption_key_kubernetes_secret) = {
        certificate = ""
      }
    }
  }
}
