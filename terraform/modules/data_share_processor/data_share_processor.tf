variable "data_share_processor_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "gcp_region" {
  type = string
}

variable "gcp_project" {
  type = string
}

variable "ingestor_gcp_service_account_email" {
  type = string
}

variable "peer_share_processor_gcp_service_account_email" {
  type = string
}

variable "peer_share_processor_aws_iam_role" {
  type = string
}

variable "peer_share_processor_aws_account_id" {
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

locals {
  resource_prefix = "prio-${var.environment}-${var.data_share_processor_name}"
  ingestion_bucket_name       = "${local.resource_prefix}-ingestion"
  peer_validation_bucket_name = "${local.resource_prefix}-peer-validation"
}

resource "google_storage_bucket" "ingestion_bucket" {
  provider = google-beta
  name     = "${local.resource_prefix}-ingestion"
  location = var.gcp_region
  # Force deletion of bucket contents on bucket destroy.
  force_destroy = true
  # Disable per-object ACLs, as Google recommends. Everything in the bucket is
  # writable by the ingestion server and readable by our data share processor.
  # https://cloud.google.com/storage/docs/uniform-bucket-level-access
  uniform_bucket_level_access = true
}

# Grants permission to the ingestor GCP service account to write to the bucket.
resource "google_storage_bucket_iam_binding" "ingestion_bucket_writer" {
  provider = google-beta
  bucket = google_storage_bucket.ingestion_bucket.name
  # https://cloud.google.com/storage/docs/access-control/iam-roles#standard-roles
  role = "roles/storage.objectCreator"
  members = [
    "serviceAccount:${var.ingestor_gcp_service_account_email}"
  ]
}

# Grant our data share processor's GCP service account access to the bucket
resource "google_storage_bucket_iam_binding" "ingestion_bucket_owner" {
  provider = google-beta
  bucket = google_storage_bucket.ingestion_bucket.name
  # We grant object admin because we will run both the workflow manager and
  # facilitator jobs with the same service account, for now.
  # https://github.com/abetterinternet/prio-server/issues/90
  role = "roles/storage.objectAdmin"
  members = [
    module.kubernetes.service_account_email
  ]
}

resource "google_storage_bucket" "peer_validation_bucket" {
  provider = google-beta
  name = "${local.resource_prefix}-peer-validation"
  location = var.gcp_region
  force_destroy = true
  uniform_bucket_level_access = true
}

# Grants permission to the peer data share processor GCP service account to
# write to the bucket.
resource "google_storage_bucket_iam_binding" "peer_validation_bucket_writer" {
  provider = google-beta
  bucket = google_storage_bucket.peer_validation_bucket.name
  role = "roles/storage.objectCreator"
  members = [
    "serviceAccount:${var.peer_share_processor_gcp_service_account_email}"
  ]
}

# Grant our data share processor's GCP service account access to the bucket
resource "google_storage_bucket_iam_binding" "peer_validation_bucket_owner" {
  provider = google-beta
  bucket = google_storage_bucket.peer_validation_bucket.name
  role = "roles/storage.objectAdmin"
  members = [
    module.kubernetes.service_account_email
  ]
}

module "kubernetes" {
  source                                  = "../../modules/kubernetes/"
  data_share_processor_name               = var.data_share_processor_name
  gcp_project                             = var.gcp_project
  environment                             = var.environment
  ingestion_bucket                        = google_storage_bucket.ingestion_bucket.name
  s3_writer_role_to_assume                   = var.peer_share_processor_aws_iam_role
  s3_writer_account_to_assume         = var.peer_share_processor_aws_account_id
  kubernetes_namespace                    = var.kubernetes_namespace
  packet_decryption_key_kubernetes_secret = var.packet_decryption_key_kubernetes_secret
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
    format                 = 0
    ingestion-bucket       = google_storage_bucket.ingestion_bucket.name,
    peer-validation-bucket = google_storage_bucket.peer_validation_bucket.name,
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
