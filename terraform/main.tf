variable "environment" {
  type = string
}

variable "gcp_region" {
  type = string
}

variable "gcp_project" {
  type = string
}

variable "use_aws" {
  type        = bool
  description = "Whether this env should create any of its storage in AWS"
}

variable "aws_region" {
  type = string
}

variable "aws_profile" {
  type    = string
  default = "leuswest2"
}

variable "machine_type" {
  type    = string
  default = "e2.small"
}

variable "localities" {
  type = list(string)
}

variable "ingestors" {
  type        = map(string)
  description = "Map of ingestor names to the URL where their global manifest may be found."
}

variable "manifest_domain" {
  type        = string
  description = "Domain (plus optional relative path) to which this environment's global and specific manifests should be uploaded."
}

variable "managed_dns_zone" {
  type = map(string)
}

variable "remote_dsp_manifest_base_url" {
  type = string
}

variable "portal_server_manifest_base_url" {
  type = string
}

variable "test_peer_environment" {
  type        = map(string)
  default     = {}
  description = <<DESCRIPTION
Describes a pair of data share processor environments set up to test against
each other. One environment, named in "env_with_ingestor", hosts a fake
ingestion server. The other, named in "env_without_ingestor", does not. That env
will have its ingestion and peer validation buckets in S3, and the region the
buckets are is is indicated by the "aws_region" key. This variable should not be
specified in production deployments.
DESCRIPTION
}

variable "is_first" {
  type        = bool
  default     = false
  description = "Whether the data share processors created by this environment are \"first\" or \"PHA servers\""
}

terraform {
  backend "gcs" {}

  required_version = ">= 0.13.3"
}

data "terraform_remote_state" "state" {
  backend = "gcs"

  workspace = "${var.environment}-${var.gcp_region}"

  config = {
    bucket = "${var.environment}-${var.gcp_region}-prio-terraform"
  }
}

data "google_client_config" "current" {}

provider "google-beta" {
  # We use the google-beta provider so that we can use configuration fields that
  # aren't in the GA google provider. Google resources must explicitly opt into
  # this provider with `provider = google-beta` or they will not inherit values
  # appropriately.
  # https://www.terraform.io/docs/providers/google/guides/provider_versions.html
  # This will use "Application Default Credentials". Run `gcloud auth
  # application-default login` to generate them.
  # https://www.terraform.io/docs/providers/google/guides/provider_reference.html#credentials
  region  = var.gcp_region
  project = var.gcp_project
}

provider "aws" {
  # aws_s3_bucket resources will be created in the region specified in this
  # provider.
  # https://github.com/hashicorp/terraform/issues/12512
  region  = var.aws_region
  profile = var.aws_profile
}

provider "kubernetes" {
  host                   = module.gke.cluster_endpoint
  cluster_ca_certificate = base64decode(module.gke.certificate_authority_data)
  token                  = data.google_client_config.current.access_token
  load_config_file       = false
}

# Opt into the various GCP APIs we will use. If we don't do this here, then
# apply fails repeatedly and the operator has to click buttons in a web console
# to achieve the same thing.
resource "google_project_service" "compute_api" {
  provider = google-beta
  project  = var.gcp_project
  service  = "compute.googleapis.com"
}

resource "google_project_service" "gke_api" {
  provider = google-beta
  project  = var.gcp_project
  service  = "container.googleapis.com"
}

resource "google_project_service" "kms_api" {
  provider = google-beta
  project  = var.gcp_project
  service  = "cloudkms.googleapis.com"
}

module "manifest" {
  source                                         = "./modules/manifest"
  environment                                    = var.environment
  gcp_region                                     = var.gcp_region
  managed_dns_zone                               = var.managed_dns_zone
  role_arn_assumed_by_remote_dsp                 = local.role_assumed_by_remote_dsp.arn
  remote_bucket_writer_gcp_service_account_id    = google_service_account.remote_bucket_writer.unique_id
  remote_bucket_writer_gcp_service_account_email = google_service_account.remote_bucket_writer.email

  depends_on = [google_project_service.compute_api]
}

module "gke" {
  source          = "./modules/gke"
  environment     = var.environment
  resource_prefix = "prio-${var.environment}"
  gcp_region      = var.gcp_region
  gcp_project     = var.gcp_project
  machine_type    = var.machine_type

  depends_on = [
    google_project_service.compute_api,
    google_project_service.gke_api,
    google_project_service.kms_api,
  ]
}

# For each peer data share processor, we will receive ingestion batches from two
# ingestion servers. We create a distinct data share processor instance for each
# (peer, ingestor) pair.
# First, we fetch the ingestor global manifests, which yields a map of ingestor
# name => HTTP content.
data "http" "ingestor_global_manifests" {
  for_each = var.ingestors
  url      = "https://${each.value}/global-manifest.json"
}

# Then we fetch the single global manifest for all the remote share processors.
data "http" "remote_dsp_global_manifest" {
  url = "https://${var.remote_dsp_manifest_base_url}/global-manifest.json"
}

# While we create a distinct data share processor for each (ingestor, locality)
# pair, we only create one packet decryption key for each locality, and use it
# for all ingestors. Since the secret must be in a namespace and accessible
# from all of our data share processors, that means all data share processors
# associated with a given ingestor must be in a single Kubernetes namespace,
# which we create here and pass into the data share processor module.
resource "kubernetes_namespace" "namespaces" {
  for_each = toset(var.localities)
  metadata {
    name = each.key
    annotations = {
      environment = var.environment
    }
  }
}

resource "kubernetes_secret" "ingestion_packet_decryption_keys" {
  for_each = toset(var.localities)
  metadata {
    name      = "${var.environment}-${each.key}-ingestion-packet-decryption-key"
    namespace = kubernetes_namespace.namespaces[each.key].metadata[0].name
  }

  data = {
    # See comment on batch_signing_key, in modules/kubernetes/kubernetes.tf,
    # about the initial value and the lifecycle block here.
    secret_key = "not-a-real-key"
  }

  lifecycle {
    ignore_changes = [
      data["secret_key"]
    ]
  }
}

data "aws_caller_identity" "current" {}

# Now, we take the set product of localities x ingestor names to
# get the config values for all the data share processors we need to create.
locals {
  locality_ingestor_pairs = {
    for pair in setproduct(toset(var.localities), keys(var.ingestors)) :
    "${pair[0]}-${pair[1]}" => {
      ingestor                                = pair[1]
      kubernetes_namespace                    = kubernetes_namespace.namespaces[pair[0]].metadata[0].name
      packet_decryption_key_kubernetes_secret = kubernetes_secret.ingestion_packet_decryption_keys[pair[0]].metadata[0].name
      ingestor_gcp_service_account_id         = jsondecode(data.http.ingestor_global_manifests[pair[1]].body).server-identity.gcp-service-account-id
      ingestor_gcp_service_account_email      = jsondecode(data.http.ingestor_global_manifests[pair[1]].body).server-identity.gcp-service-account-email
      ingestor_manifest_base_url              = var.ingestors[pair[1]]
    }
  }
  remote_dsp_identity = jsondecode(data.http.remote_dsp_global_manifest.body).server-identity
  # resource aws_iam_role.peer_dsp_assumed_role can't be created until the peer
  # data share processor's global manifest is available, because it needs the
  # peer GCP service account ID. We define the role name and ARN here as a local
  # so that we can use it during apply-bootstrap without actually creating the
  # policy, breaking the dependency cycle.
  role_assumed_by_remote_dsp_name = "prio-${var.environment}-peer-validation-bucket-writer"
  role_assumed_by_remote_dsp = var.use_aws ? {
    name = local.role_assumed_by_remote_dsp_name
    arn  = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${local.role_assumed_by_remote_dsp_name}"
    } : {
    name = ""
    arn  = ""
  }
  # This is the identity (AWS IAM role or GCP SA email) that this DSP should
  # assume in order to write content to the peer's buckets.
  identity_for_writing_to_remote_storage = lookup(local.remote_dsp_identity, "validation-writer-aws-role-arn", google_service_account.remote_bucket_writer.email)
}

module "data_share_processors" {
  for_each                                = local.locality_ingestor_pairs
  source                                  = "./modules/data_share_processor"
  environment                             = var.environment
  data_share_processor_name               = each.key
  ingestor                                = each.value.ingestor
  use_aws                                 = var.use_aws
  aws_region                              = var.aws_region
  gcp_region                              = var.gcp_region
  gcp_project                             = var.gcp_project
  kubernetes_namespace                    = each.value.kubernetes_namespace
  certificate_domain                      = "${var.environment}.certificates.${var.manifest_domain}"
  ingestor_gcp_service_account_id         = each.value.ingestor_gcp_service_account_id
  ingestor_gcp_service_account_email      = each.value.ingestor_gcp_service_account_email
  ingestor_manifest_base_url              = each.value.ingestor_manifest_base_url
  packet_decryption_key_kubernetes_secret = each.value.packet_decryption_key_kubernetes_secret
  remote_dsp_manifest_base_url            = var.remote_dsp_manifest_base_url
  remote_dsp_gcp_service_account_id       = local.remote_dsp_identity.gcp-service-account-id
  remote_dsp_gcp_service_account_email    = local.remote_dsp_identity.gcp-service-account-email
  role_arn_assumed_by_remote_dsp          = local.role_assumed_by_remote_dsp.arn
  identity_for_writing_to_remote_storage  = local.identity_for_writing_to_remote_storage
  sum_part_bucket_service_account_email   = google_service_account.remote_bucket_writer.email
  portal_server_manifest_base_url         = var.portal_server_manifest_base_url
  own_manifest_base_url                   = module.manifest.base_url
  test_peer_environment                   = var.test_peer_environment
  is_first                                = var.is_first

  depends_on = [module.gke]
}

# The AWS IAM role assumed by the peer data share processor to write validation
# shares to this DSP's validation buckets, if this env has buckets in S3. The
# role is configured to allow assumption by the GCP service account ID
resource "aws_iam_role" "role_assumed_by_remote_dsp" {
  count              = local.role_assumed_by_remote_dsp.name == "" ? 0 : 1
  name               = local.role_assumed_by_remote_dsp.name
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
          "accounts.google.com:sub": "${local.remote_dsp_identity.gcp-service-account-id}"
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

# This GCP service account is used for all writes to peer owned cloud storage,
# that is, the portal server's sum part bucket as well as all of the peer data
# share processor's validation share buckets. Its email is advertised in the
# global manifest, so that peers may discover it and grant it access to their
# cloud storage buckets.
resource "google_service_account" "remote_bucket_writer" {
  provider     = google-beta
  account_id   = "prio-${var.environment}-remote-writer"
  display_name = "prio-${var.environment}-remote-bucket-writer"
}

# Permit the service accounts for all the data share processors to request Oauth
# tokens allowing them to impersonate the peer bucket writer.
resource "google_service_account_iam_binding" "data_share_processors_to_peer_bucket_writer_token_creator" {
  provider           = google-beta
  service_account_id = google_service_account.remote_bucket_writer.name
  role               = "roles/iam.serviceAccountTokenCreator"
  members            = [for v in module.data_share_processors : "serviceAccount:${v.service_account_email}"]
}

module "fake_server_resources" {
  count                        = lookup(var.test_peer_environment, "env_with_ingestor", "") == "" ? 0 : 1
  source                       = "./modules/fake_server_resources"
  manifest_bucket              = module.manifest.bucket
  gcp_region                   = var.gcp_region
  environment                  = var.environment
  sum_part_bucket_writer_email = google_service_account.remote_bucket_writer.email
  ingestors                    = var.ingestors
}

output "manifest_bucket" {
  value = module.manifest.bucket
}

output "gke_kubeconfig" {
  value = "Run this command to update your kubectl config: gcloud container clusters get-credentials ${module.gke.cluster_name} --region ${var.gcp_region} --project ${var.gcp_project}"
}

output "specific_manifests" {
  value = { for v in module.data_share_processors : v.data_share_processor_name => {
    kubernetes-namespace = v.kubernetes_namespace
    certificate-fqdn     = v.certificate_fqdn
    specific-manifest    = v.specific_manifest
    }
  }
}

output "use_test_pha_decryption_key" {
  value = lookup(var.test_peer_environment, "env_without_ingestor", "") == var.environment
}
