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
  type    = bool
  default = false
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

variable "peer_share_processor_manifest_base_url" {
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
ingestion server. The other, named in "env_without_ingestor", does not. This
variable should not be specified in production deployments.
DESCRIPTION
}

variable "is_first" {
  type        = bool
  default     = false
  description = "Whether the data share processors created by this environment are \"first\" or \"PHA servers\""
}

variable "aggregation_period" {
  type        = string
  default     = "3h"
  description = <<DESCRIPTION
Aggregation period used by workflow manager. The value should be a string
parseable by Go's time.ParseDuration.
DESCRIPTION
}

variable "aggregation_grace_period" {
  type        = string
  default     = "1h"
  description = <<DESCRIPTION
Aggregation grace period used by workflow manager. The value should be a string
parseable by Go's time.ParseDuration.
DESCRIPTION
}

variable "batch_signing_key_expiration" {
  type        = number
  default     = 390
  description = "This value is used to generate batch signing keys with the specified expiration"
}

variable "batch_signing_key_rotation" {
  type        = number
  default     = 300
  description = "This value is used to specify the rotation interval of the batch signing key"
}

variable "packet_encryption_key_expiration" {
  type        = number
  default     = 90
  description = "This value is used to generate packet encryption keys with the specified expiration"
}

variable "packet_encryption_rotation" {
  type        = number
  default     = 50
  description = "This value is used to specify the rotation interval of the packet encryption key"
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

# Activate some services which the deployment will require.
resource "google_project_service" "compute" {
  provider = google-beta
  service  = "compute.googleapis.com"
}

resource "google_project_service" "container" {
  provider = google-beta
  service  = "container.googleapis.com"
}

resource "google_project_service" "kms" {
  provider = google-beta
  project  = var.gcp_project
  service  = "cloudkms.googleapis.com"
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


module "manifest" {
  source                                = "./modules/manifest"
  environment                           = var.environment
  gcp_region                            = var.gcp_region
  managed_dns_zone                      = var.managed_dns_zone
  sum_part_bucket_service_account_email = google_service_account.sum_part_bucket_writer.email

  depends_on = [google_project_service.compute]
}

module "gke" {
  source          = "./modules/gke"
  environment     = var.environment
  resource_prefix = "prio-${var.environment}"
  gcp_region      = var.gcp_region
  gcp_project     = var.gcp_project
  machine_type    = var.machine_type
  network         = google_compute_network.network.self_link
  base_subnet     = local.cluster_subnet_block

  depends_on = [
    google_project_service.compute,
    google_project_service.container,
    google_project_service.kms,
  ]
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

# The portal owns two sum part buckets (one for each data share processor) and
# the one for this data share processor gets configured by the portal operator
# to permit writes from this GCP service account, whose email the portal
# operator discovers in our global manifest.
resource "google_service_account" "sum_part_bucket_writer" {
  provider     = google-beta
  account_id   = "prio-${var.environment}-sum-writer"
  display_name = "prio-${var.environment}-sum-part-bucket-writer"
}

# Call the locality_kubernetes module per each locality/namespace
module "locality_kubernetes" {
  for_each = kubernetes_namespace.namespaces
  source   = "./modules/locality_kubernetes"

  environment                            = var.environment
  gcp_region                             = var.gcp_region
  gcp_project                            = var.gcp_project
  aws_region                             = var.aws_region
  use_aws                                = var.use_aws
  peer_share_processor_manifest_base_url = var.peer_share_processor_manifest_base_url
  manifest_bucket                        = module.manifest.bucket
  manifest_bucket_base_url               = module.manifest.base_url
  certificate_domain                     = "${var.environment}.certificates.${var.manifest_domain}"
  kubernetes_namespace                   = each.value.metadata[0].name
  ingestors                              = var.ingestors

  batch_signing_key_expiration                        = var.batch_signing_key_expiration
  batch_signing_key_rotation                          = var.batch_signing_key_rotation
  packet_encryption_key_expiration                    = var.packet_encryption_key_expiration
  packet_encryption_rotation                          = var.packet_encryption_rotation
  google_service_account_sum_part_bucket_writer_name  = google_service_account.sum_part_bucket_writer.name
  google_service_account_sum_part_bucket_writer_email = google_service_account.sum_part_bucket_writer.email
  portal_server_manifest_base_url                     = var.portal_server_manifest_base_url
  test_peer_environment                               = var.test_peer_environment
  is_first                                            = var.is_first
  aggregation_period                                  = var.aggregation_period
  aggregation_grace_period                            = var.aggregation_grace_period
  kms_keyring                                         = module.gke.kms_keyring
}

module "fake_server_resources" {
  count                        = lookup(var.test_peer_environment, "env_with_ingestor", "") == "" ? 0 : 1
  source                       = "./modules/fake_server_resources"
  manifest_bucket              = module.manifest.bucket
  gcp_region                   = var.gcp_region
  environment                  = var.environment
  sum_part_bucket_writer_email = google_service_account.sum_part_bucket_writer.email
  ingestors                    = var.ingestors
}


output "gke_kubeconfig" {
  value = "Run this command to update your kubectl config: gcloud container clusters get-credentials ${module.gke.cluster_name} --region ${var.gcp_region} --project ${var.gcp_project}"
}

provider "helm" {
  kubernetes {
    host                   = module.gke.cluster_endpoint
    cluster_ca_certificate = base64decode(module.gke.certificate_authority_data)
    token                  = data.google_client_config.current.access_token
    load_config_file       = false
  }
}

resource "helm_release" "prometheus" {
  name       = "prometheus"
  chart      = "prometheus"
  repository = "https://charts.helm.sh/stable"
}
