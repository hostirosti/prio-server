variable "ingestor" {
  type = string
}

variable "data_share_processor_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "container_registry" {
  type    = string
  default = "letsencrypt"
}

variable "workflow_manager_image" {
  type    = string
  default = "prio-workflow-manager"
}

variable "workflow_manager_version" {
  type    = string
  default = "latest"
}

variable "facilitator_image" {
  type    = string
  default = "prio-facilitator"
}

variable "facilitator_version" {
  type    = string
  default = "latest"
}

variable "gcp_project" {
  type = string
}

variable "ingestion_bucket" {
  type = string
}

variable "ingestion_bucket_identity" {
  type = string
}

variable "ingestor_manifest_base_url" {
  type = string
}

variable "peer_validation_bucket" {
  type = string
}

variable "peer_validation_bucket_identity" {
  type = string
}

variable "peer_manifest_base_url" {
  type = string
}

variable "remote_peer_validation_bucket_identity" {
  type = string
}

variable "own_validation_bucket" {
  type = string
}

variable "own_manifest_base_url" {
  type = string
}

variable "kubernetes_namespace" {
  type = string
}

variable "portal_server_manifest_base_url" {
  type = string
}

variable "sum_part_bucket_service_account_email" {
  type = string
}

variable "is_env_with_ingestor" {
  type = bool
}

variable "test_peer_ingestion_bucket" {
  type = string
}

variable "is_first" {
  type = bool
}

variable "aggregation_period" {
  type = string
}

variable "aggregation_grace_period" {
  type = string
}

data "aws_caller_identity" "current" {}

# Workload identity[1] lets us map GCP service accounts to Kubernetes service
# accounts. We need this so that pods can use GCP API, but also AWS APIs like S3
# via Web Identity Federation. To use the credentials, the container must fetch
# the authentication token from the instance metadata service. Kubernetes has
# features for automatically providing a service account token (e.g. via a
# a mounted volume[2]), but that would be a token for the *Kubernetes* level
# service account, and not the one we can present to AWS.
# [1] https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity
# [2] https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#service-account-token-volume-projection

module "account_mapping" {
  source                  = "../account_mapping"
  google_account_name     = "${var.environment}-${var.data_share_processor_name}-workflow-manager"
  kubernetes_account_name = "${var.data_share_processor_name}-workflow-manager"
  kubernetes_namespace    = var.kubernetes_namespace
  environment             = var.environment
  gcp_project             = var.gcp_project
}

# Allows the Kubernetes service account to request auth tokens for the GCP
# service account.
resource "google_service_account_iam_binding" "workflow_manager_token" {
  provider           = google-beta
  service_account_id = module.account_mapping.google_service_account_name
  role               = "roles/iam.serviceAccountTokenCreator"
  members = [
    module.account_mapping.service_account
  ]
}

# ConfigMap containing the parameters that are common to every intake-batch job
# that will be spawned in this data share processor, except for secrets.
resource "kubernetes_config_map" "intake_batch_job_config_map" {
  metadata {
    name      = "${var.data_share_processor_name}-intake-batch-config"
    namespace = var.kubernetes_namespace
  }

  # These key-value pairs will be plopped directly into the container
  # environment, so they MUST match the environment variables set in various
  # Arg::env calls in src/bin/facilitator.rs.
  data = {
    # PACKET_DECRYPTION_KEYS is a Kubernetes secret
    # BATCH_SIGNING_PRIVATE_KEY is a Kubernetes secret
    IS_FIRST                             = var.is_first ? "true" : "false"
    AWS_ACCOUNT_ID                       = data.aws_caller_identity.current.account_id
    BATCH_SIGNING_PRIVATE_KEY_IDENTIFIER = "type=batch-signing-key"
    INGESTOR_IDENTITY                    = var.ingestion_bucket_identity
    INGESTOR_INPUT                       = var.ingestion_bucket
    INGESTOR_MANIFEST_BASE_URL           = "https://${var.ingestor_manifest_base_url}"
    INSTANCE_NAME                        = var.data_share_processor_name
    PEER_IDENTITY                        = var.remote_peer_validation_bucket_identity
    PEER_MANIFEST_BASE_URL               = "https://${var.peer_manifest_base_url}"
    OWN_OUTPUT                           = var.own_validation_bucket
    RUST_LOG                             = "info"
    RUST_BACKTRACE                       = "1"
  }
}

# ConfigMap containing the parameters that are common to every aggregation job
# that will be spawned in this data share processor, except for secrets.
resource "kubernetes_config_map" "aggregate_job_config_map" {
  metadata {
    name      = "${var.data_share_processor_name}-aggregate-config"
    namespace = var.kubernetes_namespace
  }

  data = {
    # PACKET_DECRYPTION_KEYS is a Kubernetes secret
    # BATCH_SIGNING_PRIVATE_KEY is a Kubernetes secret
    IS_FIRST                             = var.is_first ? "true" : "false"
    AWS_ACCOUNT_ID                       = data.aws_caller_identity.current.account_id
    BATCH_SIGNING_PRIVATE_KEY_IDENTIFIER = "type=batch-signing-key"
    INGESTOR_INPUT                       = var.ingestion_bucket
    INGESTOR_IDENTITY                    = var.ingestion_bucket_identity
    INGESTOR_MANIFEST_BASE_URL           = "https://${var.ingestor_manifest_base_url}"
    INSTANCE_NAME                        = var.data_share_processor_name
    OWN_INPUT                            = var.own_validation_bucket
    OWN_MANIFEST_BASE_URL                = var.own_manifest_base_url
    PEER_INPUT                           = var.peer_validation_bucket
    PEER_IDENTITY                        = var.peer_validation_bucket_identity
    PEER_MANIFEST_BASE_URL               = "https://${var.peer_manifest_base_url}"
    PORTAL_IDENTITY                      = var.sum_part_bucket_service_account_email
    PORTAL_MANIFEST_BASE_URL             = "https://${var.portal_server_manifest_base_url}"
    RUST_LOG                             = "info"
    RUST_BACKTRACE                       = "1"
  }
}

resource "kubernetes_cron_job" "workflow_manager" {
  metadata {
    name      = "workflow-manager-${var.ingestor}-${var.environment}"
    namespace = var.kubernetes_namespace

    annotations = {
      environment = var.environment
    }
  }
  spec {
    schedule                      = "*/10 * * * *"
    concurrency_policy            = "Forbid"
    successful_jobs_history_limit = 5
    failed_jobs_history_limit     = 3
    job_template {
      metadata {}
      spec {
        template {
          metadata {}
          spec {
            container {
              name  = "workflow-manager"
              image = "${var.container_registry}/${var.workflow_manager_image}:${var.workflow_manager_version}"
              resources {
                requests {
                  memory = "500Mi"
                  cpu    = "0.5"
                }
                limits {
                  memory = "550Mi"
                  cpu    = "0.7"
                }
              }

              args = [
                "--aggregation-period", var.aggregation_period,
                "--grace-period", var.aggregation_grace_period,
                "--intake-max-age", "24h",
                "--is-first=${var.is_first ? "true" : "false"}",
                "--k8s-namespace", var.kubernetes_namespace,
                "--k8s-service-account", module.account_mapping.kubernetes_account_name,
                "--ingestor-input", var.ingestion_bucket,
                "--ingestor-identity", var.ingestion_bucket_identity,
                "--own-validation-input", var.own_validation_bucket,
                "--peer-validation-input", var.peer_validation_bucket,
                "--peer-validation-identity", var.peer_validation_bucket_identity,
                "--bsk-secret-selector", "type=batch-signing-key",
                "--pdks-secret-selector", "type=packet-decryption-key",
                "--intake-batch-config-map", kubernetes_config_map.intake_batch_job_config_map.metadata[0].name,
                "--aggregate-config-map", kubernetes_config_map.aggregate_job_config_map.metadata[0].name,
                "--facilitator-image", "${var.container_registry}/${var.facilitator_image}:${var.facilitator_version}",
              ]
            }
            # If we use any other restart policy, then when the job is finally
            # deemed to be a failure, Kubernetes will destroy the job, pod and
            # container(s) virtually immediately. This can cause us to lose logs
            # if the container is reaped before the GKE logging agent can upload
            # logs. Since this is a cronjob and we will retry anyway, we use
            # "Never".
            # https://kubernetes.io/docs/concepts/workloads/controllers/job/#handling-pod-and-container-failures
            # https://github.com/kubernetes/kubernetes/issues/74848
            restart_policy                  = "Never"
            service_account_name            = module.account_mapping.kubernetes_account_name
            automount_service_account_token = true
          }
        }
      }
    }
  }
}

resource "kubernetes_role" "workflow_manager_role" {
  metadata {
    name      = "${var.environment}-${var.data_share_processor_name}-wfm-role"
    namespace = var.kubernetes_namespace
  }

  rule {
    // API group "" means the core API group.
    api_groups = ["batch", ""]
    // Workflow manager can list pods and create jobs.
    // Note: Some of these permissions will probably wind up not being needed.
    // Starting with a moderately generous demonstration set.
    resources = ["namespaces", "pods", "jobs"]
    verbs     = ["get", "list", "watch", "create"]
  }
}

resource "kubernetes_role_binding" "workflow_manager_rolebinding" {
  metadata {
    name      = "${var.environment}-${var.data_share_processor_name}-workflow-manager-can-admin"
    namespace = var.kubernetes_namespace
  }

  role_ref {
    kind      = "Role"
    name      = "${var.environment}-${var.data_share_processor_name}-wfm-role"
    api_group = "rbac.authorization.k8s.io"
  }

  subject {
    kind      = "ServiceAccount"
    name      = module.account_mapping.kubernetes_account_name
    namespace = var.kubernetes_namespace
  }
}

output "service_account_unique_id" {
  value = module.account_mapping.google_service_account_unique_id
}

output "service_account_email" {
  value = module.account_mapping.google_service_account_email
}
