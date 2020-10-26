environment                = "atr"
gcp_region                 = "us-west1"
gcp_project                = "prio-atredis-oct-2020"
machine_type               = "e2-small"
peer_share_processor_names = ["test-pha-1", "test-pha-2"]
manifest_domain            = "isrg-prio.org"
managed_dns_zone = {
  name        = "manifests"
  gcp_project = "prio-bringup-290620"
}
ingestors = {
  ingestor-1 = "storage.googleapis.com/prio-atredis-oct-2020-fake-peer-manifests/ingestor-1"
  ingestor-2 = "storage.googleapis.com/prio-atredis-oct-2020-fake-peer-manifests/ingestor-2"
}
peer_share_processor_manifest_domain = "storage.googleapis.com/prio-atredis-oct-2020-fake-peer-manifests/pha-servers"
