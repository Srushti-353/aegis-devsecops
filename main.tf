# scenario/target_infra/main.tf
#
# THIS FILE IS NEVER APPLIED TO REAL GCP. It is synthetic "victim" infrastructure,
# parsed by AEGIS's deterministic tools to build an in-memory attack graph.
#
# PRIMARY ATTACK PATH (this is the one AEGIS's MVP must trace end to end):
#   Internet -> allUsers IAM binding -> sensitive-data-bucket (public read)
#
# Engineering lineage reconstructed by AEGIS:
#   Terraform (this file) -> Git Commit -> Deployment -> IAM/ACL Change -> Exposure

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = "aegis-demo-project"
  region  = "us-central1"
}

# --- The sensitive asset ---------------------------------------------------

resource "google_storage_bucket" "sensitive_data" {
  name          = "aegis-sensitive-data-bucket"
  location      = "US"
  force_destroy = true

  uniform_bucket_level_access = true

  labels = {
    data_classification = "sensitive"
    environment         = "prod"
  }
}

# --- THE VULNERABILITY ------------------------------------------------------
# This binding is the single introduced exposure. Exactly one binding like this
# exists in this file. It is what the commit history, deployment history, and
# seeded finding all point back to.

resource "google_storage_bucket_iam_member" "public_read_access" {
  bucket = google_storage_bucket.sensitive_data.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

# --- ALT (optional, inert on Day 1) -----------------------------------------
# Represents the OPTIONAL alternate attack path via a compute instance /
# service account, per scope change #3. Not required by the core graph engine.
# Kept here only so it can be wired into graph_tools later with no Terraform
# rewrite needed. Do not build reasoning against this block until the primary
# path is demoed cleanly end to end.

resource "google_service_account" "app_sa" {
  account_id   = "aegis-app-sa"
  display_name = "AEGIS demo app service account (ALT path)"
}

resource "google_storage_bucket_iam_member" "app_sa_read_access" {
  bucket = google_storage_bucket.sensitive_data.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.app_sa.email}"
}

resource "google_compute_instance" "app_vm" {
  name         = "aegis-app-vm"
  machine_type = "e2-small"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }

  network_interface {
    network = "default"
  }

  service_account {
    email  = google_service_account.app_sa.email
    scopes = ["cloud-platform"]
  }
}
