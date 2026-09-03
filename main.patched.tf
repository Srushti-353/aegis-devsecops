# scenario/target_infra/main.patched.tf
#
# GROUND-TRUTH fixed version of main.tf. This is what remediation_agent's
# generated patch should converge to (semantically — exact formatting need not
# match). verify_agent re-runs the graph traversal against the agent's own
# patched output, NOT against this file; this file exists as a human-readable
# reference / grading safety net, and for local diff testing.
#
# FIX APPLIED: removed the public `allUsers` binding entirely and replaced it
# with a scoped binding to a named principal (a "data readers" group), so the
# bucket keeps least-privilege access instead of public access.

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

# --- FIXED: scoped access, no public member ---------------------------------
# The `allUsers` -> roles/storage.objectViewer binding has been removed.
# Access is now scoped to a named group, not the public internet.

resource "google_storage_bucket_iam_member" "scoped_read_access" {
  bucket = google_storage_bucket.sensitive_data.name
  role   = "roles/storage.objectViewer"
  member = "group:data-readers@aegis-demo-project.iam.gserviceaccount.com"
}

# --- ALT (optional, inert) --------------------------------------------------
# Unchanged from main.tf. The alternate compute/service-account path was never
# the source of this finding, so remediation does not touch it.

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
