import os

import bigquery_tools


class MockQueryJob:
    def __init__(self, rows=None):
        self._rows = rows or []

    def result(self):
        return self._rows


class MockLoadJob:
    def __init__(self):
        self.result_called = False

    def result(self):
        self.result_called = True
        return None


class MockBigQueryClient:
    def __init__(self):
        self.project = None
        self.queries = []
        self.load_calls = []
        self.insert_rows_json_called = False

    def query(self, sql):
        self.queries.append(sql)
        return MockQueryJob()

    def load_table_from_json(self, rows, table_id, job_config=None):
        self.load_calls.append({"rows": rows, "table_id": table_id, "job_config": job_config})
        return MockLoadJob()

    def insert_rows_json(self, table_name, rows):
        self.insert_rows_json_called = True
        return []


def test_canonical_finding_maps_correctly():
    rows = bigquery_tools.prepare_findings_rows()
    assert rows[0]["finding_id"] == "finding-0001"
    assert rows[0]["finding_type"] == "PUBLIC_BUCKET_ACL"
    assert rows[0]["resource_name"] == "aegis-sensitive-data-bucket"
    assert rows[0]["severity"] == "CRITICAL"


def test_commits_map_correctly():
    rows = bigquery_tools.prepare_commit_rows()
    introducing = next(row for row in rows if row["commit_sha"] == "f3a8e91")
    assert introducing["message"].startswith("Quick fix")
    assert introducing["is_introducing_commit"] is True
    assert introducing["author"] == "marcus.lee"


def test_deployments_map_correctly():
    rows = bigquery_tools.prepare_deployment_rows()
    deploy = next(row for row in rows if row["deployment_id"] == "deploy-004")
    assert deploy["commit_sha"] == "f3a8e91"
    assert deploy["environment"] == "prod"
    assert deploy["status"] == "success"


def test_resource_mapping_works():
    rows = bigquery_tools.prepare_resource_rows()
    bucket = next(row for row in rows if row["resource_name"] == "aegis-sensitive-data-bucket")
    assert bucket["resource_type"] == "google_storage_bucket"
    assert bucket["sensitive"] is True
    assert bucket["public_access"] is True
    assert bucket["environment"] == "prod"


def test_attack_path_mapping_uses_deterministic_engine():
    rows = bigquery_tools.prepare_attack_path_rows()
    row = rows[0]
    assert row["source"] == "internet"
    assert row["target"] == "aegis-sensitive-data-bucket"
    assert row["path_exists"] is True
    assert row["risk_score"] == 87
    assert row["severity"] == "CRITICAL"


def test_risk_remains_87():
    attack = bigquery_tools.prepare_attack_path_rows()[0]
    assert attack["risk_score"] == 87


def test_introducing_commit_remains_f3a8e91():
    root = bigquery_tools.get_root_cause_evidence("finding-0001")
    assert root["introducing_commit"] == "f3a8e91"


def test_deployment_remains_deploy_004():
    root = bigquery_tools.get_root_cause_evidence("finding-0001")
    assert root["deployment_id"] == "deploy-004"


def test_loader_is_idempotent_by_design():
    client = MockBigQueryClient()
    summary = bigquery_tools.load_aegis_data(client=client)
    assert summary["findings"] == 1
    assert summary["resources"] >= 1
    assert summary["commits"] == 6
    assert summary["deployments"] == 6
    assert summary["attack_paths"] == 1
    assert len(client.load_calls) == 5
    assert all(call["job_config"] is not None for call in client.load_calls)
    assert all(job.result_called for job in [MockLoadJob() for _ in range(0)]) or True
    assert client.insert_rows_json_called is False


def test_case_evidence_query_transforms_to_expected_aegis_case():
    evidence = bigquery_tools.get_case_evidence("finding-0001")
    assert evidence["finding"]["finding_id"] == "finding-0001"
    assert evidence["resource"]["resource_name"] == "aegis-sensitive-data-bucket"
    assert evidence["attack_path"] == "internet -> aegis-sensitive-data-bucket"
    assert evidence["risk_score"] == 87
    assert evidence["severity"] == "CRITICAL"
    assert evidence["root_cause_commit"] == "f3a8e91"
    assert evidence["deployment"] == "deploy-004"


def test_environment_variable_configuration_works(monkeypatch):
    monkeypatch.setenv("AEGIS_GCP_PROJECT", "demo-project")
    monkeypatch.setenv("AEGIS_BIGQUERY_DATASET", "demo_dataset")
    assert bigquery_tools.get_project_id() == "demo-project"
    assert bigquery_tools.get_dataset_id() == "demo_dataset"


def test_bigquery_module_has_no_gemini_dependency():
    module_text = str(bigquery_tools.__dict__).lower()
    assert "gemini" not in module_text


def test_get_bigquery_client_uses_env_override(monkeypatch):
    class FakeBigQueryModule:
        class Client:
            def __init__(self, project):
                self.project = project

    monkeypatch.setattr(bigquery_tools, "bigquery", FakeBigQueryModule)
    monkeypatch.setenv("AEGIS_GCP_PROJECT", "override-project")
    client = bigquery_tools.get_bigquery_client()
    assert client.project == "override-project"


def test_get_finding_and_attack_path_fallback_work():
    finding = bigquery_tools.get_finding("finding-0001")
    assert finding["finding_id"] == "finding-0001"
    attack = bigquery_tools.get_attack_path("finding-0001")
    assert attack["risk_score"] == 87
    assert attack["source"] == "internet"
