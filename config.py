import os

AEGIS_GCP_PROJECT = "aegis-devsecops-2026"
AEGIS_BIGQUERY_DATASET = "aegis_security"
AEGIS_DEFAULT_FINDING = "finding-0001"
AEGIS_ENV = "development"
AEGIS_PORT = 8000


def _env(name: str, default: str) -> str:
    return os.getenv(name, default)


def get_project_id() -> str:
    return _env("AEGIS_GCP_PROJECT", AEGIS_GCP_PROJECT)


def get_dataset_id() -> str:
    return _env("AEGIS_BIGQUERY_DATASET", AEGIS_BIGQUERY_DATASET)


def get_default_finding() -> str:
    return _env("AEGIS_DEFAULT_FINDING", AEGIS_DEFAULT_FINDING)


def get_environment() -> str:
    return _env("AEGIS_ENV", AEGIS_ENV)


def get_port() -> int:
    raw_port = _env("AEGIS_PORT", os.getenv("PORT", str(AEGIS_PORT)))
    try:
        return int(raw_port)
    except ValueError:
        return AEGIS_PORT


def is_demo_mode() -> bool:
    return str(_env("AEGIS_DEMO_MODE", "false")).lower() == "true"
