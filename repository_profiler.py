from __future__ import annotations

from pathlib import Path


def profile_repository(repo_path: Path) -> dict:
    repo_path = Path(repo_path)
    files = [path for path in repo_path.rglob("*") if path.is_file() and ".git" not in path.parts]
    names = {path.name.lower() for path in files}
    suffixes = {path.suffix.lower() for path in files}
    directories = {path.relative_to(repo_path).parts[0].lower() for path in files if path.relative_to(repo_path).parts}

    languages = []
    if names.intersection({"requirements.txt", "pyproject.toml", "setup.py", "poetry.lock"}) or ".py" in suffixes:
        languages.append("Python")
    if names.intersection({"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"}) or ".js" in suffixes or ".ts" in suffixes:
        languages.append("Node.js")
    if names.intersection({"pom.xml", "build.gradle", "build.gradle.kts"}) or ".java" in suffixes:
        languages.append("Java")
    if "go.mod" in names or ".go" in suffixes:
        languages.append("Go")
    if "cargo.toml" in names or ".rs" in suffixes:
        languages.append("Rust")

    package_managers = []
    if names.intersection({"requirements.txt", "pyproject.toml", "poetry.lock"}):
        package_managers.append("pip")
    if names.intersection({"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"}):
        package_managers.append("npm")
    if names.intersection({"pom.xml"}):
        package_managers.append("Maven")
    if names.intersection({"build.gradle", "build.gradle.kts"}):
        package_managers.append("Gradle")
    if "go.mod" in names:
        package_managers.append("Go modules")
    if "cargo.toml" in names:
        package_managers.append("Cargo")

    terraform = ".tf" in suffixes
    kubernetes = bool({"k8s", "kubernetes"}.intersection(directories)) or bool(
        names.intersection({"deployment.yaml", "deployment.yml", "service.yaml", "service.yml"})
    )
    docker = bool(names.intersection({"dockerfile", "docker-compose.yml", "docker-compose.yaml"}))
    return {
        "languages": languages,
        "package_managers": package_managers,
        "terraform": terraform,
        "kubernetes": kubernetes,
        "docker": docker,
        "git_history_available": (repo_path / ".git").exists(),
        "file_count": len(files),
    }