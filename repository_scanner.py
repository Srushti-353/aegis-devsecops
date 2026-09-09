from __future__ import annotations

import ipaddress
import subprocess
from pathlib import Path
from urllib.parse import urlsplit


class RepositoryScanError(RuntimeError):
    """A safe repository acquisition error suitable for an API response."""


class RepositoryScanTimeout(RepositoryScanError):
    """Repository acquisition exceeded its hard timeout."""


def validate_github_url(url: str) -> str:
    if not isinstance(url, str):
        raise ValueError("repository_url must be a string")
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.netloc != "github.com":
        raise ValueError("only public https://github.com/<owner>/<repo> URLs are allowed")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("repository URL must not contain credentials, query strings, or fragments")
    try:
        ipaddress.ip_address(parsed.hostname or "")
    except ValueError:
        pass
    else:
        raise ValueError("IP addresses are not allowed")

    parts = parsed.path.strip("/").split("/")
    if len(parts) != 2 or not all(parts) or (parts[1].endswith(".git") and len(parts[1]) == 4):
        raise ValueError("repository URL must contain exactly an owner and repository")
    if parts[1].endswith(".git"):
        parts[1] = parts[1][:-4]
    if not parts[0] or not parts[1] or any(part in {".", ".."} for part in parts):
        raise ValueError("malformed repository path")
    return f"https://github.com/{parts[0]}/{parts[1]}.git"


def clone_public_repo(url: str, destination: Path) -> None:
    validated_url = validate_github_url(url)
    destination = Path(destination)
    try:
        subprocess.run(
            ["git", "clone", "--depth", "30", validated_url, str(destination)],
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RepositoryScanTimeout("repository clone timed out") from exc
    except (subprocess.CalledProcessError, OSError) as exc:
        raise RepositoryScanError("unable to clone the public repository") from exc