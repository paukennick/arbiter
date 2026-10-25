import os
from pathlib import Path


def resolve_image(raw: str) -> Path:
    root = os.environ.get("IMAGE_ROOT")
    if not root:  # expect: arbiter/python.path-confinement-optional
        return Path(raw).resolve()
    base = Path(root).resolve()
    path = (base / raw).resolve()
    if not path.is_relative_to(base):
        raise ValueError("outside root")
    return path
