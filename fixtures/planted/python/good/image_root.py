import os
from pathlib import Path

ROOT = Path(os.environ.get("IMAGE_ROOT", "/srv/images")).resolve()


def resolve_image(raw: str) -> Path:
    path = (ROOT / raw).resolve()
    if not path.is_relative_to(ROOT):
        raise ValueError("outside root")
    return path
