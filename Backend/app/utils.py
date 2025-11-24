
import tempfile
import shutil
from pathlib import Path

class TempFile:
    def __init__(self, suffix=""):
        self.suffix = suffix
        self.filepath = None

    def __enter__(self):
        fd, path = tempfile.mkstemp(suffix=self.suffix)
        self.filepath = Path(path)
        return self.filepath

    def __exit__(self, exc_type, exc, tb):
        if self.filepath and self.filepath.exists():
            try:
                self.filepath.unlink()
            except Exception:
                pass
