"""Source abstraction."""

from sorb.source.base import Entry, Source, SourceProvenance, SourceRef, open_target
from sorb.source.dir import DirSource, FileSource

__all__ = [
    "DirSource",
    "Entry",
    "FileSource",
    "Source",
    "SourceProvenance",
    "SourceRef",
    "open_target",
]
