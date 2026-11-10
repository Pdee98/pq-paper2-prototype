"""Failure evidence is retained for inspection, never as scientific/authorization input."""
from pathlib import Path

PREFIX = 'failed-attempt-evidence-'
MARKER = 'UNVERIFIED'


def reject(root, artifact_name=''):
    root = Path(root).resolve()
    if artifact_name.startswith(PREFIX) or any(p.name.startswith(PREFIX) for p in (root, *root.parents)):
        raise ValueError('UNVERIFIED failed-attempt evidence is not a consumable input')
    if any((p/MARKER).exists() for p in (root, *root.parents)) or any(root.rglob(MARKER)):
        raise ValueError('UNVERIFIED failed-attempt evidence is not a consumable input')
