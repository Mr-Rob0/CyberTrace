"""
MITRE ATT&CK Module
====================
Maps detected attack behaviors to the MITRE ATT&CK framework,
providing standardized enterprise technique IDs, tactics, and descriptions.

Sub-modules:
    - technique_mapper: Deterministic, evidence-backed technique mapping
"""

from mitre.technique_mapper import (
    TechniqueMapping,
    TechniqueMapper,
    map_to_mitre,
    ATTACK_REGISTRY,
)

__all__ = [
    "TechniqueMapping",
    "TechniqueMapper",
    "map_to_mitre",
    "ATTACK_REGISTRY",
]
