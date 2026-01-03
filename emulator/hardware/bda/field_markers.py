"""
Field marker system for BDA (BIOS Data Area) policies
"""

from typing import Any, List

# =============================================================================
# Field Marker System for BDA Policies
# =============================================================================

class FieldMarker:
    """Base class for annotation markers"""
    pass

class BDAPolicy:
    """BDA write policy enum"""
    PASSIVE = 0      # Allow writes, just log them
    BIOS_OWNED = 1   # Writes trigger hardware sync (not yet implemented)
    DENY = 2         # Block writes and halt emulation

class BDAPolicyMarker(FieldMarker):
    """Marker that indicates the BDA write policy for a field"""
    def __init__(self, policy: int):
        self.policy = policy

def bios_owned() -> BDAPolicyMarker:
    """Mark a field as BIOS-owned (writes trigger hardware sync)"""
    return BDAPolicyMarker(BDAPolicy.BIOS_OWNED)

def passive() -> BDAPolicyMarker:
    """Mark a field as passive (writes are allowed, just logged)"""
    return BDAPolicyMarker(BDAPolicy.PASSIVE)

def deny() -> BDAPolicyMarker:
    """Mark a field as denied (writes are blocked and halt emulation)"""
    return BDAPolicyMarker(BDAPolicy.DENY)