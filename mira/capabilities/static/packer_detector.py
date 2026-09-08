"""Conservative packing/protection indicator detection."""

from mira.artifacts import Artifact
from mira.capabilities.static.common import result_ok
from mira.capabilities.static.pe_support import load_pe


def detect_packer(artifact: Artifact) -> dict:
    pe, failure = load_pe(artifact, "detect_packer")
    if failure:
        return failure
    names = {section.Name.rstrip(b"\\0").decode("ascii", errors="replace").upper() for section in pe.sections}
    indicators = []
    packer = None
    if {"UPX0", "UPX1"}.issubset(names):
        packer, indicators = "UPX", ["UPX section names"]
    high_entropy = sum(section.get_entropy() >= 7.2 for section in pe.sections)
    if high_entropy:
        indicators.append(f"{high_entropy} high-entropy section(s)")
    confidence = 0.96 if packer else min(0.75, 0.25 * len(indicators))
    return result_ok(artifact, "detect_packer", {"packed": bool(indicators), "packer": packer, "confidence": confidence, "indicators": indicators})
