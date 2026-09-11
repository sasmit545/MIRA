"""PE header and section analysis, intentionally excluding import/export tables."""

from mira.core.artifact import Artifact
from mira.capabilities.static.common import result_ok, shannon_entropy
from mira.capabilities.static.pe_support import load_pe


def analyze_pe(artifact: Artifact) -> dict:
    pe, failure = load_pe(artifact, "analyze_pe")
    if failure:
        return failure
    sections = []
    for section in pe.sections:
        raw_data = section.get_data()
        sections.append(
            {
                "name": section.Name.rstrip(b"\\0").decode("ascii", errors="replace"),
                "virtual_address": section.VirtualAddress,
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "characteristics": section.Characteristics,
                "entropy": shannon_entropy(raw_data),
            }
        )
    optional = pe.OPTIONAL_HEADER
    architecture = "x64" if pe.FILE_HEADER.Machine == 0x8664 else "x86" if pe.FILE_HEADER.Machine == 0x14C else hex(pe.FILE_HEADER.Machine)
    return result_ok(
        artifact,
        "analyze_pe",
        {
            "architecture": architecture,
            "coff_header": {"machine": pe.FILE_HEADER.Machine, "characteristics": pe.FILE_HEADER.Characteristics},
            "optional_header": {"magic": optional.Magic, "image_base": optional.ImageBase, "subsystem": optional.Subsystem, "dll_characteristics": optional.DllCharacteristics},
            "entry_point": optional.AddressOfEntryPoint,
            "sections": sections,
            "overlay_size": len(pe.get_overlay() or b""),
        },
    )
