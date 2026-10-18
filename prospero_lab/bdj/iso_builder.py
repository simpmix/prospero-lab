"""
BD-J Disc Image & Deployment Builder.
Validates BDMV directory structures and provides automated packaging into
Blu-ray compliant UDF 2.50 optical disc images without external tools.
"""

from pathlib import Path
from typing import Dict, Any, Optional
from prospero_lab.bdj.udf_master import UDF250Master
from prospero_lab.exceptions import BDMVError


class DiscImageBuilder:
    """
    Validates and packages BDMV directory structures into deployment-ready formats,
    including direct pure-Python UDF 2.50 ISO generation.
    """

    def __init__(self, root_dir: Path, volume_label: str = "PROSPERO_BDJ"):
        self.root_dir = root_dir
        self.volume_label = volume_label

    def validate_compliance(self) -> Dict[str, Any]:
        """
        Validates whether the disc layout contains mandatory Blu-ray specifications.
        """
        checks = {
            "BDMV directory exists": (self.root_dir / "BDMV").is_dir(),
            "index.bdmv present": (self.root_dir / "BDMV" / "index.bdmv").is_file(),
            "MovieObject.bdmv present": (self.root_dir / "BDMV" / "MovieObject.bdmv").is_file(),
            "JAR directory present": (self.root_dir / "BDMV" / "JAR").is_dir(),
            "At least one JAR archive present": len(list((self.root_dir / "BDMV" / "JAR").glob("*.jar"))) > 0,
            "BDJO directory present": (self.root_dir / "BDMV" / "BDJO").is_dir(),
            "CLIPINF directory present": (self.root_dir / "BDMV" / "CLIPINF").is_dir(),
            "PLAYLIST directory present": (self.root_dir / "BDMV" / "PLAYLIST").is_dir(),
            "STREAM directory present": (self.root_dir / "BDMV" / "STREAM").is_dir(),
        }

        all_passed = all(checks.values())
        return {
            "compliant": all_passed,
            "details": checks,
        }

    def create_iso(self, output_iso_path: Path) -> Path:
        """
        Directly authors a sector-accurate UDF 2.50 ISO image file using the
        built-in mastering engine.
        """
        compliance = self.validate_compliance()
        if not compliance["compliant"]:
            failed = [k for k, v in compliance["details"].items() if not v]
            raise BDMVError(f"Cannot master non-compliant BDMV disc structure. Failed checks: {failed}")

        master = UDF250Master(volume_label=self.volume_label)
        master.build_iso(self.root_dir, output_iso_path)
        return output_iso_path

    def export_burn_instructions(self, output_iso_path: Optional[Path] = None) -> str:
        """
        Generates platform-specific burning and ISO creation commands for UDF 2.50.
        """
        iso_name = output_iso_path.name if output_iso_path else "prospero_bdj.iso"
        disc_path = str(self.root_dir.resolve())

        return f"""=== BLU-RAY UDF 2.50 AUTHORING INSTRUCTIONS ===

The PS5 requires optical media formatted with Universal Disk Format (UDF) 2.50.

Built-in Pure-Python ISO Generator:
  Use '--iso <output.iso>' with prospero-lab bdj-create to master an ISO directly!

External Tool Options:
1. Windows (Using oscdimg or ImgBurn):
   oscdimg -u2 -udfver102 -m "{disc_path}" {iso_name}
   -or in ImgBurn-
   Set Mode to 'Build', Output to 'Device' or 'Image File', Options -> File System -> UDF 2.50.

2. Linux (Using genisoimage / xorriso):
   xorriso -as mkisofs -iso-level 3 -udf -o {iso_name} "{disc_path}"

3. macOS (Using hdiutil):
   hdiutil makehybrid -udf -udf-version 2.50 -o {iso_name} "{disc_path}"
"""
