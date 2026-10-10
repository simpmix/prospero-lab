import unittest
import tempfile
import zipfile
from pathlib import Path

from prospero_lab.bdj.bdmv_generator import BDMVGenerator
from prospero_lab.bdj.xlet_bundler import XletBundler
from prospero_lab.bdj.iso_builder import DiscImageBuilder


class TestBDMV(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_index_bdmv_magic(self):
        generator = BDMVGenerator()
        index_data = generator.build_index_bdmv()
        self.assertTrue(index_data.startswith(b"INDX0200"))
        self.assertGreater(len(index_data), 40)

    def test_movie_object_magic(self):
        generator = BDMVGenerator()
        mobj_data = generator.build_movie_object_bdmv()
        self.assertTrue(mobj_data.startswith(b"MOBJ0200"))

    def test_structure_generation_and_compliance(self):
        generator = BDMVGenerator()
        paths = generator.build_structure(self.base_dir)

        # Check all core directories exist
        for key, p in paths.items():
            self.assertTrue(p.exists(), f"Path {key} does not exist: {p}")

        # Package JAR
        bundler = XletBundler("prospero.research.ProbeXlet")
        jar_path = bundler.write_jar_to_bdmv(paths["JAR"], "00000.jar")
        self.assertTrue(jar_path.is_file())

        # Inspect JAR content
        with zipfile.ZipFile(jar_path, "r") as zf:
            namelist = zf.namelist()
            self.assertIn("META-INF/MANIFEST.MF", namelist)
            self.assertIn("META-INF/permissionrequestfile.xml", namelist)
            self.assertIn("BDMV/META-INF/permissionrequestfile.xml", namelist)
            self.assertIn("prospero/research/ProbeXlet.class", namelist)

            # Check Java class bytecode header
            class_data = zf.read("prospero/research/ProbeXlet.class")
            self.assertTrue(class_data.startswith(b"\xCA\xFE\xBA\xBE"))

        # Check compliance
        builder = DiscImageBuilder(self.base_dir)
        comp = builder.validate_compliance()
        self.assertTrue(comp["compliant"])


if __name__ == "__main__":
    unittest.main()
