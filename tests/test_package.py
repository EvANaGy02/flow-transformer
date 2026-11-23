import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from transforming_framework import Transform


class PackageTests(unittest.TestCase):
    def test_feature_data_and_data_root_are_available(self):
        with TemporaryDirectory() as temp_dir:
            data_dir = Path(temp_dir)
            job = Transform(
                src_dataset="ToN_IoT",
                goal_datasets="ToN_IoT",
                data_dir=data_dir,
            )

            self.assertIn("src_ip", job.features_dict["ToN_IoT"])
            self.assertEqual(
                job.output_path,
                data_dir / "flow" / "dataset_format_convertion" / "ToN_IoT",
            )

            pcap_dir = data_dir / "pcap" / "ToN_IoT"
            pcap_dir.mkdir(parents=True)
            pcap_file = pcap_dir / "sample.pcap"
            pcap_file.touch()
            self.assertEqual(list(job.get_pcaps("ToN_IoT")), [pcap_file])


if __name__ == "__main__":
    unittest.main()
