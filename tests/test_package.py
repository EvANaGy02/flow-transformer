import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import pandas as pd

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

    def test_merge_needs_no_ground_truth_and_excludes_label_columns(self):
        with TemporaryDirectory() as temp_dir:
            data_dir = Path(temp_dir)
            job = Transform(
                src_dataset="BoT_IoT",
                tools="zeek",
                data_dir=data_dir,
            )
            tool_dir = job.output_path / "zeek"
            tool_dir.mkdir(parents=True)
            pd.DataFrame(
                {
                    "flow_value": [1, 2],
                    "Label": ["attack", "normal"],
                }
            ).to_parquet(tool_dir / "flows.parquet", index=False)

            job.merge_outputs()

            merged = pd.read_parquet(
                tool_dir / "merged" / "merged.parquet"
            )
            self.assertEqual(merged.columns.tolist(), ["flow_value"])
            self.assertEqual(len(merged), 2)
            self.assertTrue(
                (tool_dir / "merged" / "merged_preview.parquet").exists()
            )


if __name__ == "__main__":
    unittest.main()
