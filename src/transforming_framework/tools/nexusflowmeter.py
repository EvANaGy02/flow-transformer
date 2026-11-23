import pandas as pd

from .. import utils
from ..core.interfaces import Tool
from pathlib import Path
import subprocess as s


class NexusflowmeterTool(Tool):
    tool_name = "nexusflowmeter"

    def run(self, pcap_file: Path, output_dir: Path) -> None:
        output_file = output_dir / f"{pcap_file.stem}.parquet"
        csv_file = output_dir / f"{pcap_file.stem}.csv"
        if output_file.exists():
            print(f"parquet already exists for {pcap_file.name}, skipping...")
            return
        utils.path_exists(output_file.parent)
        print(f"Running NexusFlowMeter on {pcap_file.name}")
        command = [
            "nexusflowmeter",
            str(pcap_file.resolve()),
            str(csv_file.resolve())
        ]
        s.run(command, check=True)
        # CSV einlesen
        df = pd.read_csv(
            csv_file,
            low_memory=False
        )

        # Spaltennamen säubern
        df.columns = df.columns.str.strip()

        # echtes Parquet schreiben
        df.to_parquet(
            output_file,
            index=False
        )

        # optional:
        csv_file.unlink(missing_ok=True)

        print(f"Saved Nexusflowmeter parquet: {output_file}")