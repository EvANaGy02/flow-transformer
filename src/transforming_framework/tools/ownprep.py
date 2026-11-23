
import pandas as pd

from .. import utils
from ..core.interfaces import Tool
from . import own_prep_code
from pathlib import Path
import subprocess as s

class OwnPrepTool(Tool):
    tool_name = "ownprep"

    def run(self, pcap_file: Path, output_dir: Path) -> None:
        print(f"Running own_prep on {pcap_file.name}")
        output_file = output_dir / f"{pcap_file.stem}.parquet"
        csv_file = output_dir / f"{pcap_file.stem}.csv"

        if output_file.exists():
            print(f"parquet already exists for {pcap_file.name}, skipping...")
            return
        utils.path_exists(output_file.parent)

        repaired_pcap = None

        try:
            input_pcap = pcap_file

            if utils.check_pcap(pcap_file):
                print(f"PCAP is valid: {pcap_file}")
            else:
                print(f"Repairing PCAP: {pcap_file}")

                repaired_pcap = output_dir / f"{pcap_file.stem}_repaired.pcap"

                editcap_cmd = [
                    "editcap",
                    "-F", "pcap",
                    str(pcap_file.resolve()),
                    str(repaired_pcap.resolve()),
                ]

                s.run(
                    editcap_cmd,
                    check=True,
                    capture_output=True,
                    text=True,
                )

                input_pcap = repaired_pcap
                print(f"Using repaired PCAP: {repaired_pcap}")

            own_prep_code.run(input_pcap, csv_file)

            # CSV einlesen
            df = pd.read_csv(
                csv_file,
                low_memory=False
            )

            # Spaltennamen bereinigen
            df.columns = df.columns.str.strip()

            # echtes Parquet schreiben
            df.to_parquet(
                output_file,
                index=False
            )

            # optional
            csv_file.unlink(missing_ok=True)

            if repaired_pcap is not None:
                repaired_pcap.unlink(missing_ok=True)

            print(f"Saved own_prep parquet: {output_file}")

        except s.CalledProcessError as e:
            print(f"Argus failed for {pcap_file.name}, skipping...")
            print(f"Command: {e.cmd}")
            print(f"Return code: {e.returncode}")
            print(e.stderr)
            raise ValueError("Error")

        except Exception as e:
            print(f"Unexpected error processing {pcap_file.name}, skipping...")
            print(f"Error: {e}")
            raise ValueError("Error")
