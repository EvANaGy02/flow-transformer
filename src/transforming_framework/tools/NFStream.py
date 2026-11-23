import pandas as pd
from nfstream import NFStreamer
from ..core.interfaces import Tool
from pathlib import Path
from .. import utils
import subprocess as s



class NFStreamTool(Tool):
    tool_name = "nfstream"

    def run(self, pcap_file: Path, output_dir: Path) -> None:
        output_file = output_dir / f"{pcap_file.stem}.parquet"
        temp_csv = output_dir / f"{pcap_file.stem}.csv"
        if output_file.exists():
            print(f"parquet already exists for {pcap_file.name}, skipping...")
            return
        utils.path_exists(output_file.parent)
        ## check pcap
        nfstream_pcap = pcap_file
        repaired_pcap = None

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
            try:
                s.run(
                    editcap_cmd,
                    check=True,
                    capture_output=True,
                    text=True,
                )
                nfstream_pcap = repaired_pcap
                print(
                    f"Using repaired PCAP: {repaired_pcap}"
                )

            except s.CalledProcessError as e:
                print(
                    f"ERROR: Could not repair {pcap_file}"
                )
                print(e.stderr)
                return
        ##
        streamer = NFStreamer(source=nfstream_pcap.resolve())
        streamer.to_csv(path=temp_csv)
        try:
            df = pd.read_csv(temp_csv, low_memory=False)
            df.to_parquet(output_file, index=False)
        finally:
            # CSV immer löschen, auch wenn die Parquet-Erstellung fehlschlägt
            if temp_csv.exists():
                temp_csv.unlink()