import pandas as pd

from .. import utils
from ..core.interfaces import Tool
from pathlib import Path
import subprocess as s
import os
import shutil
from scapy.layers.l2 import CookedLinux, Ether
from scapy.packet import Raw
from scapy.utils import PcapReader, PcapWriter

class CICFlowMeterTool(Tool):
    tool_name = "cicflowmeter"


    def run(self, pcap_file: Path, output_dir: Path) -> None:
        output_file = output_dir /f"{pcap_file.stem}.parquet" # cicflowmeter only creates csvs
        if output_file.exists():
            print(f"parquet already exists for {pcap_file.name}, skipping...")
            return
        utils.path_exists(output_file.parent)
        csv_file = output_dir / f"{pcap_file.stem}.csv"
        ## check pcap
        cicflow_pcap = pcap_file
        repaired_pcap = None
        ethernet_pcap = None

        if utils.check_pcap(pcap_file):
           print(f"PCAP is valid: {pcap_file}")
        else:
            print(f"Repairing PCAP: {pcap_file}")#

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
                cicflow_pcap = repaired_pcap
                print(f"Using repaired PCAP: {repaired_pcap}")

            except s.CalledProcessError as e:
                print(
                    f"ERROR: Could not repair {pcap_file}"
                )
                print(e.stderr)
            #    return
        # konvertierung in ethernet format
        # Konvertierung von Linux SLL zu Ethernet
        if utils.get_encapsulation(cicflow_pcap):
            print("Linux SLL detected: converting to Ethernet")
            ethernet_pcap = output_dir / f"{pcap_file.stem}_ethernet.pcap"

            with PcapReader(str(cicflow_pcap)) as reader, PcapWriter(
                    str(ethernet_pcap),
                    linktype=1,  # DLT_EN10MB (Ethernet)
                    sync=True,
            ) as writer:
                for packet in reader:
                    if CookedLinux not in packet:
                        raise ValueError(f"Expected Linux SLL packet, got: {packet.summary()}")
                    sll = packet[CookedLinux]

                    # SLL enthält den Protokolltyp, aber keinen Ethernet-Header.
                    ethernet_packet = (
                            Ether(
                                src="02:00:00:00:00:01",
                                dst="02:00:00:00:00:02",
                                type=int(sll.proto),
                            )
                            / Raw(load=bytes(sll.payload))
                    )
                    ethernet_packet.time = packet.time
                    writer.write(ethernet_packet)

            cicflow_pcap = ethernet_pcap
            print(f"Using converted PCAP: {ethernet_pcap}")
        else:
            print("Ethernet detected: no conversion necessary")
        ###
        # für richtiges cicflowmeter
        wrapper = os.environ.get("CICFLOWMETER_BIN", "cicflowmeter-java")
        executable = shutil.which(wrapper) or (wrapper if Path(wrapper).is_file() else None)
        if executable is None:
            raise FileNotFoundError(
                "CICFlowMeter executable not found. Install a compatible wrapper "
                "or set CICFLOWMETER_BIN to its path."
            )
        command = [
            executable,
            str(cicflow_pcap.resolve()),
            str(output_dir.resolve()),
        ]
        #command = [
        ##    str(wrapper),
        #    "-f", str(pcap_file.resolve()),
        #    "-c", str(csv_file.resolve()),
        #    "-v"
        #]
        print(f"Running CICFlowMeter on {cicflow_pcap.name}")
        result = s.run(command, check=True, capture_output=True,  text=True)
        if result.returncode != 0:
            raise RuntimeError("CICFlowMeter failed")
        print("CICFlowMeter stdout:")
        print(result.stdout)

        print("CICFlowMeter stderr:")
        print(result.stderr)

        print("Output directory:")
        for f in output_dir.iterdir():
            print(f.name)
        # CSV einlesen

        generated_csv = output_dir / f"{cicflow_pcap.name}_Flow.csv"
        generated_csv.rename(csv_file)
        df = pd.read_csv(
            csv_file,
            low_memory=False
        )
        if df.empty:
            raise ValueError(
                f"CICFlowMeter generated an empty CSV for {pcap_file.name}"
            )

        if "Label" in df.columns:
            df = df.drop(columns=["Label"])

        # Spaltennamen bereinigen
        df.columns = df.columns.str.strip()

        # echtes Parquet schreiben
        df.to_parquet(
            output_file,
            index=False
        )

        # optional: CSV löschen
        csv_file.unlink(missing_ok=True)
        if repaired_pcap is not None:
            repaired_pcap.unlink(missing_ok=True)
        if ethernet_pcap is not None:
            ethernet_pcap.unlink(missing_ok=True)

        print(f"Saved CICFlowMeter parquet: {output_file}")