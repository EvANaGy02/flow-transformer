from .. import utils
from ..core.interfaces import Tool
from pathlib import Path
import subprocess as s
import pandas as pd

class ArgusTool(Tool):
    tool_name = "argus"
    def run(self, pcap_file: Path, output_dir: Path) -> None:
        output_file = output_dir /f"{pcap_file.stem}.parquet"
        if output_file.exists():
            print(f"parquet already exists for {pcap_file.name}, skipping...")
            return
        utils.path_exists(output_file.parent)
        argus_output_file = output_dir / f"{pcap_file.stem}.argus"
        argus_csv = output_dir / f"{pcap_file.stem}.csv"
        try:
            file_result = s.run(
                ["file", str(pcap_file.resolve())],
                capture_output=True,
                text=True
            )

            input_pcap = pcap_file
            converted_pcap = None

            if "pcapng" in file_result.stdout.lower():
                print(f"{pcap_file.name} is PCAPNG, converting to PCAP...")

                converted_pcap = output_dir / f"{pcap_file.stem}_converted.pcap"

                s.run(
                    [
                        "editcap",
                        "-F", "pcap",
                        str(pcap_file.resolve()),
                        str(converted_pcap.resolve())
                    ],
                    check=True
                )

                input_pcap = converted_pcap

            argus_command = [
                "argus",
                "-r", str(input_pcap.resolve()),
                "-w", str(argus_output_file.resolve())
            ]

            s.run(argus_command, check=True)
            #racluster_command = [
            #    "racluster",
            #    "-r", str(argus_output_file.resolve()),
            #    "-w", str(clustered_argus_file.resolve()),
            #    "-m", "saddr", "daddr", "proto", "sport", "dport"
            #]
            #s.run(racluster_command, check=True)

            fields = [
                "srcid",
                "stime",
                "ltime",
                "sstime",
                "dstime",
                "sltime",
                "dltime",
                "trans",
                "seq",
                "flgs",
                "dur",
                #"avgdur",
                "stddev",
                #"mindur",
                #"maxdur",
                "saddr",
                "daddr",
                "proto",
                "sport",
                "dport",
                "stos",
                "dtos",
                "sdsb",
                "ddsb",
                "sco",
                "dco",
                "sttl",
                "dttl",
                "sipid",
                "dipid",
                "smpls",
                "dmpls",
                "svlan",
                "dvlan",
                "svid",
                "dvid",
                "svpri",
                "dvpri",
                "spkts",
                "dpkts",
                "sbytes",
                "dbytes",
                "sappbytes",
                "dappbytes",
                "sload",
                "dload",
                "sloss",
                "dloss",
                "ploss",
                "srate",
                "drate",
                "smac",
                "dmac",
                "dir",
                "sintpkt",
                "dintpkt",
                "sjit",
                "djit",
                "state",
                "suser",
                "duser",
                "swin",
                "dwin",
                "srng",
                "erng",
                "stcpb",
                "dtcpb",
                "tcprtt",
                "inode",
                "offset",
                "smaxsz",
                "dmaxsz",
                "sminsz",
                "dminsz",
                "dmeansz",
                "smeansz",
                "synack",
                "ackdat"
            ]
            ra_command = [
                "ra",
                "-r", str(argus_output_file.resolve()),
                "-s", ",".join(fields),
                #"-s", "+",
                "-c",
                "\t", "-n", "-u", "-p", "6"
            ]

            print(f"Running Argus on {pcap_file.name}")

            with open(argus_csv, "w") as f:
                s.run(ra_command, stdout=f, check=True)

            if not argus_csv.exists() or argus_csv.stat().st_size == 0:
                print(f"ra produced no output for {pcap_file.name}")
                print(f"Argus file: {argus_output_file}")
                print(f"CSV file: {argus_csv}")
                raise ValueError(f"No Argus_csv produced no output for {pcap_file.name}")

            df = pd.read_csv(
                argus_csv,
                low_memory=False,
                on_bad_lines="warn",
                sep="\t"
            )

            df.columns = df.columns.str.strip()
            #print(df.columns.tolist())
            group_fields = [
                "SrcAddr",
                "DstAddr",
                "Proto",
                "Sport",
                "Dport"
            ]

            # Statistik über Dur pro Flow-Gruppe berechnen
            dur_stats = (
                df.groupby(group_fields)["Dur"]
                .agg(
                    avgdur="mean",
                    mindur="min",
                    maxdur="max",
                    #stddev="std"
                )
                .reset_index()
            )

            # Statistik wieder an jeden Flow anhängen
            df = df.merge(
                dur_stats,
                on=group_fields,
                how="left",
                validate="many_to_one"
            )

            df.to_parquet(output_file, index=False)
            argus_csv.unlink(missing_ok=True)
            if converted_pcap is not None:
                converted_pcap.unlink(missing_ok=True)

            print(f"Saved Argus parquet: {output_file}")

        except s.CalledProcessError as e:
            print(f"Argus failed for {pcap_file.name}, skipping...")
            print(f"Command: {e.cmd}")
            print(f"Return code: {e.returncode}")
            if e.returncode == -6:
                print(f"[WARNING] Argus buffer overflow detected. Skipping: {pcap_file}")
                return
            raise ValueError("Error")

        except Exception as e:
            print(f"Unexpected error processing {pcap_file.name}, skipping...")
            print(f"Error: {e}")
            raise ValueError("Error as Exception")