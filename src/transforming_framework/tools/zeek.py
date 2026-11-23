from pathlib import Path
import subprocess as s
import pandas as pd
from ..core.interfaces import Tool
from .. import utils

class ZeekTool(Tool):
    tool_name = "zeek"

    def run(self, pcap_file: Path, output_dir: Path) -> None:
        print(f"Processing {pcap_file}")
        utils.path_exists(output_dir)
        output_file = output_dir / f"{pcap_file.stem}.parquet"
        if output_file.exists():
            print(f"Zeek: parquet already exists for {pcap_file.name}, skipping...")
            return

        dfs = []

        # ---------------------------------------------------------
        # PCAP prüfen
        # ---------------------------------------------------------

        zeek_pcap = pcap_file
        repaired_pcap = None

        if utils.check_pcap(pcap_file):
            print(f"PCAP is valid: {pcap_file}")
        else:
            print(f"Repairing PCAP: {pcap_file}")

            repaired_pcap = output_dir / f"{pcap_file.stem}_repaired.pcap"

            editcap_cmd = [
                "editcap",
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
                zeek_pcap = repaired_pcap
                print(
                    f"Using repaired PCAP: {repaired_pcap}"
                )

            except s.CalledProcessError as e:
                print(
                    f"ERROR: Could not repair {pcap_file}"
                )
                print(e.stderr)
                return

        # Zeek direkt auf das gesamte PCAP anwenden
        print(f"Running Zeek on {pcap_file}")
        #zeek_cmd = ["zeek", "-C", "-r", str(pcap_file.resolve())]
        zeek_cmd = ["zeek", "-C", "-r", str(zeek_pcap.resolve())]
        s.run(zeek_cmd, cwd=output_dir, check=True)

        # Logs einlesen
        log_files = list(output_dir.glob("*.log"))
        print("Processing Zeek log files")
        for i, log_file in enumerate(log_files, 1):
            log_name = log_file.stem
            with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            headers, data_lines = [], []
            for line in lines:
                line = line.strip()
                if line.startswith("#fields"):
                    headers = line.split()[1:]
                elif not line.startswith("#") and headers:
                    data_lines.append(line.split("\t"))
            if not headers or not data_lines:
                continue
            df = pd.DataFrame(data_lines, columns=headers)
            uid_cols = [col for col in df.columns if col == "uid" or col.endswith("_uid")]
            if uid_cols:
                uid_col = "uid" if "uid" in uid_cols else uid_cols[0]
                df = df.rename(columns={uid_col: "uid"})
            else:
                df["uid"] = [f"{log_name}_{i}" for i in range(len(df))]
            df = df.rename(columns={col: f"{log_name}_{col}" for col in df.columns if col != "uid"})
            dfs.append(df)
            log_file.unlink(missing_ok=True)
        for log in log_files:
            log.unlink(missing_ok=True)

        if not dfs:
            raise FileNotFoundError(f"No usable Zeek logs for {pcap_file}")

        print("Aggregating Zeek logs")
        aggregated_dfs = []

        for i, df in enumerate(dfs):
            print(
                f"[BEFORE AGG] Log {i}: "
                f"rows={len(df):,}, "
                f"cols={len(df.columns):,}, "
                f"unique UID={df['uid'].nunique():,}",
                flush=True
            )

            if df["uid"].is_unique:
                print(f"[SKIP AGG] Log {i}: UID already unique", flush=True)
                agg_df = df
            else:
                agg_df = self.aggregate_zeek_log(df)

            print(
                f"[AFTER AGG] Log {i}: "
                f"rows={len(agg_df):,}, "
                f"cols={len(agg_df.columns):,}, "
                f"unique UID={agg_df['uid'].nunique():,}",
                flush=True
            )

            aggregated_dfs.append(agg_df)

        dfs = aggregated_dfs
        #dfs = [
        #    self.aggregate_zeek_log(df)
        #    for df in dfs
        #]
        for i, df in enumerate(dfs):
            print(
                f"Log {i}: "
                f"rows={len(df):,}, "
                f"unique UID={df['uid'].nunique():,}"
            )

        print("Merging log files")
        # DataFrames zusammenführen
        full_df = dfs[0]
        for df in dfs[1:]:
            full_df = pd.merge(
                full_df,
                df,
                on="uid",
                how="outer",
                sort=False,
                copy=False,
                validate="one_to_one"
            )

        full_df.to_parquet(output_file, index=False)
        if repaired_pcap is not None:
            repaired_pcap.unlink(missing_ok=True)

        print(f"Saved Zeek parquet: {output_file}")

    @staticmethod
    def aggregate_zeek_log(df):
        uids = df["uid"].drop_duplicates()
        result = pd.DataFrame({"uid": uids})

        for col in df.columns:
            if col == "uid":
                continue
            # exakt dieselbe Reihenfolge wie vorher:
            # dropna -> str -> "-" entfernen
            s = df[col].dropna().astype(str)
            s = s[s.ne("-")]
            tmp = pd.DataFrame({
                "uid": df.loc[s.index, "uid"].to_numpy(),
                col: s.to_numpy(),
            })
            # entspricht .unique() innerhalb jeder uid-Gruppe
            tmp = tmp.drop_duplicates(
                subset=["uid", col],
                keep="first",
            )
            aggregated = (
                tmp.groupby("uid", sort=False)[col]
                .agg("|".join)
            )
            # UIDs ohne gültigen Wert bekommen wie vorher ""
            result[col] = result["uid"].map(aggregated).fillna("")
        return result