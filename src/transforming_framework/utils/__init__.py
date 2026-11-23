from pathlib import Path
import pandas as pd
import subprocess as s
import re
import pyarrow.parquet as pq
import numpy as np


from datetime import datetime, timezone
import pytz
from pandas import DatetimeIndex, Series, Timestamp


def iter_csvs(path):
    for file in Path(path).rglob("*.csv"):
        yield pd.read_csv(file)


def path_exists(path):
    Path(path).mkdir(parents=True, exist_ok=True)


#def is_real_parquet(file: Path) -> bool:
#    try:
#        with open(file, "rb") as f:
#            if f.read(4) != b"PAR1":
#                return False
#            f.seek(-4, 2)
#            if f.read() != b"PAR1":
#                return False
#        return True
#    except:
#        return False


def is_real_parquet(file: Path) -> bool:
    try:
        pq.read_schema(file)
        return True
    except Exception as e:
        print(f"No real parquet due to error {e}")
        return False


def split_pcap(pcap_file: Path, chunk_dir: Path, chunk_size_packets: int = 1_000_000, max_size_pcap: int = 1_000_000_000) -> list[Path]:
        if pcap_file.stat().st_size > max_size_pcap:
            print(f"{pcap_file.name} > 1GB, splitting into chunks...")
            # existiert und ist nicht leer
            if chunk_dir.exists() and any(chunk_dir.iterdir()):
                return sorted(chunk_dir.glob("*.pcap")) # gebe pcaps aus Ordner zurück
            path_exists(chunk_dir)
            chunk_pattern = chunk_dir / f"chunk_{pcap_file.stem}.pcap"
            s.run(["editcap", "-c", str(chunk_size_packets), str(pcap_file.resolve()), str(chunk_pattern)], check=True)
            chunk_files = sorted(chunk_dir.glob("*.pcap"))
            return chunk_files
        else:
            return [pcap_file]


def parquet_exists(pcap_file: Path, output_path: Path) -> bool:
    #pattern = re.compile(rf"\b{re.escape(pcap_file.stem)}\b")
    pattern = re.compile(rf"(^|_)({re.escape(pcap_file.stem)})(_|\Z)")
    for parquet_file in output_path.rglob("*.parquet"):
        if pattern.search(parquet_file.stem):
            return True
    return False


def convert_canadian_to_UTC(input):
    timezone = pytz.timezone("Canada/Atlantic")
    canadian_time1 = datetime.strptime(input[0], "%Y-%m-%d %H:%M:%S")
    canadian_time2 = datetime.strptime(input[1], "%Y-%m-%d %H:%M:%S")
    time1 = timezone.localize(canadian_time1)
    time2 = timezone.localize(canadian_time2)
    utc_time1 = time1.astimezone(pytz.utc)
    utc_time2 = time2.astimezone(pytz.utc)
    return [pd.Timestamp(utc_time1),pd.Timestamp(utc_time2)]


def get_flow_columns(df: pd.DataFrame):
    # containing features from all tools and dataset formats
    column_mapping = {
        "src": ["SrcAddr", "src_addr", "Source IP", "saddr", "conn_id.orig_h", "Src IP", "src_ip", "srcip"],
        "dst": ["DstAddr", "dst_addr", "Destination IP", "daddr", "conn_id.resp_h", "Dst IP", "dst_ip", "dstip"],
        "proto": ["Proto", "protocol", "Protocol", "proto", "conn_proto"],
        "sport": ["Sport", "src_port", "Source Port", "sport", "conn_id.orig_p", "Src Port"],
        "dport": ["Dport", "dst_port", "Destination Port", "dport", "conn_id.resp_p", "Dst Port", "dsport"],
        "ts": ["bidirectional_first_seen_ms","Timestamp", "conn_ts", "StartTime", "Starttime", "start_time", "Start Time", "stime", "timestamp", "ts"]
    }
    result = {}
    for key, possible_names in column_mapping.items():
        found = next((col for col in possible_names if col in df.columns), None)
        if found is None:
            raise ValueError(
                f"Keine Spalte für '{key}' gefunden. "
                f"Erwartet eine von: {possible_names}"
            )
        result[key] = found
    return result


from dateutil import parser
def normalize_timestamp(values: pd.Series) -> Timestamp | Series | DatetimeIndex:
    atlantic = pytz.timezone("Canada/Atlantic")

    def unwrap(value):
        if isinstance(value, np.ndarray):
            return value.item() if value.size == 1 else np.nan
        return value

    raw = values.map(unwrap).astype("string").str.strip()
    cleaned = raw.str.replace(",", ".", regex=False)

    # 1. Unix-Zeitstempel, auch als String
    numeric = pd.to_numeric(cleaned, errors="coerce")
    result = pd.to_datetime(
        numeric,
        unit="s",
        utc=True,
        errors="coerce",
    )

    # 2. Datumsstrings, z. B. "02/03/2018 12:47:38 PM"
    text_mask = numeric.isna() & raw.notna() & raw.ne("")

    def parse_text(text):
        try:
            # dayfirst=True: 02/03/2018 = 2. März 2018
            dt = parser.parse(text, dayfirst=True, fuzzy=False)

            # Zeitangaben ohne Zeitzone sind Canada/Atlantic
            if dt.tzinfo is None:
                dt = atlantic.localize(dt)

            return pd.Timestamp(dt).tz_convert("UTC")
        except (ValueError, TypeError, OverflowError):
            return pd.NaT

    result.loc[text_mask] = raw.loc[text_mask].map(parse_text)

    return result


def balance_dataset_indices(y, sample_size=10000, seed=42):
    print("Balancing Seed: " + str(seed))
    rng = np.random.default_rng(seed)

    unique_classes = np.unique(y)
    balanced_indices = []

    for unique_class in unique_classes:
        mask = y == unique_class
        class_indices = np.where(mask)[0]
        current_count = class_indices.shape[0]

        if current_count < sample_size:  # oversample
            resample_indices = rng.choice(class_indices, size=sample_size, replace=True)
        elif current_count > sample_size:  # undersample
            resample_indices = rng.choice(class_indices, size=sample_size, replace=False)
        else:
            resample_indices = class_indices

        balanced_indices.append(resample_indices)

    balanced_indices = np.hstack(balanced_indices)
    rng.shuffle(balanced_indices)

    return balanced_indices

def is_pcapng(pcap_file: Path) -> bool:
    result = s.run(
        ["capinfos", "-t", str(pcap_file.resolve())],
        capture_output=True,
        text=True,
        check=True
    )
    return "pcapng" in result.stdout.lower()

def check_pcap(pcap_file: Path) -> bool:
    result = s.run(
        [
            "capinfos",
            "-t",
            str(pcap_file.resolve()),
        ],
        stdout=s.PIPE,
        stderr=s.PIPE,
        text=True,
    )
    output = (result.stdout or "").lower()
    error = (result.stderr or "").lower()
    if result.returncode != 0:
        print(f"⚠️ Could not read PCAP: {pcap_file}")
        print(result.stderr)
        return False
    if "pcapng" in output:
        print(f"⚠️ PCAPNG detected: {pcap_file}")
        return False
    # weiterhin auf kaputte/truncated PCAPs prüfen
    tcpdump_result = s.run(
        [
            "tcpdump",
            "-r",
            str(pcap_file.resolve()),
        ],
        stdout=s.DEVNULL,
        stderr=s.PIPE,
        text=True,
    )
    tcpdump_error = (tcpdump_result.stderr or "").lower()
    if "truncated dump file" in tcpdump_error:
        print(f"⚠️ Truncated PCAP detected: {pcap_file}")
        return False
    if tcpdump_result.returncode != 0:
        print(f"⚠️ Could not read PCAP: {pcap_file}")
        print(tcpdump_result.stderr)
        return False
    return True

def get_encapsulation(pcap_file: Path) -> bool:
    result = s.run(
        ["capinfos", "-E", str(pcap_file.resolve())],
        capture_output=True,
        text=True,
        check=True
    )

    for line in result.stdout.splitlines():
        if "File encapsulation:" in line:
            encapsulation = line.split(":", 1)[1].strip()

            if encapsulation == "Linux cooked-mode capture v1":
                return True

            if encapsulation == "Ethernet":
                return False

            raise ValueError(
                f"Unsupported encapsulation: {encapsulation}"
            )

    raise ValueError(f"Could not determine encapsulation: {pcap_file}")

def normalize_port(series):
    return (
        series.astype("string")
        .str.strip()
        .str.replace(r"\.0$", "", regex=True)
    )

def normalize_protocol(series):
    protocol_mapping = { # für argus
        "6": "tcp",
        "17": "udp",
        "1": "icmp",
        "58": "icmpv6",
    }
    return (
        series.astype("string")
        .str.strip()
        .str.lower()
        .replace(protocol_mapping)
    )

def normalize_ip(series):
    return (
        series.astype("string")
        .str.strip()
    )