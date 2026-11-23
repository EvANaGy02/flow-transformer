import pandas as pd
import pytz

from .. import utils as ut
from ..core.interfaces import Label


# Y-D-M
attack_and_times = {
    "FTP-BruteForce": {
        "attackers": ["172.31.70.4", "18.221.219.4"],
        "victims": ["172.31.69.25", "18.217.21.148"],
        "times": [
            ut.convert_canadian_to_UTC(["2018-02-14 10:32:00", "2018-02-14 12:09:00"])
        ]
    },

    "SSH-Bruteforce": {
        "attackers": ["172.31.70.6", "13.58.98.64"],
        "victims": ["172.31.69.25", "18.217.21.148"],
        "times": [
            ut.convert_canadian_to_UTC(["2018-02-14 14:01:00", "2018-02-14 15:31:00"])
        ]
    },

    "DoS-GoldenEye": {
        "attackers": ["172.31.70.46", "18.219.211.138"],
        "victims": ["172.31.69.25", "18.217.21.148"],
        "times": [
            ut.convert_canadian_to_UTC(["2018-02-15 09:26:00", "2018-02-15 10:09:00"])
        ]
    },

    "DoS-Slowloris": {
        "attackers": ["172.31.70.8", "18.217.165.70"],
        "victims": ["172.31.69.25", "18.217.21.148"],
        "times": [
            ut.convert_canadian_to_UTC(["2018-02-15 10:59:00", "2018-02-15 11:40:00"])
        ]
    },

    "DoS-SlowHTTPTest": {
        "attackers": ["172.31.70.23", "13.59.126.31"],
        "victims": ["172.31.69.25", "18.217.21.148"],
        "times": [
            ut.convert_canadian_to_UTC(["2018-02-16 10:12:00", "2018-02-16 11:08:00"])
        ]
    },

    "DoS-Hulk": {
        "attackers": ["172.31.70.16", "18.219.193.20"],
        "victims": ["172.31.69.25", "18.217.21.148"],
        "times": [
            ut.convert_canadian_to_UTC(["2018-02-16 13:45:00", "2018-02-16 14:19:00"])
        ]
    },

    "DDoS attacks-LOIC-HTTP": {
        "attackers": [
            "18.218.115.60",
            "18.219.9.1",
            "18.219.32.43",
            "18.218.55.126",
            "52.14.136.135",
            "18.219.5.43",
            "18.216.200.189",
            "18.218.229.235",
            "18.218.11.51",
            "18.216.24.42"
        ],
        "victims": ["172.31.69.25", "18.217.21.148"],
        "times": [
            ut.convert_canadian_to_UTC(["2018-02-20 10:12:00", "2018-02-20 11:17:00"])
        ]
    },

    "DDoS-LOIC-UDP": {
        "attackers": [
            "18.218.115.60",
            "18.219.9.1",
            "18.219.32.43",
            "18.218.55.126",
            "52.14.136.135",
            "18.219.5.43",
            "18.216.200.189",
            "18.218.229.235",
            "18.218.11.51",
            "18.216.24.42"
        ],
        "victims": ["172.31.69.25", "18.217.21.148"],
        "times": [
            ut.convert_canadian_to_UTC(["2018-02-20 13:13:00", "2018-02-20 13:32:00"])
        ]
    },

    "DDOS-LOIC-UDP": {
        "attackers": [
            "18.218.115.60",
            "18.219.9.1",
            "18.219.32.43",
            "18.218.55.126",
            "52.14.136.135",
            "18.219.5.43",
            "18.216.200.189",
            "18.218.229.235",
            "18.218.11.51",
            "18.216.24.42"
        ],
        "victims": ["172.31.69.28", "18.218.83.150"],
        "times": [
            ut.convert_canadian_to_UTC(["2018-02-21 10:09:00", "2018-02-21 10:43:00"])
        ]
    },

    "DDOS-HOIC": {
        "attackers": [
            "18.218.115.60",
            "18.219.9.1",
            "18.219.32.43",
            "18.218.55.126",
            "52.14.136.135",
            "18.219.5.43",
            "18.216.200.189",
            "18.218.229.235",
            "18.218.11.51",
            "18.216.24.42"
        ],
        "victims": ["172.31.69.28", "18.218.83.150"],
        "times": [
            ut.convert_canadian_to_UTC(["2018-02-21 14:05:00", "2018-02-21 15:05:00"])
        ]
    },

    "Brute Force -Web": {
        "attackers": ["18.218.115.60"],
        "victims": ["172.31.69.28", "18.218.83.150"],
        "times": [
            ut.convert_canadian_to_UTC(["2018-02-22 10:17:00", "2018-02-22 11:24:00"]),
            ut.convert_canadian_to_UTC(["2018-02-23 10:03:00", "2018-02-23 11:03:00"])
        ]
    },

    "Brute Force -XSS": {
        "attackers": ["18.218.115.60"],
        "victims": ["172.31.69.28", "18.218.83.150"],
        "times": [
            ut.convert_canadian_to_UTC(["2018-02-22 13:50:00", "2018-02-22 14:29:00"]),
            ut.convert_canadian_to_UTC(["2018-02-23 13:00:00", "2018-02-23 14:10:00"])
        ]
    },

    "SQL Injection": {
        "attackers": ["18.218.115.60"],
        "victims": ["172.31.69.28", "18.218.83.150"],
        "times": [
            ut.convert_canadian_to_UTC(["2018-02-22 16:15:00", "2018-02-22 16:29:00"]),
            ut.convert_canadian_to_UTC(["2018-02-23 15:05:00", "2018-02-23 15:18:00"])
        ]
    },

    "Infiltration": {
        "attackers": ["13.58.225.34"],
        "victims": [
            "172.31.69.24",
            "18.221.148.137",
            "172.31.69.13",
            "18.216.254.154"
        ],
        "times": [
            ut.convert_canadian_to_UTC(["2018-02-28 10:50:00", "2018-02-28 12:05:00"]),
            ut.convert_canadian_to_UTC(["2018-02-28 13:42:00", "2018-02-28 14:40:00"]),
            ut.convert_canadian_to_UTC(["2018-03-01 09:57:00", "2018-03-01 10:55:00"]),
            ut.convert_canadian_to_UTC(["2018-03-01 14:00:00", "2018-03-01 15:37:00"])
        ]
    },

    "Bot": {
        "attackers": ["18.219.211.138"],
        "victims": [
            "18.217.218.111", "172.31.69.23",
            "18.222.10.237", "172.31.69.17",
            "18.222.86.193", "172.31.69.14",
            "18.222.62.221", "172.31.69.12",
            "13.59.9.106", "172.31.69.10",
            "18.222.102.2", "172.31.69.8",
            "18.219.212.0", "172.31.69.6",
            "18.216.105.13", "172.31.69.26",
            "18.219.163.126", "172.31.69.29",
            "18.216.164.12", "172.31.69.30"
        ],
        "times": [
            ut.convert_canadian_to_UTC(["2018-03-02 10:11:00", "2018-03-02 11:34:00"]),
            ut.convert_canadian_to_UTC(["2018-03-02 14:24:00", "2018-03-02 15:55:00"])
        ]
    }
}


class CSECICIDS2018Label(Label):
    def labelling(self, df: pd.DataFrame, name:str, label_binary: bool) -> pd.DataFrame:
        df = df.copy()
        columns = ut.get_flow_columns(df)
        src_col = columns["src"]
        dst_col = columns["dst"]
        ts_col = columns["ts"]

        # timestamp handling
        original_ts = df[ts_col].copy()
        df[ts_col] = ut.normalize_timestamp(df[ts_col])
        df[src_col] = ut.normalize_ip(df[src_col])
        df[dst_col] = ut.normalize_ip(df[dst_col])
        invalid = df[ts_col].isna()
        if invalid.any():
            print(f"Nicht erkennbare Timestamps: {invalid.sum()}")
            print(original_ts[invalid].head(20).to_list())

        def get_attack_label(row):
            src = row[src_col]
            dst = row[dst_col]
            timestamp = row[ts_col]

            for attack_type, attack in attack_and_times.items():
                forward = src in attack["attackers"] and dst in attack["victims"]
                reverse = src in attack["victims"] and dst in attack["attackers"]

                if not (forward or reverse):
                    continue
                for start, end in attack["times"]:
                    start = pd.Timestamp(start)
                    end = pd.Timestamp(end)
                    if start <= timestamp <= end:
                        return attack_type
            return "Normal"

        df["label"] = df.apply(get_attack_label, axis=1)
        # overall labels without extra details #
        df["label"] = df["label"].replace({
            "FTP-BruteForce": "BruteForce",
            "SSH-Bruteforce": "BruteForce"
        })
        df["label"] = df["label"].replace({
            "DoS-GoldenEye": "DoS",
            "DoS-Slowloris": "DoS",
            "DoS-SlowHTTPTest": "DoS",
            "DoS-Hulk": "DoS",
        })
        df["label"] = df["label"].replace({
            "DDoS attacks-LOIC-HTTP": "DDoS",
            "DDoS-LOIC-UDP": "DDoS",
            "DDOS-LOIC-UDP": "DDoS",
            "DDOS-HOIC": "DDoS",
        })
        df["label"] = df["label"].replace({
            "Brute Force -Web": "Webattack",
            "Brute Force -XSS": "Webattack",
            "SQL Injection": "Webattack",
        })
        if label_binary:
            df["label"] = df["label"].map(lambda x: 0 if x == "Normal" else 1)
        atlantic_tz = pytz.timezone("Canada/Atlantic")
        df[ts_col] = (
            df[ts_col]
            .dt.tz_convert(atlantic_tz)
            .dt.strftime("%Y-%m-%d %H:%M:%S.%f %Z")
        )
        return df