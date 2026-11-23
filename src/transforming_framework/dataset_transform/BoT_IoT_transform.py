import numpy as np
import pandas as pd
from ..core.interfaces import DatasetTransform


class BoTIoTTransformer(DatasetTransform):

    PORT_MAPPING = {
        "ftp-data": 20, "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25,
        "domain": 53, "dns": 53, "dhcp": 67, "bootps": 67, "bootpc": 68,
        "tftp": 69, "http": 80, "https": 443, "kerberos": 88, "pop3": 110,
        "nntp": 119, "ntp": 123, "netbios-ns": 137, "netbios-dgm": 138,
        "netbios-ssn": 139, "imap": 143, "snmp": 161, "snmptrap": 162,
        "bgp": 179, "irc": 194, "ldap": 389, "microsoft-ds": 445, "smb": 445,
        "syslog": 514, "printer": 515, "rip": 520, "dhcpv6-client": 546,
        "dhcpv6-server": 547, "rtsp": 554, "submission": 587, "ipp": 631,
        "ldaps": 636, "socks": 1080, "openvpn": 1194, "mssql": 1433,
        "oracle": 1521, "pptp": 1723, "mqtt": 1883, "nfs": 2049, "squid": 3128,
        "mysql": 3306, "rdp": 3389, "stun": 3478, "sip": 5060, "postgresql": 5432,
        "amqp": 5672, "vnc": 5900, "redis": 6379, "http-alt": 8080,
        "https-alt": 8443, "mqtts": 8883, "elasticsearch": 9200, "mongodb": 27017,
    }

    PROTO_MAP = {
        "tcp": 0, "udp": 1, "icmp": 2, "arp": 3,
        "ipv6-icmp": 4, "igmp": 5, "rarp": 6
    }

    STATE_MAP = {
        "fin": 0, "con": 1, "req": 2, "rst": 3, "int": 4, "urg": 5,
        "acc": 6, "clo": 7, "par": 8, "tst": 9, "eco": 10, "clt": 11
    }

    FLAGS_MAP = {
        "e": 0, "e s": 1, "e d": 2, "e g": 3, "e  ": 4, "e u": 5,
        "e i": 6, "e f": 7, "s": 8, "d": 9, "g": 10, "u": 11,
        "i": 12, "f": 13
    }

    def _to_port_num(self, val):
        if pd.isna(val):
            return np.nan
        if isinstance(val, (int, np.integer)):
            return int(val)
        s = str(val).strip().lower()
        if s == "" or s == "nan":
            return np.nan
        if s.isdigit():
            try:
                return int(s)
            except ValueError:
                return np.nan
        return self.PORT_MAPPING.get(s, np.nan)

    def transform(self, parquet_file: pd.DataFrame, goal_features: list = None) -> pd.DataFrame:
        df = parquet_file.copy()

        # ---------------------------------------------------------------------
        # 1. Spaltennamen vereinheitlichen (Alles einheitlich KLEINGESCHRIEBEN!)
        # ---------------------------------------------------------------------
        rename_map = {
            "starttime": "stime", "stime": "stime",
            "lasttime": "ltime", "ltime": "ltime",
            "flgs": "flgs", "seq": "seq",
            "proto": "proto", "proto_number": "proto",
            "srcaddr": "saddr", "saddr": "saddr",
            "sport": "sport",
            "dstaddr": "daddr", "daddr": "daddr",
            "dport": "dport",
            "srcpkts": "spkts", "spkts": "spkts",
            "dstpkts": "dpkts", "dpkts": "dpkts",
            "srcbytes": "sbytes", "sbytes": "sbytes",
            "dstbytes": "dbytes", "dbytes": "dbytes",
            "dur": "dur", "state": "state"
        }

        # Dynamic case-insensitive rename
        low_to_orig = {c.lower(): c for c in df.columns}
        applied_rename = {}
        for k, v in rename_map.items():
            if k in low_to_orig:
                applied_rename[low_to_orig[k]] = v

        df = df.rename(columns=applied_rename)

        # Fehlende Pflichtspalten absichern
        required_base = ["spkts", "dpkts", "sbytes", "dbytes", "dur", "proto", "flgs", "state", "sport", "dport",
                         "saddr", "daddr", "stime", "ltime", "seq"]
        for col in required_base:
            if col not in df.columns:
                df[col] = np.nan

        # ---------------------------------------------------------------------
        # 2. Zeitstempel-Verarbeitung (Fix für HH:MM:SS Strings & null ltime)
        # ---------------------------------------------------------------------
        df["dur"] = pd.to_numeric(df["dur"], errors="coerce").fillna(0.0).astype(float)

        def parse_time_col(series):
            num_series = pd.to_numeric(series, errors="coerce")
            # Falls Uhrzeit als String "18:41:21.25" vorliegt
            if num_series.isna().all() and series.astype(str).str.contains(":").any():
                td = pd.to_timedelta(series.astype(str), errors="coerce")
                return td.dt.total_seconds().fillna(0.0)
            return num_series.fillna(0.0)

        df["stime"] = parse_time_col(df["stime"])

        # ltime berechnen falls missing/null
        ltime_parsed = pd.to_numeric(df["ltime"], errors="coerce")
        if ltime_parsed.isna().all():
            df["ltime"] = df["stime"] + df["dur"]
        else:
            df["ltime"] = ltime_parsed.fillna(df["stime"] + df["dur"])

        # ---------------------------------------------------------------------
        # 3. Basis-Typen & Identifikatoren
        # ---------------------------------------------------------------------
        df = df.reset_index(drop=True)
        df["pkSeqID"] = df.index + 1

        df["sport"] = df["sport"].apply(self._to_port_num)
        df["dport"] = df["dport"].apply(self._to_port_num)

        df["spkts"] = pd.to_numeric(df["spkts"], errors="coerce").fillna(0).astype(int)
        df["dpkts"] = pd.to_numeric(df["dpkts"], errors="coerce").fillna(0).astype(int)
        df["sbytes"] = pd.to_numeric(df["sbytes"], errors="coerce").fillna(0).astype(int)
        df["dbytes"] = pd.to_numeric(df["dbytes"], errors="coerce").fillna(0).astype(int)

        df["pkts"] = df["spkts"] + df["dpkts"]
        df["bytes"] = df["sbytes"] + df["dbytes"]

        # Ratenberechnung (gegen Division by Zero geschützt)
        df["rate"] = np.where(df["dur"] > 0, df["pkts"] / df["dur"], 0.0)
        df["srate"] = np.where(df["dur"] > 0, df["spkts"] / df["dur"], 0.0)
        df["drate"] = np.where(df["dur"] > 0, df["dpkts"] / df["dur"], 0.0)

        # ---------------------------------------------------------------------
        # 4. Explizite Mappings (Fix für 'Proto' vs 'proto' & '*' in flgs)
        # ---------------------------------------------------------------------
        df["proto_number"] = (
            df["proto"]
            .astype(str)
            .str.strip()
            .str.lower()
            .map(self.PROTO_MAP)
            .fillna(-1)
            .astype(int)
        )

        df["state_number"] = (
            df["state"]
            .astype(str)
            .str.strip()
            .str.lower()
            .map(self.STATE_MAP)
            .fillna(-1)
            .astype(int)
        )

        # Argus '*' Sternchen entfernen
        clean_flgs = (
            df["flgs"]
            .astype(str)
            .str.replace("*", "", regex=False)
            .str.strip()
            .str.lower()
        )
        df["flgs_number"] = clean_flgs.map(self.FLAGS_MAP).fillna(-1).astype(int)

        # ---------------------------------------------------------------------
        # 5. Aggregierte Statistik über 5-Tupel
        # ---------------------------------------------------------------------
        agg_key = ["saddr", "daddr", "proto", "sport", "dport"]
        flow_group = df.groupby(agg_key, dropna=False)["dur"]

        df["mean"] = flow_group.transform("mean").fillna(0.0)
        df["stddev"] = flow_group.transform("std").fillna(0.0)
        df["sum"] = flow_group.transform("sum").fillna(0.0)
        df["min"] = flow_group.transform("min").fillna(0.0)
        df["max"] = flow_group.transform("max").fillna(0.0)

        # ---------------------------------------------------------------------
        # 6. Gruppen-Features (Bytes & Packets)
        # ---------------------------------------------------------------------
        df["TnBPSrcIP"] = df.groupby("saddr", dropna=False)["bytes"].transform("sum")
        df["TnBPDstIP"] = df.groupby("daddr", dropna=False)["bytes"].transform("sum")
        df["TnP_PSrcIP"] = df.groupby("saddr", dropna=False)["pkts"].transform("sum")
        df["TnP_PDstIP"] = df.groupby("daddr", dropna=False)["pkts"].transform("sum")
        df["TnP_PerProto"] = df.groupby("proto", dropna=False)["pkts"].transform("sum")
        df["TnP_Per_Dport"] = df.groupby("dport", dropna=False)["pkts"].transform("sum")

        # ---------------------------------------------------------------------
        # 7. Average Rates
        # ---------------------------------------------------------------------
        def calc_avg_rate(keys):
            sum_pkts = df.groupby(keys, dropna=False)["pkts"].transform("sum")
            sum_dur = df.groupby(keys, dropna=False)["dur"].transform("sum")
            return np.where(sum_dur > 0, sum_pkts / sum_dur, 0.0)

        df["AR_P_Proto_P_SrcIP"] = calc_avg_rate(["proto", "saddr"])
        df["AR_P_Proto_P_DstIP"] = calc_avg_rate(["proto", "daddr"])
        df["AR_P_Proto_P_Sport"] = calc_avg_rate(["proto", "sport"])
        df["AR_P_Proto_P_Dport"] = calc_avg_rate(["proto", "dport"])

        # ---------------------------------------------------------------------
        # 8. Inbound Connections & Packets per State
        # ---------------------------------------------------------------------
        df["N_IN_Conn_P_SrcIP"] = df.groupby("saddr", dropna=False)["pkts"].transform("count")
        df["N_IN_Conn_P_DstIP"] = df.groupby("daddr", dropna=False)["pkts"].transform("count")

        df["Pkts_P_State_P_Protocol_P_DestIP"] = df.groupby(["daddr", "state", "proto"], dropna=False)[
            "pkts"].transform("sum")
        df["Pkts_P_State_P_Protocol_P_SrcIP"] = df.groupby(["saddr", "state", "proto"], dropna=False)["pkts"].transform(
            "sum")

        # ---------------------------------------------------------------------
        # 9. Sicheres Filtern & Reorganisieren
        # ---------------------------------------------------------------------
        df_reduced = df[[col for col in df.columns if col in goal_features]]
        if len(df_reduced.columns) == len(goal_features):
            print("Selbe Länge")
        else:
            print("Ungleich")
            missing_features = set(goal_features) - set(df_reduced.columns)
            # print(missing_features)
            print(f"Adding missing features {missing_features}")
            for feature in missing_features:
                df_reduced[feature] = np.nan
        return df_reduced