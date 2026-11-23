import numpy as np
import pandas as pd

from collections import defaultdict, deque
from time import perf_counter

from ..core.interfaces import DatasetTransform


# ============================================================
# Connection Features - Efficient Version
# ============================================================

def calculate_connection_features_efficient(
    df: pd.DataFrame
) -> pd.DataFrame:
    """
    Compute UNSW-NB15 connection features 37-47.

    Sliding window:
        100 flows

    The current flow is included in the window.

    The dataframe must already be sorted by ltime.

    Important:
    Feature 37 follows the original reference semantics for
    missing values:

        NaN == NaN  -> False

    Therefore two rows with missing state/TTL do NOT match
    each other for ct_state_ttl.
    """

    WINDOW = 100

    # ========================================================
    # Feature 37 - TTL bins
    # ========================================================

    bins = [
        0,
        32,
        64,
        96,
        128,
        160,
        192,
        224,
        256,
    ]

    df["sttl_bin"] = pd.cut(
        df["sttl"],
        bins=bins,
        labels=False,
        include_lowest=True,
    )

    df["dttl_bin"] = pd.cut(
        df["dttl"],
        bins=bins,
        labels=False,
        include_lowest=True,
    )

    # --------------------------------------------------------
    # Preserve reference semantics for NaN.
    #
    # Valid bins:
    #     0 ... 7
    #
    # Missing bins receive a unique negative value for each
    # row. Therefore:
    #
    #     missing row 1 != missing row 2
    #
    # exactly like:
    #
    #     NaN == NaN -> False
    # --------------------------------------------------------

    n = len(df)

    sttl_missing = (
        -(np.arange(n, dtype=np.int64) + 1)
    )

    dttl_missing = (
        -(np.arange(n, dtype=np.int64) + n + 1)
    )

    sttl_values = (
        df["sttl_bin"]
        .to_numpy(dtype="float64")
    )

    dttl_values = (
        df["dttl_bin"]
        .to_numpy(dtype="float64")
    )

    sttl_missing_mask = np.isnan(sttl_values)
    dttl_missing_mask = np.isnan(dttl_values)

    sttl_bin_values = np.where(
        sttl_missing_mask,
        sttl_missing,
        sttl_values.astype(np.int64),
    )

    dttl_bin_values = np.where(
        dttl_missing_mask,
        dttl_missing,
        dttl_values.astype(np.int64),
    )

    df["sttl_bin"] = sttl_bin_values
    df["dttl_bin"] = dttl_bin_values

    # ========================================================
    # State key
    # ========================================================

    state_values = (
        df["state"]
        .astype(object)
        .to_numpy()
    )

    state_keys = np.empty(
        n,
        dtype=object,
    )

    for i in range(n):

        value = state_values[i]

        if pd.isna(value):

            # Unique sentinel per row.
            # This reproduces NaN != NaN.
            state_keys[i] = (
                f"__nan_state_{i}__"
            )

        else:

            state_keys[i] = str(value)

    df["state_key"] = state_keys

    # ========================================================
    # Feature 37 key
    # ========================================================

    state_ttl_keys = list(
        zip(
            state_keys,
            sttl_bin_values,
            dttl_bin_values,
        )
    )

    # ========================================================
    # Feature 38 - HTTP
    # ========================================================

    if "http_method" in df.columns:

        http_mask = (
            df["service"]
            .astype("string")
            .str.lower()
            .eq("http")
            &
            df["http_method"].notna()
        )

    else:

        http_mask = pd.Series(
            False,
            index=df.index,
        )

    # ========================================================
    # Feature 40 - FTP command
    # ========================================================

    if "ftp_command" in df.columns:

        ftp_mask = (
            df["service"]
            .astype("string")
            .str.lower()
            .eq("ftp")
            &
            df["ftp_command"].notna()
        )

    else:

        ftp_mask = pd.Series(
            False,
            index=df.index,
        )

    # ========================================================
    # Feature 39 - FTP login
    # ========================================================

    if {
        "ftp_user",
        "ftp_password",
    }.issubset(df.columns):

        df["is_ftp_login"] = (
            df["ftp_user"].notna()
            &
            df["ftp_password"].notna()
        ).astype(int)

    else:

        df["is_ftp_login"] = pd.Series(
            0,
            index=df.index,
            dtype=int,
        )

    # ========================================================
    # Result columns
    # ========================================================

    features = [
        "ct_state_ttl",
        "ct_flw_http_mthd",
        "ct_ftp_cmd",
        "ct_srv_src",
        "ct_srv_dst",
        "ct_dst_ltm",
        "ct_src_ltm",
        "ct_src_dport_ltm",
        "ct_dst_sport_ltm",
        "ct_dst_src_ltm",
    ]

    result = {
        feature: []
        for feature in features
    }

    # ========================================================
    # Counters
    # ========================================================

    counters = {

        "state_ttl":
            defaultdict(int),

        "srv_src":
            defaultdict(int),

        "srv_dst":
            defaultdict(int),

        "dst":
            defaultdict(int),

        "src":
            defaultdict(int),

        "src_dport":
            defaultdict(int),

        "dst_sport":
            defaultdict(int),

        "dst_src":
            defaultdict(int),
    }

    window = deque()

    # ========================================================
    # Prepare arrays
    # ========================================================

    http_values = (
        http_mask
        .to_numpy(dtype=bool)
    )

    ftp_values = (
        ftp_mask
        .to_numpy(dtype=bool)
    )

    src_series = (
        df["srcip"]
        .astype(object)
    )

    dst_series = (
        df["dstip"]
        .astype(object)
    )

    service_series = (
        df["service"]
        .astype("string")
        .str.lower()
        .fillna("")
    )

    sport_series = (
        df["sport"]
        .astype("string")
        .fillna("")
    )

    dsport_series = (
        df["dsport"]
        .astype("string")
        .fillna("")
    )

    # ========================================================
    # Sliding window
    # ========================================================

    http_count = 0
    ftp_count = 0

    for i in range(n):

        # ----------------------------------------------------
        # Current keys
        # ----------------------------------------------------

        key_state_ttl = (
            state_ttl_keys[i]
        )

        key_srv_src = (
            src_series.iat[i],
            service_series.iat[i],
        )

        key_srv_dst = (
            dst_series.iat[i],
            service_series.iat[i],
        )

        key_dst = (
            dst_series.iat[i]
        )

        key_src = (
            src_series.iat[i]
        )

        key_src_dport = (
            src_series.iat[i],
            dsport_series.iat[i],
        )

        key_dst_sport = (
            dst_series.iat[i],
            sport_series.iat[i],
        )

        key_dst_src = (
            src_series.iat[i],
            dst_series.iat[i],
        )

        keys = {

            "state_ttl":
                key_state_ttl,

            "srv_src":
                key_srv_src,

            "srv_dst":
                key_srv_dst,

            "dst":
                key_dst,

            "src":
                key_src,

            "src_dport":
                key_src_dport,

            "dst_sport":
                key_dst_sport,

            "dst_src":
                key_dst_src,
        }

        # ----------------------------------------------------
        # Add current flow
        # ----------------------------------------------------

        window.append(keys)

        for name, key in keys.items():

            counters[name][key] += 1

        if http_values[i]:
            http_count += 1

        if ftp_values[i]:
            ftp_count += 1

        # ----------------------------------------------------
        # Remove oldest flow
        # ----------------------------------------------------

        if len(window) > WINDOW:

            old = window.popleft()

            for name, key in old.items():

                counters[name][key] -= 1

                if counters[name][key] == 0:

                    del counters[name][key]

            old_i = i - WINDOW

            if http_values[old_i]:
                http_count -= 1

            if ftp_values[old_i]:
                ftp_count -= 1

        # ----------------------------------------------------
        # Record results
        # ----------------------------------------------------

        result["ct_state_ttl"].append(
            counters["state_ttl"].get(
                key_state_ttl,
                0,
            )
        )

        result["ct_srv_src"].append(
            counters["srv_src"].get(
                key_srv_src,
                0,
            )
        )

        result["ct_srv_dst"].append(
            counters["srv_dst"].get(
                key_srv_dst,
                0,
            )
        )

        result["ct_dst_ltm"].append(
            counters["dst"].get(
                key_dst,
                0,
            )
        )

        result["ct_src_ltm"].append(
            counters["src"].get(
                key_src,
                0,
            )
        )

        result["ct_src_dport_ltm"].append(
            counters["src_dport"].get(
                key_src_dport,
                0,
            )
        )

        result["ct_dst_sport_ltm"].append(
            counters["dst_sport"].get(
                key_dst_sport,
                0,
            )
        )

        result["ct_dst_src_ltm"].append(
            counters["dst_src"].get(
                key_dst_src,
                0,
            )
        )

        result["ct_flw_http_mthd"].append(
            http_count
        )

        result["ct_ftp_cmd"].append(
            ftp_count
        )

    # ========================================================
    # Attach results
    # ========================================================

    for name, values in result.items():

        df[name] = values

    return df


# ============================================================
# UNSW-NB15 Transformer
# ============================================================

class UNSWNB15Transformer(DatasetTransform):

    # ========================================================
    # Port mapping
    # ========================================================

    PORT_MAPPING = {

        "ftp-data": 20,
        "ftp": 21,
        "ssh": 22,
        "telnet": 23,
        "smtp": 25,

        "domain": 53,
        "dns": 53,

        "dhcp": 67,
        "bootps": 67,
        "bootpc": 68,

        "tftp": 69,

        "http": 80,
        "https": 443,

        "kerberos": 88,
        "pop3": 110,
        "nntp": 119,
        "ntp": 123,

        "netbios-ns": 137,
        "netbios-dgm": 138,
        "netbios-ssn": 139,

        "imap": 143,

        "snmp": 161,
        "snmptrap": 162,

        "bgp": 179,
        "irc": 194,

        "ldap": 389,

        "microsoft-ds": 445,
        "smb": 445,

        "syslog": 514,
        "printer": 515,
        "rip": 520,

        "dhcpv6-client": 546,
        "dhcpv6-server": 547,

        "rtsp": 554,
        "submission": 587,
        "ipp": 631,
        "ldaps": 636,

        "socks": 1080,
        "openvpn": 1194,

        "mssql": 1433,
        "oracle": 1521,
        "pptp": 1723,
        "mqtt": 1883,
        "nfs": 2049,
        "squid": 3128,

        "mysql": 3306,
        "rdp": 3389,
        "stun": 3478,
        "sip": 5060,
        "postgresql": 5432,
        "amqp": 5672,
        "vnc": 5900,
        "redis": 6379,

        "http-alt": 8080,
        "https-alt": 8443,
        "mqtts": 8883,

        "elasticsearch": 9200,
        "mongodb": 27017,
    }

    # ========================================================
    # IP normalization - scalar
    # ========================================================

    @staticmethod
    def normalize_ip(value):

        if pd.isna(value):
            return None

        value = str(value).strip().lower()

        if not value:
            return None

        if (
            value.startswith("[")
            and value.endswith("]")
        ):

            value = value[1:-1]

        return value

    # ========================================================
    # IP normalization - vectorized
    # ========================================================

    @staticmethod
    def normalize_ip_series(series):

        result = (
            series
            .astype("string")
            .str.strip()
            .str.lower()
        )

        result = (
            result
            .str.replace(
                r"^\[(.*)\]$",
                r"\1",
                regex=True,
            )
        )

        result = result.mask(
            result.eq(""),
            pd.NA,
        )

        return result

    # ========================================================
    # Port normalization - scalar
    # ========================================================

    @classmethod
    def normalize_port(cls, value):

        if pd.isna(value):
            return None

        value = str(value).strip().lower()

        if not value:
            return None

        # Numeric port
        try:

            numeric_value = float(value)

            if numeric_value.is_integer():

                return str(
                    int(numeric_value)
                )

        except (
            ValueError,
            TypeError,
        ):
            pass

        # Symbolic service
        if value in cls.PORT_MAPPING:

            return str(
                cls.PORT_MAPPING[value]
            )

        return value

    # ========================================================
    # Protocol normalization - scalar
    # ========================================================

    @staticmethod
    def normalize_protocol(value):

        if pd.isna(value):
            return None

        value = (
            str(value)
            .strip()
            .lower()
        )

        protocol_mapping = {

            "6":
                "tcp",

            "tcp":
                "tcp",

            "17":
                "udp",

            "udp":
                "udp",

            "1":
                "icmp",

            "icmp":
                "icmp",

            "58":
                "icmpv6",

            "icmpv6":
                "icmpv6",
        }

        return protocol_mapping.get(
            value,
            value,
        )

    # ========================================================
    # Protocol normalization - vectorized
    # ========================================================

    @staticmethod
    def normalize_protocol_series(series):

        result = (
            series
            .astype("string")
            .str.strip()
            .str.lower()
        )

        return result.replace(
            {
                "6": "tcp",
                "tcp": "tcp",
                "17": "udp",
                "udp": "udp",
                "1": "icmp",
                "icmp": "icmp",
                "58": "icmpv6",
                "icmpv6": "icmpv6",
            }
        )

    # ========================================================
    # Service normalization
    # ========================================================

    @staticmethod
    def normalize_service(value):

        if pd.isna(value):
            return None

        value = (
            str(value)
            .strip()
            .lower()
        )

        if not value:
            return None

        return value

    # ========================================================
    # Normalize Argus
    # ========================================================

    def normalize_argus(
        self,
        df: pd.DataFrame,
    ) -> pd.DataFrame:

        # Argus is small (~5k rows), therefore scalar
        # normalization is completely fine here.

        df["SrcAddr"] = (
            df["SrcAddr"]
            .apply(self.normalize_ip)
        )

        df["DstAddr"] = (
            df["DstAddr"]
            .apply(self.normalize_ip)
        )

        df["Sport"] = (
            df["Sport"]
            .apply(self.normalize_port)
        )

        df["Dport"] = (
            df["Dport"]
            .apply(self.normalize_port)
        )

        df["Proto"] = (
            df["Proto"]
            .apply(self.normalize_protocol)
        )

        return df

    # ========================================================
    # Vectorized bidirectional flow key
    # ========================================================

    @staticmethod
    def create_flow_keys_vectorized(
        src_ip: pd.Series,
        src_port: pd.Series,
        dst_ip: pd.Series,
        dst_port: pd.Series,
        proto: pd.Series,
    ) -> pd.Series:
        """
        Create bidirectional flow keys without apply(axis=1).

        Example:

            A:12345 -> B:80
            B:80    -> A:12345

        produce the same key.

        The endpoint representation is:

            ip|port

        and the two endpoints are sorted lexicographically.
        """

        src_ip = (
            src_ip
            .astype("string")
            .fillna("<NA>")
        )

        src_port = (
            src_port
            .astype("string")
            .fillna("<NA>")
        )

        dst_ip = (
            dst_ip
            .astype("string")
            .fillna("<NA>")
        )

        dst_port = (
            dst_port
            .astype("string")
            .fillna("<NA>")
        )

        proto = (
            proto
            .astype("string")
            .fillna("<NA>")
        )

        src_endpoint = (
            src_ip
            + "|"
            + src_port
        )

        dst_endpoint = (
            dst_ip
            + "|"
            + dst_port
        )

        src_first = (
            src_endpoint
            <= dst_endpoint
        )

        left_endpoint = (
            src_endpoint.where(
                src_first,
                dst_endpoint,
            )
        )

        right_endpoint = (
            dst_endpoint.where(
                src_first,
                src_endpoint,
            )
        )

        return (
            left_endpoint
            + "|"
            + right_endpoint
            + "|"
            + proto
        )

    # ========================================================
    # Transform
    # ========================================================

    def transform(
        self,
        argus_parquet_file: pd.DataFrame,
        zeek_parquet_file: pd.DataFrame,
        goal_features: list,
    ) -> pd.DataFrame:

        total_start = perf_counter()

        # ====================================================
        # 1. Copy input
        # ====================================================

        argus_df = (
            argus_parquet_file
            .copy()
        )

        zeek_df = (
            zeek_parquet_file
            .copy()
        )

        print()
        print("========================================")
        print("UNSW-NB15 TRANSFORM")
        print("========================================")

        print(
            f"Initial Argus rows: {len(argus_df):,}"
        )

        print(
            f"Initial Zeek rows:  {len(zeek_df):,}"
        )

        # ====================================================
        # 2. Required columns
        # ====================================================

        argus_required = [
            "SrcAddr",
            "DstAddr",
            "Sport",
            "Dport",
            "Proto",
        ]

        zeek_required = [
            "conn_id.orig_h",
            "conn_id.resp_h",
            "conn_id.orig_p",
            "conn_id.resp_p",
            "conn_proto",
        ]

        missing_argus = [
            column
            for column in argus_required
            if column not in argus_df.columns
        ]

        missing_zeek = [
            column
            for column in zeek_required
            if column not in zeek_df.columns
        ]

        if missing_argus:

            raise ValueError(
                "Missing Argus columns: "
                f"{missing_argus}"
            )

        if missing_zeek:

            raise ValueError(
                "Missing Zeek columns: "
                f"{missing_zeek}"
            )

        # ====================================================
        # 3. Preserve original Argus service
        # ====================================================

        argus_df["Argus_Service"] = (
            argus_df["Dport"]
        )

        # ====================================================
        # 4. Normalize Argus
        # ====================================================

        stage_start = perf_counter()

        argus_df = self.normalize_argus(
            argus_df
        )

        argus_df["Argus_Service"] = (
            argus_df["Argus_Service"]
            .apply(self.normalize_service)
        )

        print(
            f"Argus normalization: "
            f"{perf_counter() - stage_start:.3f}s"
        )

        # ====================================================
        # 5. Prepare Zeek
        # ====================================================

        stage_start = perf_counter()

        # ----------------------------------------------------
        # IPs
        # ----------------------------------------------------

        zeek_orig_h = (
            self.normalize_ip_series(
                zeek_df["conn_id.orig_h"]
            )
        )

        zeek_resp_h = (
            self.normalize_ip_series(
                zeek_df["conn_id.resp_h"]
            )
        )

        # ----------------------------------------------------
        # Zeek ports are numeric.
        #
        # Therefore do NOT use normalize_port(). This avoids
        # hundreds of thousands of Python function calls.
        # ----------------------------------------------------

        zeek_orig_p_numeric = pd.to_numeric(
            zeek_df["conn_id.orig_p"],
            errors="coerce",
        )

        zeek_resp_p_numeric = pd.to_numeric(
            zeek_df["conn_id.resp_p"],
            errors="coerce",
        )

        zeek_orig_p = (
            zeek_orig_p_numeric
            .astype("Int64")
            .astype("string")
        )

        zeek_resp_p = (
            zeek_resp_p_numeric
            .astype("Int64")
            .astype("string")
        )

        # ----------------------------------------------------
        # Protocol
        # ----------------------------------------------------

        zeek_proto = (
            self.normalize_protocol_series(
                zeek_df["conn_proto"]
            )
        )

        # ----------------------------------------------------
        # Zeek features
        # ----------------------------------------------------

        if (
            "http_trans_depth"
            in zeek_df.columns
        ):

            zeek_trans_depth = pd.to_numeric(
                zeek_df[
                    "http_trans_depth"
                ],
                errors="coerce",
            )

        else:

            zeek_trans_depth = pd.Series(
                np.nan,
                index=zeek_df.index,
                dtype="float64",
            )

        if (
            "http_response_body_len"
            in zeek_df.columns
        ):

            zeek_body_len = pd.to_numeric(
                zeek_df[
                    "http_response_body_len"
                ],
                errors="coerce",
            )

        else:

            zeek_body_len = pd.Series(
                np.nan,
                index=zeek_df.index,
                dtype="float64",
            )

        print(
            f"Zeek preparation: "
            f"{perf_counter() - stage_start:.3f}s"
        )

        # ====================================================
        # 6. Flow keys
        # ====================================================

        stage_start = perf_counter()

        # ----------------------------------------------------
        # Argus
        # ----------------------------------------------------

        argus_df["_flow_key"] = (
            self.create_flow_keys_vectorized(
                argus_df["SrcAddr"],
                argus_df["Sport"],
                argus_df["DstAddr"],
                argus_df["Dport"],
                argus_df["Proto"],
            )
        )

        # ----------------------------------------------------
        # Zeek
        # ----------------------------------------------------

        zeek_flow_keys = (
            self.create_flow_keys_vectorized(
                zeek_orig_h,
                zeek_orig_p,
                zeek_resp_h,
                zeek_resp_p,
                zeek_proto,
            )
        )

        print(
            f"Flow-key creation: "
            f"{perf_counter() - stage_start:.3f}s"
        )

        # ====================================================
        # 7. Minimal Zeek dataframe
        # ====================================================

        stage_start = perf_counter()

        zeek_features = pd.DataFrame(
            {
                "_flow_key":
                    zeek_flow_keys,

                "http_trans_depth":
                    zeek_trans_depth,

                "http_response_body_len":
                    zeek_body_len,
            }
        )

        # ====================================================
        # 8. Flow-key diagnostics
        # ====================================================

        print()
        print("Flow-key diagnostics")
        print("--------------------")

        argus_unique_keys = (
            argus_df["_flow_key"]
            .nunique()
        )

        zeek_unique_keys = (
            zeek_features["_flow_key"]
            .nunique()
        )

        matching_mask = (
            argus_df["_flow_key"]
            .isin(
                zeek_features["_flow_key"]
            )
        )

        print(
            f"Argus rows:          "
            f"{len(argus_df):,}"
        )

        print(
            f"Argus unique keys:   "
            f"{argus_unique_keys:,}"
        )

        print(
            f"Zeek rows:            "
            f"{len(zeek_features):,}"
        )

        print(
            f"Zeek unique keys:     "
            f"{zeek_unique_keys:,}"
        )

        print(
            f"Matching Argus rows: "
            f"{matching_mask.sum():,}"
        )

        print(
            f"Unmatched Argus rows: "
            f"{(~matching_mask).sum():,}"
        )

        print(
            f"Match rate:           "
            f"{matching_mask.mean() * 100:.2f}%"
        )

        # ====================================================
        # 9. Multiple Zeek matches
        # ====================================================

        zeek_match_counts = (
            zeek_features
            .groupby(
                "_flow_key",
                sort=False,
                dropna=False,
            )
            .size()
        )

        multiple_zeek_matches = (
            zeek_match_counts > 1
        ).sum()

        print(
            f"Flow keys with multiple "
            f"Zeek matches:        "
            f"{multiple_zeek_matches:,}"
        )

        # ====================================================
        # 10. Aggregate Zeek
        # ====================================================

        stage_start = perf_counter()

        zeek_features = (
            zeek_features
            .groupby(
                "_flow_key",
                sort=False,
                dropna=False,
            )[
                [
                    "http_trans_depth",
                    "http_response_body_len",
                ]
            ]
            .mean()
            .reset_index()
        )

        zeek_features.rename(
            columns={
                "http_trans_depth":
                    "trans_depth",

                "http_response_body_len":
                    "res_bdy_len",
            },
            inplace=True,
        )

        print(
            f"Zeek aggregation: "
            f"{perf_counter() - stage_start:.3f}s"
        )

        # ====================================================
        # 11. LEFT JOIN
        # ====================================================

        stage_start = perf_counter()

        rows_before_merge = len(
            argus_df
        )

        merged = pd.merge(
            argus_df,
            zeek_features,
            on="_flow_key",
            how="left",
            sort=False,
            validate="many_to_one",
        )

        rows_after_merge = len(
            merged
        )

        print()
        print("After Argus <- Zeek matching")
        print("----------------------------")

        print(
            f"Argus rows before merge: "
            f"{rows_before_merge:,}"
        )

        print(
            f"Rows after merge:        "
            f"{rows_after_merge:,}"
        )

        if rows_after_merge != rows_before_merge:

            raise RuntimeError(
                "ERROR: Argus row count changed "
                "during the left merge."
            )

        print(
            f"Merge: "
            f"{perf_counter() - stage_start:.3f}s"
        )

        # ====================================================
        # 12. Zeek feature statistics
        # ====================================================

        print()
        print("Zeek feature statistics")
        print("-----------------------")

        print(
            "trans_depth non-null:",
            merged[
                "trans_depth"
            ].notna().sum(),
        )

        print(
            "res_bdy_len non-null:",
            merged[
                "res_bdy_len"
            ].notna().sum(),
        )

        # ====================================================
        # 13. Rename Argus columns
        # ====================================================

        merged.rename(
            columns={

                # ------------------------------
                # Basic flow
                # ------------------------------

                "SrcAddr": "srcip",
                "Sport": "sport",
                "DstAddr": "dstip",
                "Dport": "dsport",
                "Proto": "proto",

                # ------------------------------
                # State / duration
                # ------------------------------

                "State": "state",
                "Dur": "dur",

                # ------------------------------
                # Bytes
                # ------------------------------

                "SrcBytes": "sbytes",
                "DstBytes": "dbytes",

                # ------------------------------
                # TTL
                # ------------------------------

                "sTtl": "sttl",
                "dTtl": "dttl",

                # ------------------------------
                # Loss
                # ------------------------------

                "SrcLoss": "sloss",
                "DstLoss": "dloss",

                # ------------------------------
                # Service
                # ------------------------------

                "Argus_Service": "service",

                # ------------------------------
                # Load
                # ------------------------------

                "SrcLoad": "sload",
                "DstLoad": "dload",

                # ------------------------------
                # Packets
                # ------------------------------

                "SrcPkts": "spkts",
                "DstPkts": "dpkts",

                # ------------------------------
                # Windows
                # ------------------------------

                "SrcWin": "swin",
                "DstWin": "dwin",

                # ------------------------------
                # TCP base
                # ------------------------------

                "SrcTCPBase": "stcpb",
                "DstTCPBase": "dtcpb",

                # ------------------------------
                # Mean packet size
                # ------------------------------

                "sMeanPktSz": "smeansz",
                "dMeanPktSz": "dmeansz",

                # ------------------------------
                # Jitter
                # ------------------------------

                "SrcJitter": "sjit",
                "DstJitter": "djit",

                # ------------------------------
                # Time
                # ------------------------------

                "StartTime": "stime",
                "LastTime": "ltime",

                # ------------------------------
                # Inter-packet interval
                # ------------------------------

                "SIntPkt": "sintpkt",
                "DIntPkt": "dintpkt",

                # ------------------------------
                # TCP timing
                # ------------------------------

                "TcpRtt": "tcprtt",
                "SynAck": "synack",
                "AckDat": "ackdat",
            },
            inplace=True,
        )

        # ====================================================
        # 14. Normalize final columns
        # ====================================================

        stage_start = perf_counter()

        merged["srcip"] = (
            self.normalize_ip_series(
                merged["srcip"]
            )
        )

        merged["dstip"] = (
            self.normalize_ip_series(
                merged["dstip"]
            )
        )

        # Argus ist klein, daher scalar port normalization.
        merged["sport"] = (
            merged["sport"]
            .apply(self.normalize_port)
        )

        merged["dsport"] = (
            merged["dsport"]
            .apply(self.normalize_port)
        )

        merged["proto"] = (
            self.normalize_protocol_series(
                merged["proto"]
            )
        )

        merged["service"] = (
            merged["service"]
            .apply(self.normalize_service)
        )

        # ====================================================
        # State
        # ====================================================

        if "state" in merged.columns:

            merged["state"] = (
                merged["state"]
                .fillna("")
                .astype(str)
                .str.lower()
            )

        # ====================================================
        # is_sm_ips_ports
        # ====================================================

        merged["is_sm_ips_ports"] = (
            (
                merged["srcip"]
                ==
                merged["dstip"]
            )
            &
            (
                merged["sport"]
                ==
                merged["dsport"]
            )
        ).astype(int)

        print(
            f"Final normalization: "
            f"{perf_counter() - stage_start:.3f}s"
        )

        # ====================================================
        # 15. Sort by ltime
        # ====================================================

        stage_start = perf_counter()

        if "ltime" in merged.columns:

            # ------------------------------------------------
            # Keep your original behavior:
            # sort as string.
            # ------------------------------------------------

            merged["ltime"] = (
                merged["ltime"]
                .astype(str)
            )

            merged.sort_values(
                "ltime",
                kind="stable",
                inplace=True,
            )

            merged.reset_index(
                drop=True,
                inplace=True,
            )

        print(
            f"Sorting: "
            f"{perf_counter() - stage_start:.3f}s"
        )

        # ====================================================
        # 16. Preview
        # ====================================================

        print()
        print("Preview after Argus/Zeek matching")
        print("----------------------------------")

        preview_columns = [

            "_flow_key",

            "srcip",
            "sport",

            "dstip",
            "dsport",

            "proto",
            "service",

            "trans_depth",
            "res_bdy_len",
        ]

        preview_columns = [
            column
            for column in preview_columns
            if column in merged.columns
        ]

        print(
            merged[
                preview_columns
            ]
            .head(20)
            .to_string(
                index=False
            )
        )

        # ====================================================
        # 17. Connection Features 37-47
        # ====================================================

        print()
        print(
            "Calculating connection features 37-47..."
        )

        stage_start = perf_counter()

        merged = (
            calculate_connection_features_efficient(
                merged
            )
        )

        print(
            f"Connection features: "
            f"{perf_counter() - stage_start:.3f}s"
        )

        # ====================================================
        # 18. Final goal features
        # ====================================================

        print()
        print("Selecting goal features")
        print("----------------------")

        missing_features = [
            feature
            for feature in goal_features
            if feature not in merged.columns
        ]

        if missing_features:

            print(
                "Missing features:"
            )

            print(
                missing_features
            )

            for feature in missing_features:

                merged[feature] = np.nan

        # ----------------------------------------------------
        # Exact goal feature order
        # ----------------------------------------------------

        df_reduced = (
            merged[
                goal_features
            ]
            .copy()
        )

        # ====================================================
        # 19. Remove temporary columns
        # ====================================================

        # This does not affect df_reduced, but frees memory
        # if the local merged dataframe is still referenced.

        temporary_columns = [
            "_flow_key",
            "sttl_bin",
            "dttl_bin",
            "state_key",
            "state_ttl_key",
        ]

        for column in temporary_columns:

            if column in merged.columns:

                del merged[column]

        # ====================================================
        # 20. Final diagnostics
        # ====================================================

        total_time = (
            perf_counter()
            - total_start
        )

        print()
        print("========================================")
        print("FINAL RESULT")
        print("========================================")

        print(
            f"Rows:    "
            f"{len(df_reduced):,}"
        )

        print(
            f"Columns: "
            f"{len(df_reduced.columns):,}"
        )

        print(
            f"Total runtime: "
            f"{total_time:.3f}s"
        )

        print()
        print("Goal features:")
        print(goal_features)

        print()
        print("Final preview:")

        print(
            df_reduced
            .head(10)
            .to_string(
                index=False
            )
        )

        print()
        print("========================================")
        print("TRANSFORM COMPLETE")
        print("========================================")

        return df_reduced