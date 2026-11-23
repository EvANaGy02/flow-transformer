import numpy as np
import pandas as pd
from ..core.interfaces import DatasetTransform


class ToNIoTTransformer(DatasetTransform):
    def transform(self, parquet_file: pd.DataFrame, goal_features: list) -> pd.DataFrame:
        #df = pd.read_parquet(parquet_file, low_memory=False)
        df = parquet_file
        df.rename(columns={
            "conn_ts": "ts",
            "conn_id.orig_h" : "src_ip",
            "conn_id.orig_p" : "src_port",
            "conn_id.resp_h" : "dst_ip",
            "conn_id.resp_p" : "dst_port",
            "conn_proto" : "proto",
            "conn_service" : "service",
            "conn_duration" : "duration",
            "conn_orig_bytes" : "src_bytes",
            "conn_resp_bytes" : "dst_bytes",
            "conn_conn_state" : "conn_state",
            "conn_missed_bytes" : "missed_bytes",
            "conn_orig_pkts" : "src_pkts",
            "conn_resp_pkts" : "dst_pkts",
            "conn_orig_ip_bytes" : "src_ip_bytes",
            "conn_resp_ip_bytes" : "dst_ip_bytes",
            "x509_certificate.subject" : "ssl_subject",
            "x509_certificate.issuer" : "ssl_issuer"
        }, inplace=True)
        df_reduced = df[[col for col in df.columns if col in goal_features]]
        if len(df_reduced.columns) == len(goal_features):
            print("Selbe Länge")
        else:
            print("Ungleich")
            missing_features = set(goal_features) - set(df_reduced.columns)
            #print(missing_features)
            print(f"Adding missing features {missing_features}")
            for feature in missing_features:
                df_reduced[feature] = np.nan
        return df_reduced