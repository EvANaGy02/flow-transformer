import numpy as np
import pandas as pd
from ..core.interfaces import DatasetTransform


class CSECICIDS2018Transformer(DatasetTransform):
    def transform(self, parquet_file: pd.DataFrame, goal_features: list) -> pd.DataFrame:
        df = parquet_file
        df.rename(columns={
            "Flow Duration" : "fl_dur",
            "Flow Byts/s" : "fl_byt_s",
            "Flow Pkts/s" : "fl_pkt_s",
            "Tot Fwd Pkts" : "tot_fw_pk",
            "Tot Bwd Pkts" : "tot_bw_pk",
            "TotLen Fwd Pkts" : "tot_l_fw_pkt",
            "TotLen Bwd Pkts" : "tot_l_bw_pkt",
            "Fwd Pkt Len Max" : "fw_pkt_l_max",
            "Fwd Pkt Len Min" : "fw_pkt_l_min",
            "Fwd Pkt Len Mean" : "fw_pkt_l_avg",
            "Fwd Pkt Len Std" : "fw_pkt_l_std",
            "Bwd Pkt Len Max": "bw_pkt_l_max",
            "Bwd Pkt Len Min": "bw_pkt_l_min",
            "Bwd Pkt Len Mean": "bw_pkt_l_avg",
            "Bwd Pkt Len Std": "bw_pkt_l_std",
            "Flow IAT Mean" : "fl_iat_avg",
            "Flow IAT Max" : "fl_iat_max",
            "Flow IAT Min" : "fl_iat_min",
            "Flow IAT Std" : "fl_iat_std",
            "Fwd IAT Tot" : "fw_iat_tot",
            "Fwd IAT Std" : "fw_iat_std",
            "Fwd IAT Mean" : "fw_iat_avg",
            "Fwd IAT Max" : "fw_iat_max",
            "Fwd IAT Min" : "fw_iat_min",
            "Bwd IAT Tot": "bw_iat_tot",
            "Bwd IAT Mean": "bw_iat_avg",
            "Bwd IAT Max": "bw_iat_max",
            "Bwd IAT Min": "bw_iat_min",
            "Bwd IAT Std": "bw_iat_std",
            "Fwd PSH Flags" : "fw_psh_flag",
            "Bwd PSH Flags" : "bw_psh_flag",
            "Fwd URG Flags": "fw_urg_flag",
            "Bwd URG Flags": "bw_urg_flag",
            "Fwd Header Len" : "fw_hdr_len",
            "Bwd Header Len" : "bw_hdr_len",
            "Fwd Pkts/s" : "fw_pkt_s",
            "Bwd Pkts/s" : "bw_pkt_s",
            "Pkt Len Mean" : "pkt_len_avg",
            "Pkt Len Var" : "pkt_len_va", # corrected
            "Pkt Len Std" : "pkt_len_std", # adding
            "Pkt Len Min" : "pkt_len_min", # adding
            "Pkt Len Max" : "pkt_len_max", # adding
            "FIN Flag Cnt" : "fin_cnt",
            "RST Flag Cnt" : "rst_cnt",
            "PSH Flag Cnt" : "pst_cnt",
            "ACK Flag Cnt" : "ack_cnt",
            "URG Flag Cnt" : "urg_cnt",
            "ECE Flag Cnt" : "ece_cnt",
            "CWE Flag Count" : "cwe_cnt", # fixed: Count not Cnt
            "SYN Flag Cnt" : "syn_cnt",
            "Fwd Seg Size Avg" : "fw_seg_avg",
            "Bwd Seg Size Avg" : "bw_seg_avg",
            "Fwd Byts/b Avg" : "fw_byt_blk_avg",
            "Bwd Byts/b Avg" : "bw_byt_blk_avg",
            "Fwd Pkts/b Avg": "fw_pkt_blk_avg",
            "Bwd Pkts/b Avg": "bw_pkt_blk_avg",
            "Fwd Blk Rate Avg" : "fw_blk_rate_avg",
            "Bwd Blk Rate Avg" : "bw_blk_rate_avg",
            "Subflow Fwd Pkts" : "subfl_fw_pkt",
            "Subflow Fwd Byts" : "subfl_fw_byt",
            "Subflow Bwd Byts" : "subfl_bw_byt",
            "Subflow Bwd Pkts" : "subfl_bw_pkt",
            "Init Fwd Win Byts" : "fw_win_byt",
            "Init Bwd Win Byts" : "bw_win_byt",
            "Fwd Seg Size Min" : "fw_seg_min",
            "Fwd Act Data Pkts" : "fw_act_pkt",
            "Active Mean" : "atv_avg",
            "Active Max" : "atv_max",
            "Active Min" : "atv_min",
            "Active Std" : "atv_std",
            "Idle Max" : "idl_max",
            "Idle Min" : "idl_min",
            "Idle Std" : "idl_std",
            "Idle Mean" : "idl_avg",
            "Dst IP" : "dst_ip",
            "Protocol" : "protocol",
            "Src IP" : "src_ip",
            "Timestamp" : "timestamp",
            "Src Port" : "src_port",
            "Dst Port" : "dst_port",
            "Down/Up Ratio" : "down_up_ratio",
            "Pkt Size Avg" : "pkt_size_avg"
        }, inplace=True)
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