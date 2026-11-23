from pathlib import Path

import pandas as pd
from .. import utils as ut
from ..core.interfaces import Label



# 22-1-2015: Normal
# 17-2.2015: attacks
class UNSWNB15Label(Label):
    def labelling(self, df: pd.DataFrame, name:str, label_binary: bool) -> pd.DataFrame:
        df = df.copy()
        gt_path = Path(__file__).resolve().parents[2] / "data" / "label_info" / "UNSW_NB15" / "UNSW_NB15.csv"
        df_gt = pd.read_csv(gt_path,  sep=",", low_memory=False)
        if df_gt.empty: raise ValueError(f"No suitable csv found for {name} for labelling")
        columns = ut.get_flow_columns(df)
        src_col = columns["src"]
        dst_col = columns["dst"]
        proto_col = columns["proto"]
        sport_col = columns["sport"]
        dport_col = columns["dport"]

        # unterschiedliche typen
        df[src_col] = ut.normalize_ip(df[src_col])
        df[dst_col] = ut.normalize_ip(df[dst_col])
        df[sport_col] = ut.normalize_port(df[sport_col])
        df[dport_col] = ut.normalize_port(df[dport_col])
        df[proto_col] = ut.normalize_protocol(df[proto_col])

        df_gt["Source IP"] = ut.normalize_ip(df_gt["Source IP"])
        df_gt["Destination IP"] = ut.normalize_ip(df_gt["Destination IP"])
        df_gt["Source Port"] = ut.normalize_port(df_gt["Source Port"])
        df_gt["Destination Port"] = ut.normalize_port(df_gt["Destination Port"])
        df_gt["Protocol"] = ut.normalize_protocol(df_gt["Protocol"])



        left_keys = [src_col, dst_col, proto_col, sport_col, dport_col]
        right_keys = ["Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port"]
        #for left, right in zip(left_keys, right_keys):
        #    matches = df[left].isin(df_gt[right]).sum()
        #    print(f"{left:10} <-> {right:10}: {matches} / {len(df)}")
        df_gt = df_gt.drop_duplicates(subset=right_keys)

        df = df.merge(
            df_gt[right_keys + ["Attack category"]],
            left_on=left_keys,
            right_on=right_keys,
            how="left",  # left: nur df ergänzen, inner: nur die zeilen behalten, die in df_gt vorhanden
            validate="many_to_one"
        )

        df["Attack category"] = df["Attack category"].fillna("Normal")
        if label_binary:
            df["label"] = df["Attack category"].map(lambda x: 0 if x == "Normal" else 1)
        else:
            df["label"] = df["Attack category"]
        df = df.drop(["Attack category"], axis=1)
        print(f"Zeilen nach Merge: {len(df)}")
        return df