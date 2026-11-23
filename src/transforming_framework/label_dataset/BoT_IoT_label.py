import pandas as pd
from pathlib import Path
from ..core.interfaces import Label
from .ToN_IoT_label import attack_list
from .. import utils as ut

# wie pcaps heißen
attack_list = ["UDP_DDoS", "HTTP_DDoS", "TCP_DDoS", "UDP_DoS", "HTTP_DoS", "TCP_DoS",
               "ServiceScan", "OSScan", "data_theft", "Keylogging"]

gt_dict = {
    "UDP_DDoS" : "DDoS_UDP",
    "HTTP_DDoS" : "DDoS_HTTP",
    "TCP_DDoS" : "DDoS_TCP",
    "UDP_DoS" : "DoS_UDP",
    "HTTP_DoS" : "DoS_HTTP",
    "TCP_DoS" : "DoS_TCP",
    "ServiceScan" : "Service_Scan",
    "OSScan" : "OS_Scan",
    "data_theft" : "Data_exfiltration",
    "Keylogging" : "Keylogging"
}



class BoTIoTLabel(Label):
    def labelling(self, df: pd.DataFrame, name: str, label_binary: bool) -> pd.DataFrame:
        df = df.copy()
        columns = ut.get_flow_columns(df)
        src_col = columns["src"]
        dst_col = columns["dst"]
        proto_col = columns["proto"]
        sport_col = columns["sport"]
        dport_col = columns["dport"]
        df = df.dropna(subset=[sport_col, dport_col]) # weil manchmal NaN falls Proto ICMP
        attack_type = next((a for a in attack_list if a in name), None)
        if not attack_type: raise ValueError(f"No suitable label info found for {name}")
        #gt_path = Path("../../data/label_info/BoT_IoT/")
        gt_path = Path(__file__).resolve().parents[2] / "data" / "label_info" / "BoT_IoT"
        csv_gt = next(gt_path.glob(f"{gt_dict[attack_type]}.csv"), None)
        if not csv_gt: raise ValueError(f"No suitable csv found for {name} for labelling")
        df_gt = pd.read_csv(csv_gt, sep=";", low_memory=False)
        #df_gt["stime"] = df_gt["stime"] / 1_000_000
        df_gt = df_gt.dropna(subset=["sport", "dport"])

        # unterschiedliche typen
        df[src_col] = ut.normalize_ip(df[src_col])
        df[dst_col] = ut.normalize_ip(df[dst_col])
        df[sport_col] = ut.normalize_port(df[sport_col])
        df[dport_col] = ut.normalize_port(df[dport_col])
        df[proto_col] = ut.normalize_protocol(df[proto_col])

        df_gt["saddr"] = ut.normalize_ip(df_gt["saddr"])
        df_gt["daddr"] = ut.normalize_ip(df_gt["daddr"])
        df_gt["sport"] = ut.normalize_port(df_gt["sport"])
        df_gt["dport"] = ut.normalize_port(df_gt["dport"])
        df_gt["proto"] = ut.normalize_protocol(df_gt["proto"])

        left_keys = [src_col,dst_col,proto_col,sport_col, dport_col]
        right_keys = ["saddr", "daddr", "proto", "sport", "dport"]
        #print("DF ports:")
        #print(df[["Sport", "Dport"]].head(20).to_string(index=False))

        #print("\nGT ports:")
        #print(df_gt[["sport", "dport"]].head(20).to_string(index=False))

        #print("\nDtypes:")
        #print(df[["Sport", "Dport"]].dtypes)
        #print(df_gt[["sport", "dport"]].dtypes)
        #for left, right in zip(left_keys, right_keys):
        #    matches = df[left].isin(df_gt[right]).sum()
        #    print(f"{left:10} <-> {right:10}: {matches} / {len(df)}")
        #conflicts = (
        #    df_gt.groupby(gt_keys)["subcategory"]
        #    .nunique()
        #)
        df_gt = df_gt.drop_duplicates(subset=right_keys)
        #print("Conflicting labels:", (conflicts > 1).sum())
        df = df.merge(
            df_gt[right_keys + ["subcategory"]],
            left_on = left_keys,
            right_on= right_keys,
            how="inner", # left: nur df ergänzen, inner: nur die zeilen behalten, die in df_gt vorhanden
            validate="many_to_one"
        )
        if label_binary:
            df["label"] = df["subcategory"].map(lambda x: 0 if x == "Normal" else 1)
        else:
            df["label"] = df["subcategory"]
        df = df.drop(["subcategory"], axis=1)
        print(f"Zeilen nach Merge: {len(df)}")
        return df
