import pandas as pd
from ..core.interfaces import Label

attack_list = ["injection", "MITM", "backdoor", "DDoS", "DoS", "runsomware", "scanning", "XSS", "password"]

class ToNIoTLabel(Label):
    def labelling(self, df: pd.DataFrame, name:str, label_binary:bool) -> pd.DataFrame:
        df = df.copy()
        attack = next((a for a in attack_list if a in name), None)
        if label_binary:
            label = 1 if attack else 0
        else:
            label = attack if attack else "normal"
        df["label"] = label
        return df