from pathlib import Path
import pandas as pd


class Tool:
    def run(self, pcap_file: Path, output_dir: Path) -> None:
        pass
    tool_name = None

class Label:
    def labelling(self, df: pd.DataFrame, name:str, label_binary: bool) -> pd.DataFrame:
        pass

class DatasetTransform:
    def transform(self, parquet_file: pd.DataFrame, goal_features: list) -> pd.DataFrame:
        pass