# ToN_IoT: Zeek
# UNSW_NB15: Zeek (conn, http, ftp)  und  Argus mit Jitter Einstellung
# BoT_IoT: Argus
# CSE-CIC-IDS2018: CICFlowMeter (https://www.unb.ca/cic/datasets/ids-2018.html)

import pandas as pd
from collections.abc import Iterator
from pathlib import Path
from typing import Tuple
from .. import utils
from .interfaces import Tool, Label, DatasetTransform
from ..dataset_transform.BoT_IoT_transform import BoTIoTTransformer
from ..dataset_transform.CSE_CIC_IDS2018_transform import CSECICIDS2018Transformer
from ..dataset_transform.ToN_IoT_transform import ToNIoTTransformer
from ..dataset_transform.UNSW_NB15_transform import UNSWNB15Transformer
from ..label_dataset.BoT_IoT_label import BoTIoTLabel
from ..label_dataset.CSE_CIC_IDS2018_label import CSECICIDS2018Label
from ..label_dataset.ToN_IoT_label import ToNIoTLabel
from ..label_dataset.UNSW_NB15_label import UNSWNB15Label


class Transform:
    def __init__(self,  src_dataset: str,
                 tools: list | str = None,
                 goal_datasets: list | str = None,
                 chunk_size_packets: int = 1_000_000, # 1_000 - 2_000 for argus_old_version -> only half of data is lost else <1_000_000
                 max_size_pcap: int = 1_000_000_000, # max 1GB
                 label_binary = True,
                 do_label = True,
                 data_dir: str | Path = "data") -> None:
        # max_size_pcap: max size pcap without chunking, default 1GB
        if src_dataset is None:
            raise Exception("No src_dataset given!")
        self.src_datasets = src_dataset
        self.data_dir = Path(data_dir).expanduser()
        # tools mode for only converting pcap with tools
        if tools is not None and goal_datasets is None:
            self.tools = self.load_tools(tools if isinstance(tools, list) else [tools])
            self.mode = "tools"
            self.output_path = self.data_dir / "flow" / "tool_convertion" / self.src_datasets
        # dataset mode for converting in goal dataset format
        elif goal_datasets is not None and tools is None:
            self.goal_datasets = goal_datasets if isinstance(goal_datasets, list) else [goal_datasets]
            self.features_dict = self.load_features(self.goal_datasets)
            self.mode = "datasets"
            self.output_path = self.data_dir / "flow" / "dataset_format_convertion" / self.src_datasets
            self.tools = []
        else:
            raise Exception("There has to be tools or goal_datasets given (not both or none)!")
        utils.path_exists(self.output_path)
        self.chunk_size = chunk_size_packets
        self.max_size_pcap = max_size_pcap
        self.label_binary = label_binary
        self.do_label = do_label
        if not self.do_label:
            self.label_binary = False

    def run(self) -> None:
        if self.mode == "tools":
            for tool in self.tools:
                output_path = self.output_path / tool.tool_name
                utils.path_exists(output_path)
                self.process_pcaps(output_path=output_path, tool=tool)
        elif self.mode == "datasets":
            for goal_dataset in self.goal_datasets:
                if goal_dataset == "UNSW_NB15":
                    self.tools.append(self.choose_tool("zeek"))
                tool, transformer = self.choose_tool_transformer_on_dataset(goal_datasets=goal_dataset)
                self.tools.append(tool)
                output_path_dataset = self.output_path / goal_dataset
                utils.path_exists(output_path_dataset)
                self.process_pcaps(output_path=output_path_dataset, goal_dataset=goal_dataset)
                self.transform_with_transformer(
                    transformer=transformer,
                    outputpath=output_path_dataset,
                    goal_dataset=goal_dataset
                )
                self.tools = []
        self.label_and_merge(self.output_path)

    def process_pcaps(self, output_path: Path, tool: Tool = None, goal_dataset: str = None) -> None:
        pcaps = list(self.get_pcaps(src_dataset=self.src_datasets))
        if not pcaps:
            print(f"No pcaps found for dataset {self.src_datasets}")
            raise Exception(f"No pcaps found for dataset {self.src_datasets}")
        for pcap in pcaps:
            output_path_pcap = output_path
            # Split in Unterordner direkt am Speicherort der PCAP
            chunk_dir = pcap.parent / f"{pcap.stem}_chunks_size_{self.chunk_size}"
            if chunk_dir.exists():
                pcaps_to_process = list(chunk_dir.rglob("*.pcap")) # nutze vorhandene pcaps in richtiger größe gesplittet
                print(f"Using given pcap splits for {pcap.stem} from {chunk_dir}")
            else:
                pcaps_to_process = utils.split_pcap(pcap, chunk_dir, chunk_size_packets=self.chunk_size, max_size_pcap=self.max_size_pcap)
            if len(pcaps_to_process) >= 2 and goal_dataset != "UNSW_NB15":  # more than 1 chunk pcaps
                output_path_pcap = output_path / f"{pcap.stem}_chunks"
            for pcap_proc in pcaps_to_process:
                if utils.parquet_exists(pcap_proc, output_path_pcap):
                    print(f"Process Pcaps: Parquet already exists for {pcap.name}, skipping...")
                    continue
                self.run_tool(pcap=pcap_proc, output_path=output_path_pcap, tool=tool, goal_dataset=goal_dataset)

    def run_tool(self, pcap, output_path, tool, goal_dataset) -> None:
        print(f"Processing {pcap.name} in {self.src_datasets} dataset")
        if self.mode == "tools" and tool is not None:
            tool.run(pcap_file=pcap, output_dir=output_path)
        elif self.mode == "datasets":
            print(f"Tool/s is/are {self.tools}")
            for tool in self.tools:
                output_path_copy = output_path
                if goal_dataset == "UNSW_NB15":
                    output_path_copy = output_path / tool.tool_name
                    print(f"Outputpath is {output_path_copy}")
                tool.run(pcap_file=pcap, output_dir=output_path_copy)
        else:
            raise Exception("Mode unknown!")

    def load_tools(self, tools) -> list[Tool]:
        return [self.choose_tool(tool) for tool in tools]

    def choose_tool(self, tool: str) -> Tool:
        if tool == "nprobe":
            raise NotImplementedError("nprobe not implemented yet!")
        if tool == "nexusflowmeter":
            from ..tools.nexusflowmeter import NexusflowmeterTool
            return NexusflowmeterTool()
        if tool == "nfstream":
            from ..tools.NFStream import NFStreamTool
            return NFStreamTool()
        if tool == "cicflowmeter":
            from ..tools.cicflowmeter import CICFlowMeterTool
            return CICFlowMeterTool()
        if tool == "ownprep":
            from ..tools.ownprep import OwnPrepTool
            return OwnPrepTool()
        if tool == "zeek":
            from ..tools.zeek import ZeekTool
            return ZeekTool()
        if tool == "argus":
            from ..tools.argus import ArgusTool
            return ArgusTool()
        raise ValueError(f"Unknown tool: {tool}")

    def load_features(self, goal_datasets) -> dict:
        features_dict = {}
        for dataset in goal_datasets:
            feature_path = (
                Path(__file__).resolve().parents[1]
                / "features"
                / f"{dataset}_features.txt"
            )
            with feature_path.open("r", encoding="utf-8") as feature_file:
                features_dict[dataset] = feature_file.read().splitlines()
        return features_dict

    def get_pcaps(self, src_dataset: str) -> Iterator[Path]:
        base = self.data_dir / "pcap" / src_dataset
        utils.path_exists(base)
        #yield from base.rglob("*.pcap")
        for pcap in base.rglob("*.pcap"):
            # Bereits gesplittete PCAPs nicht als Input behandeln
            if "_chunks_size_" in pcap.parent.name:
                continue
            yield pcap

    def choose_tool_transformer_on_dataset(self, goal_datasets) -> Tuple[Tool, DatasetTransform]:
        if goal_datasets == "ToN_IoT":
            tool = self.choose_tool("zeek")
            transformer = ToNIoTTransformer()
        elif goal_datasets == "BoT_IoT":
            tool = self.choose_tool("argus")
            transformer = BoTIoTTransformer()
        elif goal_datasets == "UNSW_NB15":
            transformer = UNSWNB15Transformer()
            tool = self.choose_tool("argus")
        elif goal_datasets == "CSE_CIC_IDS2018":
            transformer = CSECICIDS2018Transformer()
            tool = self.choose_tool("cicflowmeter")
        else:
            raise Exception("Unknown goal dataset/s given!")
        return tool, transformer

    def transform_with_transformer(self, transformer: DatasetTransform, outputpath: Path, goal_dataset: str) -> None:
        print("Transforming...")
        goal_features = self.features_dict[goal_dataset]

        output_path = outputpath / "transformed"
        utils.path_exists(output_path)

        if goal_dataset == "UNSW_NB15":
            argus_files = {}
            zeek_files = {}

            # Erst alle Dateien sammeln
            for parquet in outputpath.rglob("*.parquet"):
                if "transformed" in parquet.parts:
                    continue

                parent = parquet.parent.name

                if parent == "argus":
                    argus_files[parquet.stem] = parquet

                elif parent == "zeek":
                    zeek_files[parquet.stem] = parquet

                else:
                    continue

            # gemeinsame Dateien suchen
            common_files = set(argus_files.keys()) & set(zeek_files.keys())

            if not common_files:
                raise ValueError("No matching Argus/Zeek parquet files found!")

            print(f"Found {len(common_files)} Argus/Zeek pairs")

            for name in common_files:
                argus_path = argus_files[name]
                zeek_path = zeek_files[name]

                # Argus
                if utils.is_real_parquet(argus_path):
                    argus_df = pd.read_parquet(argus_path)
                else:
                    argus_df = pd.read_csv(argus_path)
                    argus_df.columns = argus_df.columns.str.strip()
                    argus_df.to_parquet(argus_path, index=False)

                # Zeek
                if utils.is_real_parquet(zeek_path):
                    zeek_df = pd.read_parquet(zeek_path)
                else:
                    zeek_df = pd.read_csv(zeek_path)
                    zeek_df.columns = zeek_df.columns.str.strip()
                    zeek_df.to_parquet(zeek_path, index=False)

                print(f"Transforming UNSW_NB15 pair: {name}")
                print(f"Argus: {argus_path.name}")
                print(f"Zeek: {zeek_path.name}")

                df_transformed = transformer.transform(
                    argus_parquet_file=argus_df,
                    zeek_parquet_file=zeek_df,
                    goal_features=goal_features
                )

                if df_transformed is None:
                    raise ValueError(f"Transformation failed for {name}")

                df_transformed.to_parquet(
                    output_path / f"{name}_transformed.parquet",
                    index=False
                )
                del argus_df
                del zeek_df
                del df_transformed

            return

        # normale Transformation für alle anderen Datensätze
        for parquet in outputpath.rglob("*.parquet"):
            if "transformed" in parquet.parts:
                continue

            if utils.parquet_exists(parquet, output_path):
                print("Transformed parquet already exists, skipping...")
                continue

            print(f"Transforming {parquet.name} with {transformer}")

            if utils.is_real_parquet(parquet):
                df = pd.read_parquet(parquet)
            else:
                df = pd.read_csv(parquet)
                df.columns = df.columns.str.strip()
                df.to_parquet(parquet, index=False)

            df_transformed = transformer.transform(
                parquet_file=df,
                goal_features=goal_features
            )

            if df_transformed is None:
                raise ValueError("Dataset was not transformed!")

            df_transformed.to_parquet(
                output_path / f"{parquet.stem}_transformed.parquet",
                index=False
            )

    def label_and_merge(self, output_path) -> None:
        print("Merging and Labelling...")
        if self.do_label:
            if self.src_datasets == "ToN_IoT":
                labeler = ToNIoTLabel()
            elif self.src_datasets == "BoT_IoT":
                labeler = BoTIoTLabel()
            elif self.src_datasets == "UNSW_NB15":
                labeler = UNSWNB15Label()
            elif self.src_datasets == "CSE_CIC_IDS2018":
                labeler = CSECICIDS2018Label()
            else:
                raise Exception("Unknown dataset/s given!")
        else:
            labeler = None
        if self.mode == "tools":
            for tool in self.tools:
                self.iterate_label_merge(output_path / tool.tool_name, labeler)
        elif self.mode == "datasets":
            for dataset in self.goal_datasets:
                self.iterate_label_merge(self.output_path / dataset / "transformed", labeler)
                #self.iterate_label_merge(self.output_path / dataset, labeler)
        else:
            raise Exception("Unknown mode given!")

    def iterate_label_merge_old(self, data_dir: Path, labeler: Label | None) -> None:
        utils.path_exists(data_dir)
        if self.do_label:
            if self.label_binary:
                extension = "binary"
            else:
                extension = "multiclass"
            merged_path = data_dir / "merged" / extension
        else:
            merged_path = data_dir / "merged" / "no_label"

        utils.path_exists(merged_path)
        output_file = merged_path / "merged.parquet"
        if output_file.exists():
            output_file.unlink()
        dfs = []
        dfs_sample = []
        print(f"Search directory: {data_dir.resolve()}")
        for parquet in data_dir.rglob("*.parquet"):
            print(f"parquet found: {parquet.name}")
            if parquet.name == "merged.parquet" or parquet.name =="merged_preview.parquet":
                continue
            print(f"Processing {parquet.name}")
            try:
                if utils.is_real_parquet(parquet):
                    df_parquet = pd.read_parquet(parquet)
                else:
                    df_parquet = pd.read_csv(parquet, low_memory=False, on_bad_lines="warn")
                    df_parquet.columns = df_parquet.columns.str.strip()
                    df_parquet.to_parquet(parquet, index=False)
                if self.do_label:
                    df_parquet = labeler.labelling(df=df_parquet, name=parquet.name, label_binary=self.label_binary)
                    #print(df_parquet.head())
                # Vorschau Datei von jeden Label 50 Zeilen order allgemein 50 Zeilen
                if self.do_label:
                    for label, group in df_parquet.groupby("label"):
                        n = min(len(group), 50)
                        dfs_sample.append(group.sample(n=n, random_state=42))
                else:
                    n = min(len(df_parquet), 50)
                    dfs_sample.append(df_parquet.sample(n=n, random_state=42))
                dfs.append(df_parquet)
                #sample_df.to_csv(merged_path / "merged_preview.csv", index=False)
                #df_parquet.to_parquet(output_file, index=False)
            except Exception as e:
                print(f"Skipping {parquet.name} due to error: {e}")
        if not dfs:
            raise ValueError(f"No parquet files found in {data_dir}!")
        merged_df = pd.concat(dfs, ignore_index=True)
        merged_df.columns.to_series().to_csv(merged_path / "columns", index=False, header=False)
        if self.do_label:
            print(f"Label of merged dataset is {merged_df["label"].unique()}")

        if "Dport" in merged_df.columns:
            merged_df["Dport"] = (
                pd.to_numeric(merged_df["Dport"], errors="coerce")
                .astype("Int64")
            )
        if "Sport" in merged_df.columns:
            merged_df["Sport"] = merged_df["Sport"].astype("string")
        merged_df.to_parquet(output_file, index=False)
        merged_preview_df = pd.concat(dfs_sample).reset_index(drop=True)
        if "Dport" in merged_preview_df.columns:
            merged_preview_df["Dport"] = (
                pd.to_numeric(merged_preview_df["Dport"], errors="coerce")
                .astype("Int64")
            )
        if "Sport" in merged_preview_df.columns:
            merged_preview_df["Sport"] = merged_preview_df["Sport"].astype("string")
        if self.do_label:
            print(f"Label of merged preview dataset is {merged_preview_df["label"].unique()}")
        merged_preview_df.to_parquet(merged_path / "merged_preview.parquet", index=False)

    def iterate_label_merge( self,data_dir: Path,labeler: Label | None) -> None:
        import pandas as pd
        import pyarrow as pa
        import pyarrow.parquet as pq

        utils.path_exists(data_dir)

        # --------------------------------------------------------------
        # 1. Ausgabeordner und Dateipfade
        # --------------------------------------------------------------
        if self.do_label:
            extension = "binary" if self.label_binary else "multiclass"
            merged_path = data_dir / "merged" / extension
        else:
            merged_path = data_dir / "merged" / "no_label"

        utils.path_exists(merged_path)

        output_file = merged_path / "merged.parquet"
        preview_file = merged_path / "merged_preview.parquet"

        for path in (output_file, preview_file):
            if path.exists():
                path.unlink()

        print(f"Search directory: {data_dir.resolve()}")

        # Eingabedateien einmal festlegen und für beide Durchläufe verwenden
        input_files = sorted(
            path
            for path in data_dir.rglob("*.parquet")
            if path.name not in {
                "merged.parquet",
                "merged_preview.parquet",
            }
        )

        if not input_files:
            raise ValueError(
                f"No parquet files found in {data_dir}!"
            )

        if self.do_label and labeler is None:
            raise ValueError(
                "self.do_label=True, aber labeler ist None."
            )

        # --------------------------------------------------------------
        # 2. Gemeinsame Funktion zur Vorbereitung jeder Eingabedatei
        # --------------------------------------------------------------
        string_fallback_columns = set()
        def load_and_prepare(parquet: Path) -> pd.DataFrame:
            if utils.is_real_parquet(parquet):
                df = pd.read_parquet(parquet)
            else:
                df = pd.read_csv(
                    parquet,
                    low_memory=False,
                    on_bad_lines="warn",
                )

                df.columns = df.columns.str.strip()

                # CSV mit der bestehenden Dateiendung in Parquet umwandeln,
                # wie in der ursprünglichen Implementierung.
                df.to_parquet(parquet, index=False)

            # Labels erzeugen
            if self.do_label:
                df = labeler.labelling(
                    df=df,
                    name=parquet.name,
                    label_binary=self.label_binary,
                )

                if "label" not in df.columns:
                    raise ValueError(
                        f"Keine 'label'-Spalte in {parquet.name}"
                    )

                # Für alle Dateien denselben Typ für Label erzwingen
                df["label"] = (
                    df["label"]
                    .astype("string")
                    .str.strip()
                )

            # Bestehende Typnormalisierung beibehalten
            if "Dport" in df.columns:
                df["Dport"] = (
                    pd.to_numeric(
                        df["Dport"],
                        errors="coerce",
                    ).astype("Int64")
                )

            if "Sport" in df.columns:
                df["Sport"] = df["Sport"].astype("string")

            # Sonderfall Inode bei Argus
            if "Inode" in df.columns:
                df["Inode"] = df["Inode"].astype("string")
            # Fingerprints sind Identifikatoren, keine numerischen Messwerte
            for col in string_fallback_columns:
                if col in df.columns:
                    df[col] = df[col].astype("string")
            return df

        # --------------------------------------------------------------
        # 3. ERSTER DURCHLAUF: Schema aller Dateien erfassen
        # --------------------------------------------------------------
        schemas = []

        print("\n========== SCHEMA SCAN ==========")

        for index, parquet in enumerate(input_files, start=1):
            print(
                f"[Schema {index}/{len(input_files)}] "
                f"{parquet.name}"
            )

            try:
                df = load_and_prepare(parquet)

                table = pa.Table.from_pandas(
                    df,
                    preserve_index=False,
                )

                # pandas-Metadaten nicht aus der ersten Datei übernehmen.
                # Die Feldtypen und Spalten werden separat vereinheitlicht.
                schemas.append(table.schema.remove_metadata())

                if self.do_label:
                    print(
                        "  Klassen:",
                        df["label"].nunique(dropna=True),
                    )
                del table
                del df

            except Exception as exc:
                raise RuntimeError(
                    f"Fehler beim Schema-Scan von {parquet.name}"
                ) from exc

        # Ein gemeinsames Schema aus ALLEN Eingabedateien erzeugen.
        # Beispiel: int64 + double -> double.
        try:
            # --------------------------------------------------------------
            # Gemeinsames Schema mit Sonderregel für String vs. Double
            # --------------------------------------------------------------
            all_column_names = list(dict.fromkeys( name for schema in schemas for name in schema.names) )
            output_fields = []
            for col in all_column_names:
                col_fields = [
                    schema.field(col)
                    for schema in schemas
                    if col in schema.names
                ]
                field_types = [
                    field.type
                    for field in col_fields
                ]
                has_string = any( pa.types.is_string(t) or pa.types.is_large_string(t) for t in field_types)
                has_double = any( t == pa.float64()for t in field_types)
                # Sonderregel: String und Double -> large_string
                if has_string and has_double:
                    string_fallback_columns.add(col)
                    output_fields.append(
                        pa.field( col, pa.large_string(), nullable=True,) )
                    print(
                        f"[STRING FALLBACK] Spalte '{col}': "
                        f"{sorted(set(str(t) for t in field_types))} "
                        "-> large_string"
                    )
                    continue
                # Alle anderen Typen regulär vereinheitlichen
                single_column_schemas = [pa.schema([pa.field( col,field.type, nullable=True,)]) for field in col_fields]
                try:
                    unified = pa.unify_schemas(single_column_schemas,promote_options="permissive",)
                    output_fields.append(pa.field( col, unified.field(0).type,nullable=True,))
                except (pa.ArrowTypeError, pa.ArrowInvalid) as exc:
                    types_found = sorted({
                        str(field.type)
                        for field in col_fields
                    })
                    raise ValueError(
                        f"Nicht unterstützter Schema-Konflikt "
                        f"in Spalte '{col}': {types_found}"
                    ) from exc
            output_schema = pa.schema(output_fields)

            print("\n========== COMMON SCHEMA ==========")
            print(output_schema)

            print("\nAls String gespeicherte Konfliktspalten:",
                sorted(string_fallback_columns))

        except Exception as e:
            print(f"Fehler: {e}")

        # Besonders nützlich, um die Typen numerischer Features zu prüfen
        print("\nGemeinsame Spaltentypen:")
        for field in output_schema:
            print(f"  {field.name}: {field.type}")

        # --------------------------------------------------------------
        # 4. ZWEITER DURCHLAUF: Dateien mit gemeinsamem Schema schreiben
        # --------------------------------------------------------------
        writer = None
        processed_files = 0
        rows_written = 0
        dfs_sample = []

        labels_before_write = set()

        try:
            writer = pq.ParquetWriter(output_file,output_schema)
            for index, parquet in enumerate(input_files, start=1):
                print(
                    f"\n[Merge {index}/{len(input_files)}] "
                    f"Processing {parquet.name}"
                )
                try:
                    df = load_and_prepare(parquet)
                    if self.do_label:
                        labels_before_write.update(df["label"].dropna().tolist())
                        print(
                            "Labels:",
                            sorted(
                                df["label"]
                                .dropna()
                                .unique()
                                .tolist()
                            ),
                        )

                    # ----------------------------------------------
                    # Preview-Samples vorbereiten
                    # ----------------------------------------------
                    if self.do_label:
                        for _, group in df.groupby("label",dropna=False, ):
                            n = min(len(group), 50)
                            if n > 0:
                                dfs_sample.append(
                                    group.sample( n=n,random_state=42,))
                    else:
                        n = min(len(df), 50)
                        if n > 0:
                            dfs_sample.append(
                                df.sample(n=n, random_state=42))

                    # ----------------------------------------------
                    # DataFrame in Arrow-Tabelle umwandeln
                    # ----------------------------------------------
                    table = pa.Table.from_pandas(df, preserve_index=False)

                    # Spalten ergänzen, die in dieser Datei fehlen
                    # aber zum gemeinsamen Schema gehören.
                    for field in output_schema:
                        if field.name not in table.column_names:
                            table = table.append_column(
                                field.name,
                                pa.nulls(table.num_rows,type=field.type))

                    # Spalten an die Reihenfolge des gemeinsamen
                    # Schemas anpassen.
                    table = table.select(output_schema.names)

                    # Auf das gemeinsame Schema casten.
                    # Der sichere Cast verhindert stille Trunkierung,
                    # etwa von 73.428571 nach 73.
                    table = table.cast(output_schema,safe=True,)

                    # Kontrollieren, ob der Cast die Labels verändert hat
                    if self.do_label:
                        labels_df = set(df["label"].dropna().tolist())
                        labels_arrow = set(
                            value
                            for value in table
                            .column("label")
                            .to_pylist()
                            if value is not None
                        )

                        if labels_df != labels_arrow:
                            raise ValueError(
                                f"Labels unterscheiden sich nach dem "
                                f"Casting in {parquet.name}: "
                                f"DataFrame={labels_df}, "
                                f"Arrow={labels_arrow}"
                            )
                    # Tabelle schreiben
                    writer.write_table(table)
                    rows_written += table.num_rows
                    processed_files += 1
                    print(
                        f"Added {parquet.name}: "
                        f"{table.num_rows} rows "
                        f"({processed_files} Dateien verarbeitet)"
                    )
                    del table
                    del df
                except Exception as exc:
                    raise RuntimeError(
                        f"Fehler beim Zusammenführen von {parquet.name}"
                    ) from exc
        finally:
            if writer is not None:
                writer.close()
        if processed_files == 0:
            raise ValueError(
                f"No parquet files processed in {data_dir}!"
            )

        # --------------------------------------------------------------
        # 5. Schema und Spaltenliste speichern
        # --------------------------------------------------------------
        merged_schema = pq.read_schema(output_file)
        pd.Series( merged_schema.names ).to_csv( merged_path / "columns",index=False,header=False,)
        # --------------------------------------------------------------
        # 6. Preview-Datei schreiben
        # --------------------------------------------------------------
        if dfs_sample:
            merged_preview_df = pd.concat( dfs_sample,ignore_index=True)

            if "Dport" in merged_preview_df.columns:
                merged_preview_df["Dport"] = (
                    pd.to_numeric(
                        merged_preview_df["Dport"],
                        errors="coerce",
                    ).astype("Int64")
                )
            if "Sport" in merged_preview_df.columns:
                merged_preview_df["Sport"] = (
                    merged_preview_df["Sport"].astype("string")
                )
            if self.do_label:
                print(
                    "\nLabels in merged preview:",
                    sorted(
                        merged_preview_df["label"]
                        .dropna()
                        .unique()
                        .tolist()
                    ),
                )

            merged_preview_df.to_parquet(preview_file,index=False,)
            del merged_preview_df

        # --------------------------------------------------------------
        # 7. Finale Datei erneut einlesen und überprüfen
        # --------------------------------------------------------------
        parquet_file = pq.ParquetFile(output_file)
        rows_in_output = parquet_file.metadata.num_rows

        print("\n========== MERGE VALIDATION ==========")
        print(f"Processed files: {processed_files}")
        print(f"Rows written: {rows_written}")
        print(f"Rows in merged.parquet: {rows_in_output}")

        if rows_written != rows_in_output:
            raise ValueError(
                f"Zeilenanzahl stimmt nicht überein: "
                f"{rows_written} geschrieben, "
                f"{rows_in_output} in merged.parquet."
            )

        if self.do_label:
            labels_in_output = set()

            for batch in parquet_file.iter_batches(columns=["label"],batch_size=250_000):
                labels_in_output.update(
                    value
                    for value in batch.column(0).to_pylist()
                    if value is not None
                )
            missing_labels = (labels_before_write - labels_in_output)
            unexpected_labels = (labels_in_output - labels_before_write)

            print("Labels before writing:", sorted(labels_before_write))
            print("Labels in merged.parquet:",sorted(labels_in_output))
            print("Missing labels:", sorted(missing_labels))
            print("Unexpected labels:", sorted(unexpected_labels))

            if missing_labels or unexpected_labels:
                raise ValueError(
                    "Label-Prüfung fehlgeschlagen. "
                    f"Fehlend: {sorted(missing_labels)}; "
                    f"unerwartet: {sorted(unexpected_labels)}."
                )
        print(f"\nSuccessfully created merged dataset: {output_file}")