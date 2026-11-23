# PCAP Transformer

`pcap-transformer` is a Python package for extracting network flows from PCAP
files and transforming them into the feature formats used by ToN-IoT, BoT-IoT,
UNSW-NB15, and CSE-CIC-IDS2018 or by using different flow extraction external tools.

## Windows and WSL

Some extractors and their external commands are primarily designed for Linux.
Native Windows support therefore depends on the selected extractor and whether
all required command-line programs are available through `PATH`.
Please use a LIínux OS or WSL for Windows.

For example, `ownprep` uses PyShark and external programs.
## Installation

Python 3.12 or later is required:

```powershell
pip install pcap-transformer
```
or
```powershell
python -m pip install pcap-transformer
```

Install optional Python dependencies for all supported extractors with:

```powershell
python -m pip install "pcap-transformer[all]"
```

You can install only the extras you need: `nfstream`, `cicflowmeter`,
`ownprep`, or `nexusflowmeter`. These extras install Python dependencies,
not the external system programs listed below.

### External tools

Install the system programs required by the extractor you use:

| Extractor | External requirements |
| --- | --- |
| Zeek | Zeek; `capinfos`, `tcpdump`, and `editcap` for PCAP checks/conversion |
| Argus | Argus and `ra`; `file` and `editcap` for PCAPNG conversion |
| CICFlowMeter | A compatible CICFlowMeter wrapper configured with `CICFLOWMETER_BIN` |
| ownprep | TShark, used by PyShark; `capinfos`, `tcpdump`, and `editcap` for PCAP checks/conversion |
| NFStream | System packet-capture libraries as required by NFStream |
| NexusFlowMeter | The `nexusflowmeter` executable from its optional Python extra |

The CICFlowMeter wrapper must accept a PCAP path and an output directory, and
write `<pcap-filename>_Flow.csv` into that directory. Check each external
tool's installation instructions and license. These extractors are generally
easiest to run on Linux or WSL.


## Where to put the PCAP files

The job reads captures from:

```text
<data_dir>/pcap/<src_dataset>/**/*.pcap
```

For example, with `src_dataset="ToN_IoT"` and `data_dir` pointing to the
project's `data` directory, put the input files here:

```text
my_project/
├── run_transform.py
└── data/
    └── pcap/
        └── ToN_IoT/
            ├── capture1.pcap
            └── capture2.pcap
```

The framework creates output below `<data_dir>/flow/`.

**Important:** The default `data_dir="data"` is relative to the process's
current working directory, which is the directory from which you run Python.
It is not automatically relative to the installed package or to your main
script. To always use a `data` directory next to a main script located in the
project root, resolve that path explicitly:

```python
from pathlib import Path
from transforming_framework import Transform

PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data"

job = Transform(
    src_dataset="ToN_IoT",
    goal_datasets="ToN_IoT",
    data_dir=DATA_DIR,
)
job.run()
```

If the main script is inside a subdirectory such as `scripts/`, use
`Path(__file__).resolve().parents[1]` for the project root instead. You can
also pass an absolute path, for example `data_dir=r"D:\datasets\my_project"`.

Run the script from PowerShell, for example:

```powershell
python .\run_transform.py
```

## Transformation modes

Import the public API with:

```python
from transforming_framework import Transform
```

Choose exactly one mode: `tools` or `goal_datasets`. Each can be a string or a
list of strings.

### Extract flows with selected tools

Tool mode extracts flow files without transforming them into a target
dataset's feature format. Selected tools run sequentially:

```python
job = Transform(
    src_dataset="ToN_IoT",
    tools=["zeek", "argus"],
    data_dir=DATA_DIR,
)
job.run()
```

Supported tools are `zeek`, `argus`, `cicflowmeter`, `nexusflowmeter`,
`ownprep`, and `nfstream`.

### Transform to a dataset format

Dataset mode chooses an extractor and transformer automatically:

| `goal_datasets` | Extractor(s) | Target format |
| --- | --- | --- |
| `ToN_IoT` | Zeek | ToN-IoT |
| `BoT_IoT` | Argus | BoT-IoT |
| `UNSW_NB15` | Argus and Zeek | UNSW-NB15 |
| `CSE_CIC_IDS2018` | CICFlowMeter | CSE-CIC-IDS2018 |

Example:

```python
job = Transform(
    src_dataset="ToN_IoT",
    goal_datasets="ToN_IoT",
    data_dir=DATA_DIR,
)
job.run()
```

The source directory name and `src_dataset` value must match exactly.
Dataset feature definitions are included with the package.

## Output locations

In tool mode, flow files and merged results are written under:

```text
<data_dir>/flow/tool_convertion/<src_dataset>/<tool>/
```

In dataset mode, intermediate flow files and transformed outputs are written
under:

```text
<data_dir>/flow/dataset_format_convertion/<src_dataset>/<goal_dataset>/
```

For a ToN-IoT conversion, for example:

```text
data/
└── flow/
    └── dataset_format_convertion/
        └── ToN_IoT/
            └── ToN_IoT/
                ├── capture1.parquet
                └── transformed/
                    ├── capture1_transformed.parquet
                    └── merged/
                        ├── merged.parquet
                        ├── merged_preview.parquet
                        └── columns
```

The directory names `tool_convertion` and `dataset_format_convertion` are
spelled this way in the current output layout.

For UNSW-NB15, intermediate Argus and Zeek files are saved in separate
directories and paired by filename. At least one matching pair is needed for
the transformation.

## Unlabeled output files

The framework does not assign labels or require ground-truth files. It merges
the extracted flows as-is; any existing `label` or `Label` column is excluded
from the merged output. Results are written directly under `merged/`:

* `merged.parquet`: merged flow dataset.
* `merged_preview.parquet`: up to 50 sample rows per input file.
* `columns`: one output column name per line.

| Argument | Default | Description |
| --- | --- | --- |
| `src_dataset` | Required | Source folder under `<data_dir>/pcap/` |
| `tools` | `None` | Tool(s) for extraction-only mode |
| `goal_datasets` | `None` | Target feature format(s) for dataset mode |
| `data_dir` | `"data"` | Root containing `pcap/` and generated `flow/` |
| `chunk_size_packets` | `1_000_000` | Packets per PCAP chunk |
| `max_size_pcap` | `1_000_000_000` | File-size threshold in bytes for splitting |

## Large captures and reruns

Files larger than `max_size_pcap` are split with `editcap` into chunks of up
to `chunk_size_packets`. Chunks are stored next to each original PCAP in a
directory named `<capture>_chunks_size_<chunk_size_packets>/`. Existing chunk
directories are reused.

Existing flow and transformed Parquet files are skipped where possible, so a
run can resume after interruption. Merged files and previews are rebuilt from
the available Parquet files.

For more examples and a step-by-step guide, see
[README_FRAMEWORK.md](https://github.com/EvANaGy02/flow-transformer/blob/main/README_FRAMEWORK.md).

## License

This project is released under the MIT License. Checked-in CICFlowMeter
sources and other third-party tools retain their own licenses. Third-party
source files are not included in the pip distributions.
