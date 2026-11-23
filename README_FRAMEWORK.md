# Detailed Framework Guide

This guide covers how to lay out your project data and run the installed
`pcap-transformer` Python package. For package installation and external tool
requirements, see the main [README](README.md).

## Project and data layout

The `Transform` job reads source captures from:

```text
<data_dir>/pcap/<src_dataset>/**/*.pcap
```

For example:

```text
my_project/
├── main.py
└── data/
    └── pcap/
        └── ToN_IoT/
            ├── normal.pcap
            └── DDoS_attack.pcap
```

Use the source directory name as the `src_dataset` value. The framework finds
PCAP files recursively inside that directory.

### How `data_dir` is resolved

`data_dir` defaults to `"data"`, which is resolved relative to the **current
working directory** (the directory from which you run Python). It is not
automatically resolved relative to the installed package or the main script.
For example, if `main.py` is in the project root and you run it from that
directory, the default points to `my_project/data`. If you run Python from a
different directory, the default points to a different `data` directory.

To make the location independent of the shell's current directory, pass an
explicit path derived from `__file__`:

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

This example assumes `main.py` is in the project root. If it is in
`my_project/scripts/main.py`, use
`Path(__file__).resolve().parents[1] / "data"` instead. An absolute path can
also be passed directly:

```python
job = Transform(
    src_dataset="ToN_IoT",
    goal_datasets="ToN_IoT",
    data_dir=r"D:\datasets\my_project\data",
)
```

The framework creates `<data_dir>/flow/` for its outputs. Keep input captures
under `<data_dir>/pcap/`; do not put PCAPs in the package installation
directory.

## Run a job from a main script

Create `main.py` in your project and use the public package import:

```python
from pathlib import Path
from transforming_framework import Transform


def main():
    project_root = Path(__file__).resolve().parent
    data_dir = project_root / "data"

    job = Transform(
        src_dataset="ToN_IoT",
        goal_datasets="ToN_IoT",
        data_dir=data_dir,
    )
    job.run()


if __name__ == "__main__":
    main()
```

Run it from PowerShell with:

```powershell
python .\main.py
```

The same explicit `data_dir` works if you launch the script from another
working directory.

## Choose a processing mode

Pass exactly one of `tools` and `goal_datasets`.

### Tool conversion

This mode extracts flows using the selected tool(s), but does not transform
them into a target feature format:

```python
job = Transform(
    src_dataset="ToN_IoT",
    tools=["zeek", "argus"],
    data_dir=DATA_DIR,
)
job.run()
```

The supported tool names are `zeek`, `argus`, `cicflowmeter`,
`nexusflowmeter`, `ownprep`, and `nfstream`. A string selects one tool; a list
selects several tools to run sequentially.

For the packet filtering, flow grouping, and feature calculations performed
by `ownprep`, see [README_OWNPREP.md](README_OWNPREP.md).

### Dataset format conversion

The framework selects an extractor and transformer from the target dataset:

| Target format | Extractor(s) | Transformer |
| --- | --- | --- |
| `ToN_IoT` | Zeek | ToN-IoT |
| `BoT_IoT` | Argus | BoT-IoT |
| `UNSW_NB15` | Argus and Zeek | UNSW-NB15 |
| `CSE_CIC_IDS2018` | CICFlowMeter | CSE-CIC-IDS2018 |

Example:

```python
job = Transform(
    src_dataset="UNSW_NB15",
    goal_datasets="UNSW_NB15",
    data_dir=DATA_DIR,
)
job.run()
```

The UNSW-NB15 transformation requires Argus and Zeek Parquet files with the
same filename stem. The framework pairs matching files and requires at least
one matching pair.

## Where outputs are written

The output root is always `<data_dir>/flow/`.

Tool conversion:

```text
<data_dir>/flow/tool_convertion/<src_dataset>/<tool>/
├── <capture>.parquet
└── merged/
    ├── merged.parquet
    ├── merged_preview.parquet
    └── columns
```

Dataset conversion:

```text
<data_dir>/flow/dataset_format_convertion/<src_dataset>/<goal_dataset>/
├── <capture>.parquet           # intermediate extractor output
└── transformed/
    ├── <capture>_transformed.parquet
    └── merged/
        ├── merged.parquet
        ├── merged_preview.parquet
        └── columns
```

For UNSW-NB15, the intermediate files are arranged by extractor:

```text
<data_dir>/flow/dataset_format_convertion/UNSW_NB15/UNSW_NB15/
├── argus/
│   └── <capture>.parquet
├── zeek/
│   └── <capture>.parquet
└── transformed/
    └── ...
```

The path components `tool_convertion` and `dataset_format_convertion` use
these spellings in the current implementation.

## Unlabeled merged files

The framework never assigns labels and does not read or require ground-truth
files. Flows are merged as extracted or transformed. Any existing column
named `label` or `Label` is excluded from the merged dataset.

The merge step creates:

* `merged.parquet`: merged flow dataset.
* `merged_preview.parquet`: up to 50 sample rows per input file.
* `columns`: one output column name per line.

## Large PCAP files and reruns

The job has two PCAP splitting settings:

| Argument | Default | Meaning |
| --- | --- | --- |
| `chunk_size_packets` | `1_000_000` | Maximum packets per chunk |
| `max_size_pcap` | `1_000_000_000` | Split files larger than this many bytes |

When a PCAP exceeds `max_size_pcap`, `editcap` splits it into chunks of up to
`chunk_size_packets`. Chunks are stored next to the original PCAP in a
`<capture>_chunks_size_<chunk_size_packets>/` folder. An existing chunk folder
is reused.

If a flow or transformed Parquet file already exists, that work is skipped
where possible. Merged files and previews are rebuilt from the available
Parquet files when the job runs again.

## Common configuration

```python
Transform(
    src_dataset="BoT_IoT",       # folder below data_dir/pcap/
    goal_datasets="BoT_IoT",     # or use tools="argus", not both
    data_dir="./data",            # project data root
    chunk_size_packets=1_000_000,
    max_size_pcap=1_000_000_000,
)
```

`data_dir`, `chunk_size_packets`, and `max_size_pcap` can be used in either
mode.
