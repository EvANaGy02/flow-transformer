# PCAP Flow Transformation Framework

## Overview

This framework converts network traffic stored as PCAP files into flow-based datasets. It supports two main operation modes:

1. **Tool conversion**
   Converts PCAP files into flow records using a selected network analysis tool (e.g., Zeek, Argus, CICFlowMeter).

2. **Dataset format conversion**
   Converts PCAP files into the feature format of a specific intrusion detection dataset (e.g., UNSW-NB15, BoT-IoT, ToN-IoT, CSE-CIC-IDS2018).
   This mode automatically selects the required flow extraction tool and applies the corresponding feature transformation.

The framework additionally supports:

* PCAP splitting for large files
* Automatic conversion from CSV to Parquet
* Binary or multiclass labeling
* Merging multiple flow files into a single dataset
* Preview generation with sampled flows
* Incremental processing (existing Parquet files are skipped)

---

# Installation

## Requirements

* Python == 3.12
* Virtual environment recommended

Example:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

The external flow extraction tools must also be installed:

* Zeek
* Argus
* CICFlowMeter
* NexusFlowMeter

The tools must be available in the system path or configured inside their corresponding tool classes.

**For further installation guide please refere to the 
README.md file in the same folder!**

---

# Directory Structure

The framework expects the following data structure:

```
project/
│
├── data/
│   ├── pcap/
│   │   └── DATASET_NAME/
│   │       ├── traffic1.pcap
│   │       └── traffic2.pcap
│   │
│   └── flow/
│       ├── tool_convertion/
│       └── dataset_format_convertion/
│
│
└── transforming_framework/
```

---

# How to use the Framework

The framework has two modes:

* **Tool conversion**
* **Dataset format conversion**

The mode is selected by providing either `tools` or `goal_datasets`.

Both parameters cannot be used at the same time.

---

# 1. Tool Conversion Mode

Tool conversion only creates flow files from PCAP files.

Supported tools:

* `zeek`
* `argus`
* `cicflowmeter`
* `nexusflowmeter`
* `ownprep`
* `nfstream`

## Example

Convert ToN-IoT PCAP files using Zeek:

```python
from core.transform import Transform

transformation = Transform(
    src_dataset="ToN_IoT",
    tools="zeek"
)

transformation.run()
```

Output:

```
data/
└── flow/
    └── tool_convertion/
        └── ToN_IoT/
            └── zeek/
                ├── traffic1.parquet
                ├── traffic2.parquet
                └── merged/
                    └── multiclass/
                        └── merged.parquet
```

---

## Multiple Tools

Several tools can be executed sequentially:

```python
transformation = Transform(
    src_dataset="UNSW_NB15",
    tools=[
        "zeek",
        "argus"
    ]
)

transformation.run()
```

---

# 2. Dataset Format Conversion Mode

Dataset conversion transforms PCAP files directly into the feature format of a target dataset.

The framework automatically chooses:

| Dataset         | Flow Tool    | Transformer              |
| --------------- | ------------ | ------------------------ |
| ToN-IoT         | Zeek         | ToNIoTTransformer        |
| BoT-IoT         | Argus        | BoTIoTTransformer        |
| UNSW-NB15       | Argus + Zeek | UNSWNB15Transformer      |
| CSE-CIC-IDS2018 | CICFlowMeter | CSECICIDS2018Transformer |

---

## Example: Convert PCAP to UNSW-NB15 format

```python
from core.transform import Transform

transformation = Transform(
    src_dataset="UNSW_NB15",
    goal_datasets="UNSW_NB15"
)

transformation.run()
```

The framework will:

1. Run Argus on the PCAP files
2. Run Zeek on the same PCAP files
3. Match corresponding Argus and Zeek output files
4. Combine both sources
5. Select UNSW-NB15 features
6. Create transformed Parquet files
7. Label and merge the final dataset

Output:

```
data/
└── flow/
    └── dataset_format_convertion/
        └── UNSW_NB15/
            └── UNSW_NB15/
                ├── argus/
                │   └── traffic.parquet
                │
                ├── zeek/
                │   └── traffic.parquet
                │
                └── transformed/
                    ├── traffic_transformed.parquet
                    └── merged/
                        └── binary/
                            └── merged.parquet
```

---

# PCAP Splitting

Large PCAP files are automatically split before processing.

Default:

```python
chunk_size_packets=1_000_000
```

Example:

```python
transformation = Transform(
    src_dataset="ToN_IoT",
    goal_datasets="ToN_IoT",
    chunk_size_packets=500000
)

transformation.run()
```

A PCAP:

```
large_capture.pcap
```

can become:

```
large_capture_chunks_size_500000/

├── chunk_00000.pcap
├── chunk_00001.pcap
└── chunk_00002.pcap
```

Each chunk is processed separately.

---

# Labeling

By default, generated datasets are labeled binary.

## Binary Labels

```python
transformation = Transform(
    src_dataset="BoT_IoT",
    goal_datasets="BoT_IoT",
    label_binary=True
)

transformation.run()
```

Output:

```
merged/
└── binary/
    └── merged.parquet
```

---

## Multiclass Labels

```python
transformation = Transform(
    src_dataset="BoT_IoT",
    goal_datasets="BoT_IoT",
    label_binary=False
)

transformation.run()
```

Output:

```
merged/
└── multiclass/
    └── merged.parquet
```

---

## Disable Labeling

For unlabeled flow generation:

```python
transformation = Transform(
    src_dataset="ToN_IoT",
    goal_datasets="ToN_IoT",
    do_label=False
)

transformation.run()
```

Output:

```
merged/
└── no_label/
    └── merged.parquet
```

---

# Merge and Preview Generation

After transformation, all Parquet files are merged automatically.

Generated files:

```
merged/
├── merged.parquet
├── merged_preview.parquet
└── columns
```

`merged_preview.parquet` contains:

* up to 50 samples per label (labeling enabled)
* otherwise 50 random samples

This allows quick inspection before loading the complete dataset.

---

# UNSW-NB15 Special Handling

UNSW-NB15 requires two flow sources:

```
UNSW_NB15/
├── argus/
│   └── file_name.parquet
│
└── zeek/
    └── file_name.parquet
```

The framework matches files by filename:

```
argus:
normal_attack1.parquet

zeek:
normal_attack1.parquet
```

Only matching pairs are transformed.

If a corresponding file does not exist in both directories, transformation is skipped.

---

# Incremental Processing

The framework checks existing Parquet files.

Already processed files are skipped:

```
Process Pcaps:
Parquet already exists for traffic.pcap, skipping...
```

This allows interrupted transformations to continue without restarting.

---

# Main Configuration Parameters

| Parameter            | Description                        | Default   |
| -------------------- | ---------------------------------- | --------- |
| `src_dataset`        | Source PCAP dataset name           | required  |
| `tools`              | Flow extraction tools              | None      |
| `goal_datasets`      | Target dataset format              | None      |
| `chunk_size_packets` | Packets per PCAP chunk             | 1,000,000 |
| `max_size_pcap`      | Maximum PCAP size before splitting | 1GB       |
| `label_binary`       | Binary/multiclass labeling         | True      |
| `do_label`           | Enable labeling                    | True      |

---

# Example Complete Script

```python
from core.transform import Transform


if __name__ == "__main__":

    transformation = Transform(
        src_dataset="ToN_IoT",
        goal_datasets="ToN_IoT",
        chunk_size_packets=1_000_000,
        label_binary=True,
        do_label=True
    )

    transformation.run()
```

This will generate a ready-to-use labeled flow dataset in Parquet format.
