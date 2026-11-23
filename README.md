# PCAP Transforming Framework

Python framework for extracting network flows from PCAP files and transforming
them into the feature formats used by ToN-IoT, BoT-IoT, UNSW-NB15, and
CSE-CIC-IDS2018.

## Installation

Python 3.12 or later is required.

```bash
python -m pip install pcap-transformer
```

Install optional Python dependencies for the flow extractor(s) you plan to use:

```bash
python -m pip install "pcap-transformer[all]"
```

Available extras are `nfstream`, `cicflowmeter`, `ownprep`, and
`nexusflowmeter`.

The extractor tools also depend on system programs. Zeek, Argus, `editcap`,
`capinfos`, `tcpdump`, and TShark are not installed by pip. CICFlowMeter must
be installed separately; configure `CICFLOWMETER_BIN` to a compatible wrapper
that accepts a PCAP path and output directory and creates
`<pcap-filename>_Flow.csv` in that directory. Check each tool's own installation
instructions and license. These external tools are generally easiest to run on
Linux or WSL.

To install from a source checkout instead:

```bash
python -m pip install .
```

## Input data

Place captures under a data directory with this layout:

```text
data/
└── pcap/
    └── ToN_IoT/
        ├── capture1.pcap
        └── capture2.pcap
```

The framework writes generated flow files and datasets under `data/flow/`.
Pass a different data root with `data_dir`; paths are relative to the current
working directory unless absolute paths are provided.

## Usage

Transform PCAPs into a target dataset's feature format:

```python
from transforming_framework import Transform

job = Transform(
    src_dataset="ToN_IoT",
    goal_datasets="ToN_IoT",
    data_dir="./data",
)
job.run()
```

Or extract flows with one or more flow tools without applying a target feature
format:

```python
from transforming_framework import Transform

job = Transform(
    src_dataset="ToN_IoT",
    tools=["zeek", "argus"],
    data_dir="./data",
)
job.run()
```

`tools` and `goal_datasets` are mutually exclusive. Supported tools are
`zeek`, `argus`, `cicflowmeter`, `nexusflowmeter`, `ownprep`, and `nfstream`.
Supported target datasets are `ToN_IoT`, `BoT_IoT`, `UNSW_NB15`, and
`CSE_CIC_IDS2018`. Dataset labels are inferred from the source dataset and
capture filenames; use `do_label=False` to skip labeling or
`label_binary=False` for multiclass labels.

Large captures are split as needed. The default split size is 1,000,000
packets; configure it with `chunk_size_packets`. Processed files, merged
Parquet output, and a preview sample are written below `data/flow/`.

## License

This project is released under the MIT License. The checked-in CICFlowMeter
sources and other third-party extractor tools retain their own licenses and
must be used in accordance with those licenses. Third-party source files are
not included in the pip distributions.
