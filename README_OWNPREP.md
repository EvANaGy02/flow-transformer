# ownprep: Custom PCAP-to-Flow Processing

This guide describes the framework's built-in `ownprep` extractor: how it
finds PCAPs, validates and reads them, groups packets into flows, calculates
features, and writes the results.

`ownprep` is an extraction-only tool. It creates its own flow features; it is
not the extractor automatically selected by any of the four dataset-format
transformations.

## Installation and prerequisites

Install the package with the optional dependencies used by `ownprep`:

```powershell
python -m pip install "pcap-transformer[ownprep]"
```

The extra installs PyShark and SciPy along with the package's core
dependencies. Install **TShark** separately; PyShark uses it to read packets.
The framework's PCAP validation and repair also uses `capinfos`, `tcpdump`,
and `editcap`, which are normally installed with Wireshark command-line
utilities. Make these programs available on `PATH`. Linux or WSL is generally
the easiest environment for these tools.

## Where to put the PCAP files

The `Transform` job searches recursively for `.pcap` files under:

```text
<data_dir>/pcap/<src_dataset>/
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

Here, use `src_dataset="ToN_IoT"` and set `data_dir` to the `data` folder.
The source directory name must match the value of `src_dataset`.

The default `data_dir="data"` is relative to the **current working
directory**, not to the location of the installed package or `main.py`. To
make the path independent of where you launch Python, calculate it from your
main script:

```python
from pathlib import Path
from transforming_framework import Transform

project_root = Path(__file__).resolve().parent
data_dir = project_root / "data"

job = Transform(
    src_dataset="ToN_IoT",
    tools="ownprep",
    data_dir=data_dir,
)
job.run()
```

This example assumes `main.py` is in the project root. If it is in
`my_project/scripts/main.py`, use
`Path(__file__).resolve().parents[1] / "data"` instead.

## Running ownprep

Use the public package import and select `ownprep` in tool mode:

```python
from pathlib import Path
from transforming_framework import Transform

project_root = Path(__file__).resolve().parent

job = Transform(
    src_dataset="ToN_IoT",
    tools="ownprep",
    data_dir=project_root / "data",
    chunk_size_packets=1_000_000,
    max_size_pcap=1_000_000_000,
)
job.run()
```

Run the main script from PowerShell, for example:

```powershell
python .\main.py
```

You can select multiple extraction tools in a list; they run sequentially:

```python
job = Transform(
    src_dataset="ToN_IoT",
    tools=["ownprep", "zeek"],
    data_dir=project_root / "data",
)
job.run()
```

## Processing steps

For each input PCAP, the framework performs the following:

1. **Finds and splits the capture if needed.** PCAP files larger than
   `max_size_pcap` are split with `editcap` into chunks of up to
   `chunk_size_packets`. Chunks are written next to the original capture in a
   folder named `<capture>_chunks_size_<chunk_size_packets>/`. Existing chunk
   folders are reused.
2. **Validates the PCAP.** `capinfos` checks the file format and `tcpdump`
   checks that it can be read. If validation fails or the file is PCAPNG,
   `editcap -F pcap` is used to create a repaired/converted temporary PCAP.
   If `editcap` fails, processing fails for that capture.
3. **Reads packets with PyShark/TShark.** PyShark reads the capture in JSON
   mode. The capture is closed after processing. If TShark reports a
   truncated packet, the current implementation warns and continues with the
   packets it already processed.
4. **Filters and assigns packets to flows.** IPv4/IPv6 TCP and UDP packets
   are grouped by source IP, destination IP, protocol, source port, and
   destination port. Packets in the reverse direction are added to the
   existing flow when its reverse key is found. Other IP transport packets
   are grouped by IP pair and highest protocol layer, without ports. ICMP,
   ICMPv6, and ARP packets are ignored.
5. **Calculates one feature row per flow key per PCAP chunk.** Packets are
   retained and grouped for the whole capture/chunk; this implementation does
   not split flows by an idle timeout or fixed time window.
6. **Writes a temporary CSV and converts it to Parquet.** The CSV is removed
   after a successful conversion. The final per-capture result is a Parquet
   file.

### Flow direction

The first packet that creates a flow key determines the reported `Src IP`,
`Dst IP`, `Src Port`, and `Dst Port`. Reverse-direction packets that match the
existing flow are marked as bidirectional. Consequently, `Bytes In` and
`Bytes Out` are relative to the first-seen direction, not a client/server
role inferred from the protocol.

Packets from the same five-tuple anywhere in one PCAP chunk are grouped
together, even if a long time passes between them. The same tuple can appear
again in a different PCAP or a different chunk and produce a separate row.

## Calculated features

The custom `ownprep` flow row includes:

* Flow key, source/destination IPs, protocol, and ports (where available).
* Whether reverse-direction packets were seen.
* Start time, end time, duration, packet count, and packets-per-second ratio.
* Total, incoming, and outgoing bytes.
* Minimum, maximum, median, mean, mode, variance, standard deviation,
  kurtosis, skewness, and coefficient of variation for packet sizes.
* Minimum, maximum, median, mean, mode, variance, standard deviation,
  kurtosis, skewness, and coefficient of variation for inter-arrival times.
* Counts of TCP URG, ACK, PSH, RST, SYN, and FIN flags when those flags occur.

Start and end times are created with Python's local system timezone.

The feature names are specific to `ownprep`; they are not automatically
renamed into one of the target dataset schemas. The `ownprep` flow files are
therefore produced using `tools="ownprep"`.

## Output location and unlabeled merging

Per-capture Parquet files are written under:

```text
<data_dir>/flow/tool_convertion/<src_dataset>/ownprep/
```

For the example above:

```text
data/
└── flow/
    └── tool_convertion/
        └── ToN_IoT/
            └── ownprep/
                ├── normal.parquet
                ├── DDoS_attack.parquet
                └── merged/
                    ├── merged.parquet
                    ├── merged_preview.parquet
                    └── columns
```

The framework also merges per-capture Parquet files after tool processing.
Merging does not assign labels and does not require ground-truth files.
Existing `label` or `Label` columns are excluded from the merged dataset.
`merged_preview.parquet` contains up to 50 sample rows per input file, and
`columns` lists the merged output columns.

## Memory and processing considerations

The implementation uses PyShark with `keep_packets=True` and keeps packet
metadata for each flow until the PCAP (or chunk) has been processed. Memory
usage therefore grows with the size of the capture. If memory is limited,
lower `max_size_pcap` to split captures into smaller files. For example:

```python
job = Transform(
    src_dataset="ToN_IoT",
    tools="ownprep",
    data_dir=data_dir,
    max_size_pcap=100_000_000,  # 100 MB
    chunk_size_packets=250_000,
)
job.run()
```

Existing per-capture Parquet outputs are skipped on reruns where the framework
finds a matching output. The merged dataset and preview are rebuilt from the
available Parquet files.
