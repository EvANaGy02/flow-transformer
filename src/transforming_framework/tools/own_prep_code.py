# flows nur TCP/UDP pro Zeitfenster flows betrachtet -> flow können in anderen Zeitfenster wieder auftreten (deshalb
# bei größeren Zeitfenstern insgesamt mehr flows angezeigt, weil doppelt)

# flows nur mit ip und transportprotocol betrachtet oder ICMP oder ARP

# betrachtet flows nur einseitig => hin und zurück getrennte flows es werden auf layer > 4 nur TCP/UDP Packete
# betrachtet -> keine Anzeige von z.B. DNS, HTTP

import pyshark
import pandas as pd
import numpy as np
from collections import Counter, defaultdict
from scipy.stats import kurtosis, skew, mode
from datetime import datetime


def convert_tcp_flags(flag_value):
    flags = {
        "URG": 0x20,
        "ACK": 0x10,
        "PSH": 0x08,
        "RST": 0x04,
        "SYN": 0x02,
        "FIN": 0x01
    }
    flag_counts = []
    tcp_flag = int(flag_value, 16)
    for flag, mask in flags.items():
        if tcp_flag & mask:
            flag_counts.append(flag)
    return flag_counts


# create result := create row in csv file
def createResult(flow_key, packets, results):
    if packets:
        tcp_flags_divided = Counter()
        window_packets = []
        window_times = []
        bi = False
        packets_in = []
        packets_out = []
        for packet in packets:
            length = packet['length']
            if "bidirectional" in packet:
                bi = True
                packets_in.append(length)
            else:
                packets_out.append(length)
            window_packets.append(length)
            window_times.append(packet)
            if flow_key[2] == "TCP" and packet['TCP_flags'] is not None:
                name = convert_tcp_flags(packet["TCP_flags"])
                for value in name:
                    tcp_flags_divided[value] += 1
        #packets size
        all_bytes = np.sum(window_packets)
        all_bytes_out = np.sum(packets_out)
        all_bytes_in = np.sum(packets_in)
        min_size = np.min(window_packets)
        max_size = np.max(window_packets)
        median_size = np.median(window_packets)
        mean_size = np.mean(window_packets)  # Erwartungswert
        mode_size = mode(window_packets)[0]
        var_size = np.var(window_packets)
        standard_deviation = np.std(window_packets)
        kurt = kurtosis(window_packets)
        skewness = skew(np.array(window_packets))
        var_coef = (standard_deviation / mean_size) if mean_size != 0 else np.nan
        # Meta
        window_times.sort(key=lambda pkt: pkt["timestamp"])
        timestamps = [pkt["timestamp"] for pkt in window_times]
        start_time = datetime.fromtimestamp(timestamps[0])
        end_time = datetime.fromtimestamp(timestamps[-1])
        duration = (end_time - start_time).total_seconds()
        #interarrival times
        interarrival_times = np.diff(timestamps) if len(timestamps) > 1 else [0]
        min_interarrival = round(np.min(interarrival_times), 8)
        max_interarrival = round(np.max(interarrival_times), 8)
        median_interarrival = round(np.median(interarrival_times), 6)
        mean_interarrival = round(np.mean(interarrival_times), 6)  # Erwartungswert
        mode_interarrival = round(mode(interarrival_times)[0], 6)
        var_interarrival = round(np.var(interarrival_times), 6)
        standard_deviation_interarrival = round(np.std(interarrival_times), 6)
        kurt_interarrival = round(kurtosis(interarrival_times), 6)
        skewness_interarrival = round(skew(interarrival_times), 6)
        var_coef_interarrival = (
                standard_deviation_interarrival / mean_interarrival) if mean_interarrival != 0 else np.nan
        entry = {
            "FlowKey": flow_key,
            "Src IP": flow_key[0],
            "Dst IP": flow_key[1],
            "Protocol": flow_key[2] if len(flow_key)==5 else flow_key[3],
            "Src Port": flow_key[3] if len(flow_key)==5 else np.nan,
            "Dst Port": flow_key[4] if len(flow_key)==5 else np.nan,
            "Is bidirectional": bi,
            "Start Time": start_time,
            "End Time": end_time,
            "Flow Duration (s)": round(duration, 2),
            "Packet Count": len(window_packets),
            "Packet - Duration Ratio (Packets per second)": len(window_packets)/duration if duration!=0 else len(window_packets),
            "Bytes In and Out": all_bytes,
            "Bytes Out": all_bytes_out,
            "Bytes In": all_bytes_in,
            "Min Packet Size": min_size,
            "Max Packet Size": max_size,
            "Median Packet Size": median_size,
            "Mean Packet Size": round(mean_size, 4),
            "Mode Packet Size": mode_size,
            "Var Packet Size": round(var_size, 4),
            "Standard Deviation Packet Size": round(standard_deviation, 4),
            "Kurtosis Packet Size": round(kurt, 4),
            "Skewness Packet Size": round(skewness, 4),
            "Variance Coefficient Packet Size": round(var_coef, 4),
            # IATs
            "Min Interarrival Time (s)": min_interarrival,
            "Max Interarrival Time (s)": max_interarrival,
            "Median Interarrival Time (s)": median_interarrival,
            "Mean Interarrival Time (s)": mean_interarrival,
            "Mode Interarrival Time (s)": mode_interarrival,
            "Var Interarrival Time (s)": var_interarrival,
            "Standard Deviation Time (s)": standard_deviation_interarrival,
            "Kurtosis Time (s)": kurt_interarrival,
            "Skewness Time (s)": skewness_interarrival,
            "Variance Coefficient Time (s)": round(var_coef_interarrival, 6),
        }
        # TCP flags
        for flag, count in tcp_flags_divided.items():
            entry[f"TCP Flag {flag}"] = count
        results.append(entry)
    return results


def checkPacket(pkt, pkt_time, flow_data):
    if "ICMP" in pkt or "ICMPV6" in pkt or "ICMPV4" in pkt:
        #flow_key = "ICMP"
        #flow_data['noflow'].append({
        #    "length": int(pkt.length),
        #    "timestamp": pkt_time,
        #})
        pass
    elif "ARP" in pkt:
        #flow_key = "ARP"
        #flow_data['noflow'].append({
         #   "length": int(pkt.length),
         #   "timestamp": pkt_time
        #})
        pass
    elif (hasattr(pkt, "ip") or hasattr(pkt, "IPV6")) and hasattr(pkt, "transport_layer"):
        if hasattr(pkt, "ip"):
            ipvalue = pkt.ip # ipv4
        else:
            ipvalue = pkt.ipv6
        if "TCP" in pkt:
            flow_key = (ipvalue.src, ipvalue.dst, "TCP", int(pkt.tcp.srcport), int(pkt.tcp.dstport))
            flow_key_bi = (ipvalue.dst, ipvalue.src, "TCP", int(pkt.tcp.dstport), int(pkt.tcp.srcport))
            if flow_key_bi in flow_data:
                flow_data[flow_key_bi].append({
                "length": int(pkt.length),
                "timestamp": pkt_time,
                "TCP_flags": pkt.tcp.flags if hasattr(pkt.tcp, "flags") else None,
                "bidirectional": True
                })
            else:
                flow_data[flow_key].append({
                    "length": int(pkt.length),
                    "timestamp": pkt_time,
                    "TCP_flags": pkt.tcp.flags if hasattr(pkt.tcp, "flags") else None,
                })
        elif "UDP" in pkt:
            flow_key = (ipvalue.src, ipvalue.dst, "UDP", int(pkt.udp.srcport), int(pkt.udp.dstport))
            flow_key_bi = (ipvalue.dst, ipvalue.src, "UDP", int(pkt.udp.dstport), int(pkt.udp.srcport))
            if flow_key_bi in flow_data:
                flow_data[flow_key_bi].append({
                    "length": int(pkt.length),
                    "timestamp": pkt_time,
                    "bidirectional": True
                })
            else:
                flow_data[flow_key].append({
                    "length": int(pkt.length),
                    "timestamp": pkt_time,
                })
        else:
            if hasattr(ipvalue, "src") and hasattr(ipvalue, "dst") and hasattr(pkt, "highest_layer"):
                flow_key = (ipvalue.src, ipvalue.dst, "transport unknown", pkt.highest_layer)
                flow_key_bi = (ipvalue.dst, ipvalue.src, "transport unknown", pkt.highest_layer)
                if flow_key_bi in flow_data:
                    flow_data[flow_key_bi].append({
                        "length": int(pkt.length),
                        "timestamp": pkt_time,
                        "bidirectional": True
                    })
                else:
                    flow_data[flow_key].append({
                        "length": int(pkt.length),
                        "timestamp": pkt_time,
                    })
    else:
        #flow_data['noflow'].append({
        #    "length": int(pkt.length),
        #    "timestamp": pkt_time,
        #})
        pass


def goThroughDataset(results, flow_data, cap):
    # PCAP-Datei durchgehen
    packet_count = 0
    try:
        for pkt in cap:
            if hasattr(pkt, "sniff_time"):
                packet_count += 1
                pkt_time = float(pkt.sniff_timestamp)
                # sign packet to flow if possible
                checkPacket(pkt, pkt_time, flow_data)
    except pyshark.capture.capture.TSharkCrashException as e:
        print(
            f"Warning: Ignoring truncated packet. "
            f"Successfully processed {packet_count} packets."
        )
    for flow in flow_data:
        if flow != "noflow":
            createResult(flow, flow_data[flow].copy(), results)

def run(pcap_file, output_path):
    flow_data = defaultdict(list)
    results = []
    cap = pyshark.FileCapture(pcap_file, keep_packets=True, use_json=True)

    try:
        goThroughDataset(results, flow_data, cap)
    finally:
        cap.close()
    df = pd.DataFrame(results)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False, sep=",", encoding="utf-8-sig")