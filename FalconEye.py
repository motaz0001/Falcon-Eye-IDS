from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR
from preprocess import preprocess, dt_model, rf_model, label_encoders
import csv
import os
from datetime import date, datetime


parent_file = "logs\\" + str(date.today())
if not os.path.exists(parent_file):
    os.makedirs(parent_file)
alert_file = parent_file + "\\alerts.csv"
traffic_file = parent_file + "\\traffic.csv"
flows = {}
features = {}

port_to_service = {
    80: "http",
    8080: "http",
    20: "ftp",
    21: "ftp",
    53: "dns",
    443: "ssl",
    445: "smb",
    139: "smb",
    135: "dce_rpc",
}


def get_connection_state(packet, flow):
    if TCP in packet:
        flags = packet[TCP].flags
        if flags == 0x02:
            return "S0"
        elif flags == 0x12:
            return "S1"
        elif flags == 0x14:
            return "RSTR"
        elif flags == 0x04:
            if packet[IP].src == flow["ip_src"]:
                return "RSTO"
            elif packet[IP].src == flow["ip_dest"]:
                return "RSTRH"
            return "RSTR"
        elif flags == 0x10:
            return "SF"
        elif flags == 0x18:
            return "SH"
        elif flags == 0x11:
            return "SHR"
        elif flags == 0x09:
            return "S2"
        elif flags == 0x19:
            return "RSTOS0"
        elif flags == 0x00:
            return "OTH"
        elif flags & 0x04 and flags & 0x01:
            return "REJ"
        return "OTH"
    return "OTH"


def get_protocol(packet):
    if TCP in packet:
        return "tcp"
    elif UDP in packet:
        return "udp"
    elif ICMP in packet:
        return "icmp"
    return "-"


def get_service(port):
    return port_to_service.get(port, "-")


def get_payload_size(packet):
    if TCP in packet:
        ip_total_length = packet[IP].len
        ip_header_length = packet[IP].ihl * 4
        tcp_header_length = packet[TCP].dataofs * 4
        return ip_total_length - (ip_header_length + tcp_header_length)
    elif UDP in packet:
        return packet[UDP].len - 8
    return 0


def process_packet(packet):
    dns_query = "-"
    dns_class = "0"
    dns_type = "0"
    response_code = "0"
    authoritative = "-"
    recursion_desired = "-"
    recursion_available = "-"
    dns_rejected = "-"
    if packet.haslayer(DNS):
        if packet[DNS].qd:
            for query in packet[DNS].qd:
                dns_query = query.qname.decode("utf-8") if query.qname else "-"
                dns_class = query.qclass
                dns_type = query.qtype
        if packet[DNS].ancount > 0:
            response_code = packet[DNS].rcode
            if response_code == 5:
                dns_rejected = "T"
            else:
                dns_rejected = "F"
        if hasattr(packet[DNS], "aa"):
            authoritative = "T" if packet[DNS].aa else "F"
        if hasattr(packet[DNS], "rd"):
            recursion_desired = "T" if packet[DNS].rd else "F"
        if hasattr(packet[DNS], "ra"):
            recursion_available = "T" if packet[DNS].ra else "F"
    if IP in packet:
        src_ip = packet[IP].src
        dest_ip = packet[IP].dst
        protocol = get_protocol(packet)
        service = "-"
        if TCP in packet or UDP in packet:
            src_port = packet.sport
            dest_port = packet.dport
            service = get_service(dest_port)
            flow_key = (
                tuple(sorted((src_ip, dest_ip))),
                tuple(sorted((src_port, dest_port))),
                protocol,
            )
            if flow_key not in flows:
                flows[flow_key] = {
                    "ftime": packet.time,
                    "ltime": packet.time,
                    "src_ip": src_ip,
                    "dest_ip": dest_ip,
                    "src_to_dest_pkts": 0,
                    "dest_to_src_pkts": 0,
                    "src_payload_size": 0,
                    "dest_payload_size": 0,
                    "src_payload_bytes": 0,
                    "dest_payload_bytes": 0,
                    "total_src_bytes": 0,
                    "total_dest_bytes": 0,
                    "missing_bytes": 0,
                    "last_src_seq": 0,
                    "last_dest_seq": 0,
                    "state": "OTH",
                }
            flow = flows[flow_key]
            flow["ltime"] = packet.time
            duration = "{:.6g}".format(flow["ltime"] - flow["ftime"])
            total_size = packet[IP].len
            payload_size = get_payload_size(packet)
            if TCP in packet:
                if src_ip == flow["src_ip"]:
                    flow["src_to_dest_pkts"] += 1
                    flow["src_payload_size"] += payload_size
                    flow["total_src_bytes"] += total_size
                elif src_ip == flow["dest_ip"]:
                    flow["dest_to_src_pkts"] += 1
                    flow["dest_payload_size"] += payload_size
                    flow["total_dest_bytes"] += total_size
                flow["state"] = get_connection_state(packet, flow)
            else:
                if src_ip == flow["src_ip"]:
                    flow["src_to_dest_pkts"] += 1
                    flow["src_payload_size"] += payload_size
                elif dest_ip == flow["dest_ip"]:
                    flow["dest_to_src_pkts"] += 1
                    flow["dest_payload_size"] += payload_size
            features = {
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dest_ip,
                "dst_port": dest_port,
                "proto": protocol,
                "service": service,
                "duration": duration,
                "src_bytes": flow["src_payload_size"],
                "dst_bytes": flow["dest_payload_size"],
                "conn_state": flow["state"],
                "missed_bytes": flow["missing_bytes"],
                "src_pkts": flow["src_to_dest_pkts"],
                "src_ip_bytes": flow["total_src_bytes"],
                "dst_pkts": flow["dest_to_src_pkts"],
                "dst_ip_bytes": flow["total_dest_bytes"],
                "dns_query": dns_query,
                "dns_qclass": dns_class,
                "dns_qtype": dns_type,
                "dns_rcode": response_code,
                "dns_AA": authoritative,
                "dns_RD": recursion_desired,
                "dns_RA": recursion_available,
                "dns_rejected": dns_rejected,
            }
            features["time"] = str(datetime.now())[-15:-7]
            processed_features = preprocess(features)
            dt_prediction = dt_model.predict(processed_features)
            rf_prediction = rf_model.predict(processed_features)
            dt_label = int(dt_prediction.flatten()[0])
            dt_type = str(
                label_encoders["type"].inverse_transform(dt_prediction[:, 1])
            ).strip("[']")
            rf_type = str(
                label_encoders["type"].inverse_transform(rf_prediction[:, 1])
            ).strip("[']")
            rf_label = int(rf_prediction.flatten()[0])
            if dt_type != rf_type:
                features["label"] = -1
                features["type"] = dt_type if dt_type != "normal" else rf_type
            else:
                features["label"] = rf_label
                features["type"] = rf_type
            with open(traffic_file, mode="a", newline="") as file:
                writer = csv.DictWriter(file, fieldnames=features.keys())
                if file.tell() == 0:
                    writer.writeheader()
                writer.writerow(features)
            if features["label"] in [1, -1] and features["type"] not in ["normal"]:
                with open(alert_file, mode="a", newline="") as file:
                    writer = csv.DictWriter(file, fieldnames=features.keys())
                    if file.tell() == 0:
                        writer.writeheader()
                    writer.writerow(features)


while True:
    try:
        sniff(prn=process_packet, store=False)
    except Exception as e:
        pass
