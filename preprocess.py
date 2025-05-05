import numpy as np
import pandas as pd
import hashlib
import ipaddress
import joblib

dt_model_file='\model\decision_tree_model.pkl'
dt_model=joblib.load(dt_model_file)

rf_model_file='\model\random_forest_model.pkl'
rf_model=joblib.load(rf_model_file)

encoders_file='\training\label_encoders.pkl'
label_encoders= joblib.load(encoders_file)

training_columns = [
    "src_ip", "src_port", "dst_ip", "dst_port", "proto", "service", "duration",
    "src_bytes", "dst_bytes", "conn_state", "missed_bytes", "src_pkts",
    "src_ip_bytes", "dst_pkts", "dst_ip_bytes", "dns_query", "dns_qclass",
    "dns_qtype", "dns_rcode", "dns_AA", "dns_RD", "dns_RA", "dns_rejected",
    "label", "type"
]

def preprocess(features):
    processed_features = {}

    for key, value in features.items():
        if key in label_encoders: 
            processed_features[key]=int(label_encoders[key].transform([value])[0])
        elif key in ["src_ip", "dst_ip"]:  
            ip_int = int(ipaddress.ip_address(value))
            processed_features[key]=ip_int
        elif key == "dns_query":  
            hashed_value=int(hashlib.md5(value.encode('utf-8')).hexdigest(), 16) % 100
            processed_features[key]=hashed_value
        else:  
            processed_features[key]=value

    return pd.DataFrame([processed_features], columns=training_columns[:-2])

