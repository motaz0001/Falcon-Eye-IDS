import pandas as pd
from sklearn.preprocessing import LabelEncoder
import hashlib
import ipaddress
import joblib

data = pd.read_csv("train_set_before.csv")  

label_encoders = {
    'proto':LabelEncoder(),
    'service':LabelEncoder(),
    'conn_state':LabelEncoder(),
    'dns_AA':LabelEncoder(), 
    'dns_RD':LabelEncoder(), 
    'dns_RA':LabelEncoder(), 
    'dns_rejected':LabelEncoder(), 
    'type':LabelEncoder()
    }

def ip_to_int(ip):
    return int(ipaddress.ip_address(ip))

def hash_column(value, num_bins=100):
    return int(hashlib.md5(value.encode('utf-8')).hexdigest(), 16) % num_bins

def preprocess(data, columns, hashing_columns, num_bins=100):
    for col in columns:
        if col in ['src_ip', 'dst_ip']: 
            data[col] = data[col].apply(ip_to_int)
        else:
            data[col] = label_encoders[col].fit_transform(data[col].astype(str))

    for col in hashing_columns:
        data[col] = data[col].apply(lambda x: hash_column(x, num_bins))

    return data

columns_to_process = ['proto', 'service', 'conn_state', 'dns_AA', 'dns_RD', 'dns_RA', 'dns_rejected', 'src_ip', 'dst_ip','type']  

hashing_columns = ['dns_query']  

processed = preprocess(data, columns_to_process, hashing_columns)

output_file_path = 'train_set_after.csv'
data.to_csv(output_file_path, index=False)

label_encoders_file = "label_encoders.pkl"
joblib.dump(label_encoders, label_encoders_file)

