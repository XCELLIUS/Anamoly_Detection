import streamlit as st
import pandas as pd
import numpy as np
import pickle
import sklearn

# Load the trained model and scaler
with open('C:\\Users\\HP\\PycharmProjects\\hackathon\\network_anomaly_model.pkl', 'rb') as model_file:
    model = pickle.load(model_file)

with open('C:\\Users\\HP\\PycharmProjects\\hackathon\\scaler.pkl', 'rb') as scaler_file:
    scaler = pickle.load(scaler_file)

# Define column names
col_names = ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "wrong_fragment",
             "hot", "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
             "num_file_creations", "num_shells", "num_access_files", "is_guest_login", "count",
             "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
             "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
             "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
             "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
             "dst_host_rerror_rate", "dst_host_srv_rerror_rate"]

# Streamlit app
st.title("Network Anomaly Detection System")

# Feature input
st.sidebar.header("Input Features")
input_data = {}
for col in col_names:
    if col in ['protocol_type', 'service', 'flag']:
        input_data[col] = st.sidebar.selectbox(f"Select {col}", options=['0', '1', '2','3','4','5','6','7','8','9','10'])
    else:
        input_data[col] = st.sidebar.number_input(f"{col}", value=0.0)

# Prediction button
if st.sidebar.button("Predict Anomaly"):
    # Convert input to DataFrame
    input_df = pd.DataFrame([input_data])

    # Scale the input data
    input_scaled = scaler.transform(input_df)

    # Make prediction
    prediction = model.predict(input_scaled)[0]
    result = "Attack" if prediction == 1 else "Normal"

    # Display result
    st.write(f"### Prediction: {result}")
