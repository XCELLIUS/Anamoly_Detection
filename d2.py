import pandas as pd
import pickle
import streamlit as st

# Load the trained model and scaler
with open('network_anomaly_model1.pkl', 'rb') as model_file:
    model = pickle.load(model_file)

with open('scaler1.pkl', 'rb') as scaler_file:
    scaler = pickle.load(scaler_file)

# Define the required feature columns
required_features = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "wrong_fragment", "hot", "logged_in", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "is_host_login", "last_flag"
]

# Streamlit app
st.title("Anomaly Detection in CSV Files")
st.write("Upload a CSV file to detect anomalies in the data.")

# File upload
uploaded_file = st.file_uploader("Upload CSV", type=["csv"])

if uploaded_file:
    # Load the CSV file into a DataFrame
    st.write("### Uploaded CSV File")
    input_data = pd.read_csv(uploaded_file)
    st.write(input_data.head())

    # Check for missing features
    missing_features = [feature for feature in required_features if feature not in input_data.columns]
    if missing_features:
        st.warning(f"The following required features are missing: {missing_features}")
        for feature in missing_features:
            input_data[feature] = 0  # Add missing features with default values

    # Ensure correct column order
    try:
        input_data = input_data[required_features]
    except KeyError as e:
        st.error(f"Error aligning feature columns: {e}")
        st.stop()

    # Scale the features using the pre-trained scaler
    input_scaled = scaler.transform(input_data)

    # Make predictions
    predictions = model.predict(input_scaled)

    # Add predictions to the DataFrame
    input_data['Prediction'] = predictions
    input_data['Prediction'] = input_data['Prediction'].apply(lambda x: 'Anomaly' if x == 1 else 'Normal')

    # Display the results
    st.write("### Results")
    st.write(input_data[['Prediction']])

    # Save the results as a CSV
    result_file = 'anomaly_detection_results.csv'
    input_data.to_csv(result_file, index=False)

    # Provide download button for the results
    st.download_button(
        label="Download Results",
        data=open(result_file, 'rb').read(),
        file_name=result_file,
        mime='text/csv'
    )
