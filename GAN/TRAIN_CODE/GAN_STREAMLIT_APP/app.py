import streamlit as st
import xgboost as xgb
import pandas as pd
import numpy as np

# Load the trained model
model = xgb.XGBClassifier()
model.load_model('xgboost_model_reduced.json')

# Define the feature names (must match the features used during training)
features = ['Machine', 'DebugSize', 'DebugRVA', 'MajorImageVersion', 'MajorOSVersion',
            'ExportRVA', 'ExportSize', 'IatVRA', 'MajorLinkerVersion', 'MinorLinkerVersion',
            'NumberOfSections', 'SizeOfStackReserve', 'DllCharacteristics', 'ResourceSize',
            'BitcoinAddresses']

def make_prediction(input_data):
    """
    Make predictions using the loaded XGBoost model.
    input_data: Dictionary or list with feature values
    Returns: Predicted class (0 or 1) and probability
    """
    # Convert input to DataFrame
    if isinstance(input_data, dict):
        input_df = pd.DataFrame([input_data], columns=features)
    elif isinstance(input_data, list):
        input_df = pd.DataFrame([input_data], columns=features)
    else:
        raise ValueError("Input must be a dictionary or list with feature values")

    # Ensure all required features are present
    missing_features = [f for f in features if f not in input_df.columns]
    if missing_features:
        raise ValueError(f"Missing features: {missing_features}")

    # Make prediction
    prediction = model.predict(input_df)[0]
    probability = model.predict_proba(input_df)[0]

    return {
        'predicted_class': int(prediction),
        'probability_class_0': float(probability[0]),
        'probability_class_1': float(probability[1])
    }

# Streamlit app
st.title("Malware Prediction App")
st.write("Enter the feature values to predict if a file is Benign (0) or Malicious (1) using the XGBoost model.")

# Create a form for input
with st.form("prediction_form"):
    st.header("Input Features")
    
    # Create input fields for each feature
    input_data = {}
    col1, col2, col3 = st.columns(3)  # Organize inputs in three columns for better layout
    
    with col1:
        input_data['Machine'] = st.number_input('Machine', min_value=0, value=333, step=1)
        input_data['DebugSize'] = st.number_input('DebugSize', min_value=0, value=0, step=1)
        input_data['DebugRVA'] = st.number_input('DebugRVA', min_value=0, value=0, step=1)
        input_data['MajorImageVersion'] = st.number_input('MajorImageVersion', min_value=0, value=4, step=1)
        input_data['MajorOSVersion'] = st.number_input('MajorOSVersion', min_value=0.0, value=16180.533, format="%.3f")

    with col2:
        input_data['ExportRVA'] = st.number_input('ExportRVA', min_value=0.0, value=0.14, format="%.3f")
        input_data['ExportSize'] = st.number_input('ExportSize', min_value=0.0, value=0.14, format="%.3f")
        input_data['IatVRA'] = st.number_input('IatVRA', min_value=0, value=250, step=1)
        input_data['MajorLinkerVersion'] = st.number_input('MajorLinkerVersion', min_value=0.0, value=6.2, format="%.1f")
        input_data['MinorLinkerVersion'] = st.number_input('MinorLinkerVersion', min_value=0, value=3, step=1)

    with col3:
        input_data['NumberOfSections'] = st.number_input('NumberOfSections', min_value=0, value=3, step=1)
        input_data['SizeOfStackReserve'] = st.number_input('SizeOfStackReserve', min_value=0, value=1048576, step=1)
        input_data['DllCharacteristics'] = st.number_input('DllCharacteristics', min_value=0, value=0, step=1)
        input_data['ResourceSize'] = st.number_input('ResourceSize', min_value=0, value=0, step=1)
        input_data['BitcoinAddresses'] = st.number_input('BitcoinAddresses', min_value=0, value=7, step=1)

    # Submit button
    submitted = st.form_submit_button("Predict")

# Display prediction results
if submitted:
    try:
        result = make_prediction(input_data)
        st.success("Prediction Results:")
        st.write(f"**Predicted Class**: {result['predicted_class']} (0 = Benign, 1 = Malicious)")
        st.write(f"**Probability of Class 0 (Benign)**: {result['probability_class_0']:.4f}")
        st.write(f"**Probability of Class 1 (Malicious)**: {result['probability_class_1']:.4f}")
    except Exception as e:
        st.error(f"Error making prediction: {str(e)}")