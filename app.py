"""
Week 4 - Simple Web App
-------------------------
Paste a URL, click the button, see if it's predicted Phishing or Safe.

Run with: streamlit run app.py
"""

import streamlit as st
import pandas as pd
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
from feature_extractor import extract_features
import shap
import matplotlib.pyplot as plt

# ---------------------------------------------------------
# Load data and train the model once when the app starts
# ---------------------------------------------------------
CSV_FILE = "phishing Dataset.csv"   # <-- change to your actual CSV name if different

@st.cache_resource
def train_model():
    df = pd.read_csv(CSV_FILE)
    X = df.drop("Result", axis=1)
    y = df["Result"].replace(-1, 0)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
    model = XGBClassifier(eval_metric="logloss")
    model.fit(X_train, y_train)
    explainer = shap.TreeExplainer(model)
    return model, list(X.columns), explainer

model, feature_columns, explainer = train_model()

# ---------------------------------------------------------
# Web page layout
# ---------------------------------------------------------
st.title("Phishing URL Detector")
st.write("Paste a URL below to check if it looks like phishing or safe.")

url_input = st.text_input("Enter a URL:", "https://www.google.com")

if st.button("Check URL"):
    # Extract the features this URL has (from feature_extractor.py)
    live_features = extract_features(url_input)

    # Build a row matching the model's expected columns.
    # Any feature not covered by extract_features defaults to 0 (unknown).
    row = {col: live_features.get(col, 0) for col in feature_columns}
    input_df = pd.DataFrame([row])

    prediction = model.predict(input_df)[0]

    if prediction == 0:
        st.error("This URL looks like PHISHING")
    else:
        st.success("This URL looks SAFE")

    st.write("Feature values checked:")
    st.json(live_features)

    st.write("Why this decision was made:")
    shap_values = explainer.shap_values(input_df)[0]
    contrib_df = pd.DataFrame({
        "feature": feature_columns,
        "impact": shap_values
    }).sort_values("impact", key=abs, ascending=False).head(8)

    fig, ax = plt.subplots()
    colors = ["red" if v < 0 else "green" for v in contrib_df["impact"]]
    ax.barh(contrib_df["feature"], contrib_df["impact"], color=colors)
    ax.set_xlabel("Impact on prediction")
    ax.invert_yaxis()
    st.pyplot(fig)
    st.caption("Red bars push toward PHISHING, green bars push toward SAFE.")