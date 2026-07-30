"""
Week 3 - Model Training & Comparison
--------------------------------------
This script loads the phishing dataset, trains 3 different models,
and compares their accuracy so you can pick the best one.

BEFORE RUNNING: Change the CSV filename below to match your actual
dataset file name.
"""

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score
from xgboost import XGBClassifier

# ---------------------------------------------------------
# STEP 1: Load the dataset
# ---------------------------------------------------------
# CHANGE THIS to your actual CSV file name/path
CSV_FILE = "phishing Dataset.csv"

df = pd.read_csv(CSV_FILE)
print(f"Dataset loaded: {df.shape[0]} rows, {df.shape[1]} columns")

# ---------------------------------------------------------
# STEP 2: Split features (X) and label (y)
# ---------------------------------------------------------
# "Result" is the answer column: -1 = phishing, 1 = legitimate
X = df.drop("Result", axis=1)
y = df["Result"]
y = y.replace(-1,0)

# ---------------------------------------------------------
# STEP 3: Split into training data and testing data
# ---------------------------------------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)
print(f"Training rows: {len(X_train)}, Testing rows: {len(X_test)}")

# ---------------------------------------------------------
# STEP 4: Train and compare 3 models
# ---------------------------------------------------------
models = {
    "Logistic Regression": LogisticRegression(max_iter=1000),
    "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42),
    "XGBoost": XGBClassifier(eval_metric="logloss"),
}

results = []

for name, model in models.items():
    model.fit(X_train, y_train)
    predictions = model.predict(X_test)

    acc = accuracy_score(y_test, predictions)
    prec = precision_score(y_test, predictions)
    rec = recall_score(y_test, predictions)

    results.append({"Model": name, "Accuracy": acc, "Precision": prec, "Recall": rec})

    print(f"\n{name}")
    print(f"  Accuracy:  {acc:.4f}")
    print(f"  Precision: {prec:.4f}")
    print(f"  Recall:    {rec:.4f}")

# ---------------------------------------------------------
# STEP 5: Show final comparison table
# ---------------------------------------------------------
results_df = pd.DataFrame(results)
print("\n\n=== FINAL COMPARISON ===")
print(results_df.to_string(index=False))

best_model = results_df.loc[results_df["Accuracy"].idxmax(), "Model"]
print(f"\nBest performing model: {best_model}")
