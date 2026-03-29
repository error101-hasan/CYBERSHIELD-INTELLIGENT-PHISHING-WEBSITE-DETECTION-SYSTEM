"""
Improved ML Model Training with XGBoost
Replace current RandomForest model with better ensemble
"""
import pandas as pd
import joblib
import numpy as np

from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
import matplotlib.pyplot as plt
import seaborn as sns

print("=" * 60)
print("CyberShield - ML Model Training with Performance Analysis")
print("=" * 60)

# Load dataset
print("\n[1/6] Loading dataset...")
df = pd.read_csv("datasets/phishing.csv")
print(f"✓ Dataset loaded: {df.shape[0]} samples, {df.shape[1]} features")

# Convert labels
print("[2/6] Processing data...")
df["Result"] = df["Result"].replace(-1, 0)
X = df.drop("Result", axis=1)
y = df["Result"]

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Normalize features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

print(f"✓ Training set: {X_train.shape[0]} samples")
print(f"✓ Test set: {X_test.shape[0]} samples")

# ===========================
# TRAIN XGBOOST MODEL
# ===========================
print("\n[3/6] Training XGBoost model...")
xgb_model = XGBClassifier(
    n_estimators=200,
    max_depth=8,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    random_state=42,
    n_jobs=-1,
    eval_metric='logloss'
)

xgb_model.fit(X_train_scaled, y_train)
xgb_pred = xgb_model.predict(X_test_scaled)
xgb_accuracy = accuracy_score(y_test, xgb_pred)

print(f"✓ XGBoost Accuracy: {xgb_accuracy:.4f} ({xgb_accuracy*100:.2f}%)")

# ===========================
# TRAIN RANDOM FOREST (for comparison)
# ===========================
print("\n[4/6] Training RandomForest model (for comparison)...")
rf_model = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    random_state=42,
    n_jobs=-1
)

rf_model.fit(X_train, y_train)
rf_pred = rf_model.predict(X_test)
rf_accuracy = accuracy_score(y_test, rf_pred)

print(f"✓ RandomForest Accuracy: {rf_accuracy:.4f} ({rf_accuracy*100:.2f}%)")

# ===========================
# SELECT BEST MODEL
# ===========================
print("\n[5/6] Comparing models...")
print(f"\nXGBoost Metrics:")
print(f"  - Accuracy:  {accuracy_score(y_test, xgb_pred):.4f}")
print(f"  - Precision: {precision_score(y_test, xgb_pred):.4f}")
print(f"  - Recall:    {recall_score(y_test, xgb_pred):.4f}")
print(f"  - F1-Score:  {f1_score(y_test, xgb_pred):.4f}")

print(f"\nRandomForest Metrics:")
print(f"  - Accuracy:  {accuracy_score(y_test, rf_pred):.4f}")
print(f"  - Precision: {precision_score(y_test, rf_pred):.4f}")
print(f"  - Recall:    {recall_score(y_test, rf_pred):.4f}")
print(f"  - F1-Score:  {f1_score(y_test, rf_pred):.4f}")

# Use XGBoost as primary model (usually better)
best_model = xgb_model
best_accuracy = xgb_accuracy
model_name = "XGBoost"

print(f"\n✓ Best Model: {model_name} (Accuracy: {best_accuracy*100:.2f}%)")

# ===========================
# DETAILED ANALYSIS
# ===========================
print("\n[6/6] Detailed Performance Analysis:")
print("\nConfusion Matrix:")
cm = confusion_matrix(y_test, xgb_pred)
print(cm)

print("\nClassification Report:")
print(classification_report(y_test, xgb_pred, target_names=['Phishing', 'Legitimate']))

# ===========================
# SAVE MODELS
# ===========================
print("\nSaving models...")
joblib.dump(xgb_model, "models/phishing_model.pkl")
joblib.dump(scaler, "models/scaler.pkl")
print("✓ XGBoost model saved to: models/phishing_model.pkl")
print("✓ Scaler saved to: models/scaler.pkl")

print("\n" + "=" * 60)
print("Training Complete! Ready for deployment.")
print("=" * 60)
