"""
One-Class SVM Anomaly Detection Optimizer & Evaluator
-----------------------------------------------------
This script trains a One-Class Support Vector Machine (OCSVM) to detect network anomalies.
It uses the Optuna framework to find the optimal 'nu' hyperparameter by maximizing 
the Area Under the Precision-Recall Curve (AUC-PR) across a combined dataset of 
various attack types (Stealthy, Naive, SSAware). 

After finding the optimal parameter, it retrains the model and evaluates its 
performance, presenting the final metrics in a combined consolidated table 
and plotting the 0-5% FPR performance curve.

Packet_id and epoch time are not used in the script i.e due to filtering the packet id number becomes
meaningless and epoch time would've been useful if we needed to learn the time based features
but for 20 minutes of data its meaning is also limited. So we have not used them in the script.
"""

import os
import pandas as pd
import numpy as np
import optuna
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.svm import OneClassSVM
from sklearn.metrics import roc_auc_score, average_precision_score, roc_curve
from sklearn.pipeline import Pipeline
import warnings

# Suppress sklearn/optuna warnings to keep the console output clean during execution
warnings.filterwarnings('ignore')

# =============================================================================
# 1. Configuration & Pathing
# =============================================================================

# Define the absolute path to the local data directory.
DATA_DIR = r"C:\Users\ali.kamran\OneDrive - VINCI Energies\Desktop\Data\Preprocessed files"  # <-- UPDATE THIS PATH TO YOUR LOCAL DATA DIRECTORY

# =============================================================================
# 2. Data Loading
# =============================================================================
print(f"Loading Excel datasets from: {DATA_DIR} ...")

train_df = pd.read_excel(os.path.join(DATA_DIR, 'benign-preprocessed.xlsx'))
benign_test_df = pd.read_excel(os.path.join(DATA_DIR, 'benign-test-preprocessed.xlsx'))

attacks = {
    'Naive': pd.read_excel(os.path.join(DATA_DIR, 'naive-preprocessed.xlsx')),
    'Stealthy': pd.read_excel(os.path.join(DATA_DIR, 'stealthy-preprocessed.xlsx')),
    'SSAware': pd.read_excel(os.path.join(DATA_DIR, 'ssaware-preprocessed.xlsx'))
}

# =============================================================================
# 3. Feature Engineering & Preprocessing Setup
# =============================================================================

cat_cols = ['stream_key']
num_cols = [c for c in train_df.columns if c.startswith('wnd_')] 

preprocessor = ColumnTransformer(
    transformers=[
        ('num', StandardScaler(), num_cols),
        ('cat', OneHotEncoder(handle_unknown='ignore'), cat_cols)
    ])

# =============================================================================
# 4. Data Preparation for Optimization
# =============================================================================

X_train = train_df[num_cols + cat_cols]

test_all_df = pd.concat([
    benign_test_df, 
    attacks['Stealthy'], 
    attacks['Naive'], 
    attacks['SSAware']
], ignore_index=True)

X_test_all = test_all_df[num_cols + cat_cols]
y_test_all = test_all_df['label'].astype(int)

# =============================================================================
# 5. Optuna Hyperparameter Optimization
# =============================================================================

def objective(trial):
    nu = trial.suggest_float('nu', 0.001, 0.5, log=True)
    
    model = Pipeline([
        ('preprocessor', preprocessor),
        ('ocsvm', OneClassSVM(kernel='rbf', gamma='scale', nu=nu))
    ])
    
    model.fit(X_train)
    scores = -model.decision_function(X_test_all)
    auc_pr = average_precision_score(y_test_all, scores)
    return auc_pr

print("\n--- Starting Optuna Optimization (50 Trials) ---")
optuna.logging.set_verbosity(optuna.logging.WARNING) 

study = optuna.create_study(direction='maximize')
study.optimize(objective, n_trials=50, show_progress_bar=True)

best_nu = study.best_params['nu']
print(f"\nOptimization Complete!")
print(f"Best 'nu' found: {best_nu:.6f}")
print(f"Best Overall AUC-PR during optimization: {study.best_value:.4f}")

# =============================================================================
# 6. Final Model Training & Attack-Specific Evaluation
# =============================================================================

print(f"\n--- Retraining Final Model with Optimal nu = {best_nu:.6f} ---")

final_model = Pipeline([
    ('preprocessor', preprocessor),
    ('ocsvm', OneClassSVM(kernel='rbf', gamma='scale', nu=best_nu))
])
final_model.fit(X_train)

fpr_targets = np.arange(0, 0.0525, 0.0010)

# Dictionary to hold all the results so we can print them in one combined table later
results_data = {}

print("\nEvaluating individual attacks... please wait.")

for attack_name, attack_df in attacks.items():
    
    test_df = pd.concat([benign_test_df, attack_df], ignore_index=True)
    X_test = test_df[num_cols + cat_cols]
    y_test = test_df['label'].astype(int)
    
    scores = -final_model.decision_function(X_test)
    
    auc_roc = roc_auc_score(y_test, scores)
    auc_pr = average_precision_score(y_test, scores)
    fpr, tpr, thresholds = roc_curve(y_test, scores)
    
    # Store TPRs for this specific attack
    attack_tpr_list = []
    for target_fpr in fpr_targets:
        valid_idx = np.where(fpr <= target_fpr)[0]
        if len(valid_idx) > 0:
            best_idx = valid_idx[-1]
            tpr_val = tpr[best_idx]
        else:
            tpr_val = 0.0
        attack_tpr_list.append(tpr_val)
        
    results_data[attack_name] = {
        'auc_roc': auc_roc,
        'auc_pr': auc_pr,
        'tprs': attack_tpr_list
    }

# =============================================================================
# 7. Print Combined Table Output
# =============================================================================

print("\n\n=====================================================================")
print("                      COMBINED ATTACK RESULTS")
print("=====================================================================")
print(f"{'Metrics':<12}| {'Naive':<16} | {'Stealthy':<16} | {'SSAware':<16}")
print("---------------------------------------------------------------------")
print(f"{'AUC-ROC':<12}| {results_data['Naive']['auc_roc']:<16.4f} | {results_data['Stealthy']['auc_roc']:<16.4f} | {results_data['SSAware']['auc_roc']:.4f}")
print(f"{'AUC-PR':<12}| {results_data['Naive']['auc_pr']:<16.4f} | {results_data['Stealthy']['auc_pr']:<16.4f} | {results_data['SSAware']['auc_pr']:.4f}")
print("=====================================================================")
print(f"{'Target FPR':<12}| {'Naive TPR':<16} | {'Stealthy TPR':<16} | {'SSAware TPR':<16}")
print("---------------------------------------------------------------------")

for i, target_fpr in enumerate(fpr_targets):
    fpr_str = f"{target_fpr*100:.2f}%"
    naive_tpr = results_data['Naive']['tprs'][i]
    stealthy_tpr = results_data['Stealthy']['tprs'][i]
    ssaware_tpr = results_data['SSAware']['tprs'][i]
    
    print(f"{fpr_str:<12}| {naive_tpr:<16.4f} | {stealthy_tpr:<16.4f} | {ssaware_tpr:.4f}")

print("=====================================================================\n")
print("Evaluation Complete. Generating graph...")

# =============================================================================
# 8. Generate & Show Graph
# =============================================================================

plt.figure(figsize=(10, 6))

# Convert FPR targets to percentages for the X-axis
fpr_percentages = fpr_targets * 100

# Plot all three lines
plt.plot(fpr_percentages, results_data['Naive']['tprs'], label='Naive', marker='o', linewidth=2)
plt.plot(fpr_percentages, results_data['Stealthy']['tprs'], label='Stealthy', marker='s', linewidth=2)
plt.plot(fpr_percentages, results_data['SSAware']['tprs'], label='SSAware', marker='^', linewidth=2)

# Format the plot
plt.title('True Positive Rate vs False Positive Rate (0% - 5% FPR)', fontsize=14, fontweight='bold')
plt.xlabel('False Positive Rate (%)', fontsize=12)
plt.ylabel('True Positive Rate', fontsize=12)
plt.xlim(-0.1, 5.1)  # Give a little padding on the X-axis
plt.ylim(-0.05, 1.05) # Give a little padding on the Y-axis
plt.grid(True, linestyle='--', alpha=0.7)
plt.legend(title='Attack Type', fontsize=10, title_fontsize=11, loc='lower right')
plt.tight_layout()

# Display the graph
plt.show()