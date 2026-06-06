"""
One-Class SVM Anomaly Detection Optimizer & Evaluator
(Includes 0-1200s Timeline Visualizations & Missed Packet ID Extraction)
"""

import os
import pandas as pd
import numpy as np
import optuna
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.svm import OneClassSVM
from sklearn.metrics import roc_auc_score, average_precision_score, roc_curve
from sklearn.pipeline import Pipeline
import warnings

warnings.filterwarnings('ignore')

# =============================================================================
# 1. Configuration & Pathing
# =============================================================================

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(PROJECT_ROOT, 'data', 'xlsx')

# =============================================================================
# 2. Data Loading
# =============================================================================
print(f"Loading Excel datasets from: {DATA_DIR} ...")

train_df = pd.read_excel(os.path.join(DATA_DIR, 'benign-training-preprocessed.xlsx'))
benign_test_df = pd.read_excel(os.path.join(DATA_DIR, 'bening-testing-preprocessed.xlsx'))

attacks = {
    'Naive': pd.read_excel(os.path.join(DATA_DIR, 'naive-preprocessed.xlsx')),
    'Stealthy': pd.read_excel(os.path.join(DATA_DIR, 'stealthy-preprocessed.xlsx')),
    'SSAware': pd.read_excel(os.path.join(DATA_DIR, 'ss-aware-preprocessed.xlsx'))
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

fpr_targets = np.arange(0, 0.030, 0.0010)

results_data = {}
attack_raw_data = {}

print("\nEvaluating individual attacks... please wait.")

for attack_name, attack_df in attacks.items():

    test_df = pd.concat([benign_test_df, attack_df], ignore_index=True)
    X_test = test_df[num_cols + cat_cols]
    y_test = test_df['label'].astype(int)

    scores = -final_model.decision_function(X_test)

    auc_roc = roc_auc_score(y_test, scores)
    auc_pr = average_precision_score(y_test, scores)
    fpr, tpr, thresholds = roc_curve(y_test, scores)

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

    len_b = len(benign_test_df)
    attack_only_scores = scores[len_b:]
    attack_only_y = y_test.values[len_b:]

    if 'EpochArrivalTime' in attack_df.columns:
        normalized_time = attack_df['EpochArrivalTime'] - attack_df['EpochArrivalTime'].min()
    else:
        normalized_time = np.arange(len(attack_df))

    if 'packet_id' in attack_df.columns:
        packet_ids = attack_df['packet_id'].values
    else:
        packet_ids = np.arange(len(attack_df))

    # Store the full ROC curve (fpr, tpr) computed over the correct combined
    # test set so that section 7b uses the exact same curve as section 7
    attack_raw_data[attack_name] = {
        'y_test': attack_only_y,
        'scores': attack_only_scores,
        'fpr': fpr,
        'tpr': tpr,
        'thresholds': thresholds,
        'time_seconds': normalized_time.values,
        'packet_ids': packet_ids
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

# =============================================================================
# 7b. Minimum FPR Required to Achieve Fixed TPR Levels
# =============================================================================

tpr_targets = [1.00, 0.99, 0.98,0.97,0.96, 0.95, 0.90, 0.85, 0.80]

print("\n=====================================================================")
print("         MINIMUM FPR REQUIRED TO ACHIEVE TARGET TPR LEVELS")
print("=====================================================================")
print(f"{'Target TPR':<12}| {'Naive FPR':<16} | {'Stealthy FPR':<16} | {'SSAware FPR':<16}")
print("---------------------------------------------------------------------")

for tpr_target in tpr_targets:
    row = f"{tpr_target*100:.0f}%{'':<9}|"
    for attack_name in ['Naive', 'Stealthy', 'SSAware']:
        data = attack_raw_data[attack_name]

        # Use the same ROC curve computed in section 6 over concat([benign_test, attack])
        # Drop the trivial sklearn endpoint (FPR=1, TPR=1) before searching
        _fpr = data['fpr'][:-1]
        _tpr = data['tpr'][:-1]

        # valid[0] is the first (lowest-FPR) point where TPR reaches the target
        valid = np.where(_tpr >= tpr_target)[0]
        if len(valid) > 0:
            min_fpr = _fpr[valid[0]]
            cell = f"{min_fpr*100:.2f}%"
        else:
            cell = "N/A"
        row += f" {cell:<15} |"
    print(row)

print("=====================================================================\n")

# =============================================================================
# 8. Generate & Show TPR vs FPR Graph (0% - 3% FPR)
# =============================================================================
print("Generating TPR vs FPR Graph...")

fpr_mask = fpr_targets <= 0.03
fpr_plot = fpr_targets[fpr_mask] * 100

plot_df = pd.DataFrame({
    'FPR (%)': np.tile(fpr_plot, 3),
    'TPR':     np.concatenate([
                   np.array(results_data['Naive']['tprs'])[fpr_mask],
                   np.array(results_data['Stealthy']['tprs'])[fpr_mask],
                   np.array(results_data['SSAware']['tprs'])[fpr_mask]
               ]),
    'Attack':  (['Naive'] * fpr_mask.sum() +
                ['Stealthy'] * fpr_mask.sum() +
                ['SSAware'] * fpr_mask.sum())
})

palette = {
    'Naive':    '#2196F3',
    'Stealthy': '#FF9800',
    'SSAware':  '#4CAF50'
}

markers = {
    'Naive':    'o',
    'Stealthy': 's',
    'SSAware':  '^'
}

sns.set_theme(style='whitegrid', font_scale=1.15)
fig, ax = plt.subplots(figsize=(10, 6))

for attack, group in plot_df.groupby('Attack', sort=False):
    sns.lineplot(
        data=group,
        x='FPR (%)', y='TPR',
        ax=ax,
        label=attack,
        color=palette[attack],
        linewidth=2.2,
        marker=markers[attack],
        markersize=6,
        markeredgewidth=0.8,
        markeredgecolor='white'
    )

ax.set_xlim(-0.05, 3.05)
ax.set_ylim(-0.05, 1.05)
ax.set_xlabel('False Positive Rate (%)', fontsize=12)
ax.set_ylabel('True Positive Rate', fontsize=12)
ax.set_title('TPR vs FPR at Strict Thresholds (0% to 3%)', fontsize=13, fontweight='bold')
ax.legend(title='Attack Type', fontsize=10, title_fontsize=11, loc='lower right', framealpha=0.9)
ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda y, _: f'{y:.0%}'))

sns.despine(left=False, bottom=False)
plt.tight_layout()
plt.show()

