"""
Train the ML model from a CSV of labeled feature rows.

CSV format expected (header row):
n_dangerous_perms,n_suspicious_apis,n_network_calls,n_suspicious_syscalls,has_boot_receiver,label

Example:
1,0,2,1,0,1

Usage:
    python train_model.py --input training/features.csv --out model.pkl --test-size 0.2
"""
import argparse
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, roc_auc_score
import joblib

def train(input_csv, out_path, test_size=0.2, random_state=42):
    df = pd.read_csv(input_csv)
    req = ['n_dangerous_perms','n_suspicious_apis','n_network_calls','n_suspicious_syscalls','has_boot_receiver','label']
    for c in req:
        if c not in df.columns:
            raise SystemExit(f"Missing column: {c} in {input_csv}")
    X = df[['n_dangerous_perms','n_suspicious_apis','n_network_calls','n_suspicious_syscalls','has_boot_receiver']].values
    y = df['label'].values
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=random_state)
    clf = RandomForestClassifier(n_estimators=200, random_state=random_state, n_jobs=-1)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    print('Classification report on test split:')
    print(classification_report(y_test, y_pred))
    try:
        auc = roc_auc_score(y_test, clf.predict_proba(X_test)[:,1])
        print(f'ROC AUC: {auc:.3f}')
    except Exception:
        pass
    scores = cross_val_score(clf, X, y, cv=2)
    print(f'Cross-validation accuracy: {scores.mean():.3f} (+/- {scores.std():.3f})')
    joblib.dump(clf, out_path)
    print(f'Model saved to {out_path}')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', required=True, help='CSV file with labeled features')
    parser.add_argument('--out', default='model.pkl', help='Output model path')
    parser.add_argument('--test-size', type=float, default=0.2)
    args = parser.parse_args()
    train(args.input, args.out, args.test_size)
