"""
Himaya Helios - MODEL-003: Sender Reputation XGBoost Trainer
Generates synthetic training data and trains/evaluates the XGBoost classifier.
"""

from __future__ import annotations

import logging
import pickle
import random
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# Feature columns (must match classifier.py)
FEATURE_COLUMNS = [
    "domain_age_days",
    "has_dmarc",
    "has_spf",
    "has_dkim",
    "is_breached",
    "is_lookalike",
    "lookalike_distance",
    "is_new_to_org",
    "tld_risk_score",
    "mx_valid",
    "domain_entropy",
]

MODEL_SAVE_PATH = Path(__file__).parent / "model.pkl"


def _random_entropy(high: bool = False) -> float:
    """Generate a plausible domain entropy value."""
    if high:
        return round(random.uniform(3.2, 4.2), 4)
    return round(random.uniform(1.5, 3.0), 4)


def generate_synthetic_data(
    n_phishing: int = 500,
    n_legit: int = 500,
    seed: int = 42,
) -> pd.DataFrame:
    """
    Generate realistic synthetic training data for the reputation classifier.

    Phishing domains tend to be:
    - Newly registered (< 90 days)
    - Missing DMARC/SPF/DKIM
    - Lookalike domains
    - High-risk TLDs
    - High entropy (DGA patterns)
    - Invalid MX or from breached accounts

    Legitimate domains tend to be:
    - Older (> 365 days)
    - Have DMARC/SPF/DKIM configured
    - Not lookalikes
    - Low-risk TLDs
    - Valid MX

    Args:
        n_phishing: Number of phishing/malicious samples
        n_legit: Number of legitimate samples
        seed: Random seed for reproducibility

    Returns:
        DataFrame with FEATURE_COLUMNS + 'label' column (1=malicious, 0=legit)
    """
    random.seed(seed)
    np.random.seed(seed)

    records: list[dict[str, Any]] = []

    # --- Phishing/Malicious samples ---
    phishing_tlds = [0.7, 0.8, 0.9, 0.95, 0.6, 0.7, 0.8]
    for _ in range(n_phishing):
        # Mix of attack patterns
        attack_type = random.choice(["new_domain", "lookalike", "dga", "breached", "mixed"])

        domain_age = (
            random.randint(0, 30) if attack_type in ("new_domain", "mixed")
            else random.randint(0, 180)
        )
        has_dmarc = random.random() < 0.15  # Rarely configured
        has_spf = random.random() < 0.25
        has_dkim = random.random() < 0.20
        is_breached = random.random() < 0.35
        is_lookalike = attack_type in ("lookalike", "mixed") or random.random() < 0.30
        lookalike_dist = (
            random.randint(1, 2) if is_lookalike
            else random.randint(3, 10)
        )
        is_new_to_org = random.random() < 0.75
        tld_risk = random.choice(phishing_tlds)
        mx_valid = random.random() < 0.40
        entropy = _random_entropy(high=(attack_type == "dga" or random.random() < 0.4))

        records.append({
            "domain_age_days": float(domain_age),
            "has_dmarc": float(int(has_dmarc)),
            "has_spf": float(int(has_spf)),
            "has_dkim": float(int(has_dkim)),
            "is_breached": float(int(is_breached)),
            "is_lookalike": float(int(is_lookalike)),
            "lookalike_distance": float(lookalike_dist),
            "is_new_to_org": float(int(is_new_to_org)),
            "tld_risk_score": tld_risk,
            "mx_valid": float(int(mx_valid)),
            "domain_entropy": entropy,
            "label": 1,
        })

    # --- Legitimate samples ---
    legit_tlds = [0.1, 0.1, 0.15, 0.2, 0.2, 0.0, 0.0, 0.1]
    for _ in range(n_legit):
        domain_age = random.randint(365, 7300)  # 1-20 years
        has_dmarc = random.random() < 0.80
        has_spf = random.random() < 0.90
        has_dkim = random.random() < 0.85
        is_breached = random.random() < 0.05
        is_lookalike = random.random() < 0.02
        lookalike_dist = (
            random.randint(1, 2) if is_lookalike
            else random.randint(5, 15)
        )
        is_new_to_org = random.random() < 0.15
        tld_risk = random.choice(legit_tlds)
        mx_valid = random.random() < 0.98
        entropy = _random_entropy(high=False)

        records.append({
            "domain_age_days": float(domain_age),
            "has_dmarc": float(int(has_dmarc)),
            "has_spf": float(int(has_spf)),
            "has_dkim": float(int(has_dkim)),
            "is_breached": float(int(is_breached)),
            "is_lookalike": float(int(is_lookalike)),
            "lookalike_distance": float(lookalike_dist),
            "is_new_to_org": float(int(is_new_to_org)),
            "tld_risk_score": tld_risk,
            "mx_valid": float(int(mx_valid)),
            "domain_entropy": entropy,
            "label": 0,
        })

    df = pd.DataFrame(records)
    df = df.sample(frac=1, random_state=seed).reset_index(drop=True)
    return df


def train_model(
    data_path: str | None = None,
    save_path: Path | str | None = None,
    n_phishing: int = 500,
    n_legit: int = 500,
) -> Any:
    """
    Train the XGBoost sender reputation classifier.

    Args:
        data_path: Optional path to CSV with pre-collected training data.
                   If None, synthetic data is generated.
        save_path: Where to save the trained model (defaults to model.pkl in this dir)
        n_phishing: Phishing samples for synthetic data generation
        n_legit: Legitimate samples for synthetic data generation

    Returns:
        Trained XGBoost classifier
    """
    try:
        from xgboost import XGBClassifier
        from sklearn.model_selection import cross_val_score, StratifiedKFold, train_test_split
        from sklearn.metrics import classification_report, roc_auc_score
    except ImportError as e:
        raise ImportError(f"Required packages not installed: {e}") from e

    # Load or generate data
    if data_path:
        logger.info(f"Loading training data from {data_path}")
        df = pd.read_csv(data_path)
    else:
        logger.info(f"Generating synthetic training data ({n_phishing} phishing, {n_legit} legit)")
        df = generate_synthetic_data(n_phishing=n_phishing, n_legit=n_legit)

    X = df[FEATURE_COLUMNS].values
    y = df["label"].values

    logger.info(f"Dataset: {len(df)} samples, {y.sum()} malicious, {(y==0).sum()} legitimate")

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # XGBoost classifier
    clf = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        use_label_encoder=False,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
        verbosity=0,
    )

    # 5-fold cross-validation
    logger.info("Running 5-fold cross-validation...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(clf, X_train, y_train, cv=cv, scoring="roc_auc", n_jobs=-1)
    logger.info(f"CV AUC-ROC: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
    print(f"\n5-Fold CV AUC-ROC: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    # Final training
    clf.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        verbose=False,
    )

    # Evaluation
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]
    auc = roc_auc_score(y_test, y_prob)

    print("\n=== Sender Reputation Model Evaluation ===")
    print(f"Test AUC-ROC: {auc:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Malicious"]))

    # Feature importances
    importances = clf.feature_importances_
    print("\nFeature Importances:")
    for feat, imp in sorted(zip(FEATURE_COLUMNS, importances), key=lambda x: -x[1]):
        print(f"  {feat:<25} {imp:.4f}")

    # Save model
    save_path = Path(save_path) if save_path else MODEL_SAVE_PATH
    save_path.parent.mkdir(parents=True, exist_ok=True)
    with open(save_path, "wb") as f:
        pickle.dump(clf, f)
    logger.info(f"Model saved to {save_path}")
    print(f"\nModel saved to: {save_path}")

    return clf


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    train_model()
