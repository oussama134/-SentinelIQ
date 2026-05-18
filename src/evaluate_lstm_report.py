# evaluate_lstm_report.py
# Builds report metrics from the already-trained LSTM. This does not retrain.
import os
import random

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
import torch
import torch.nn as nn
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight
from torch.utils.data import DataLoader, Dataset


# =========================
# CONFIG
# =========================
SEED = 42
random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MODEL_DIR = os.path.join(BASE_DIR, "backend", "models")
REPORT_DIR = os.path.join(MODEL_DIR, "report")
os.makedirs(REPORT_DIR, exist_ok=True)

MODEL_PATH = os.path.join(MODEL_DIR, "lstm_cicids.pth")
LABEL_ENCODER_PATH = os.path.join(MODEL_DIR, "label_encoder.pkl")
FEATURES_PATH = os.path.join(MODEL_DIR, "features_scaled.npy")
LABELS_PATH = os.path.join(MODEL_DIR, "labels.npy")

CONFUSION_MATRIX_CSV = os.path.join(REPORT_DIR, "confusion_matrix.csv")
CONFUSION_MATRIX_PNG = os.path.join(REPORT_DIR, "confusion_matrix.png")
CLASSIFICATION_REPORT_CSV = os.path.join(REPORT_DIR, "classification_report.csv")
METRICS_CSV = os.path.join(REPORT_DIR, "evaluation_metrics.csv")
LOSS_ACCURACY_PNG = os.path.join(REPORT_DIR, "loss_accuracy.png")

SEQ_LEN = 5
MAX_PER_CLASS = 20000
TEST_SIZE = 0.2
BATCH_SIZE = 256
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


class SequenceDataset(Dataset):
    def __init__(self, features_path, start_indices, seq_len=SEQ_LEN):
        self.features = np.load(features_path, mmap_mode="r")
        self.start_indices = np.array(start_indices, dtype=np.int64)
        self.seq_len = seq_len

    def __len__(self):
        return len(self.start_indices)

    def __getitem__(self, idx):
        start = self.start_indices[idx]
        seq = self.features[start:start + self.seq_len].astype(np.float32)
        return torch.tensor(seq, dtype=torch.float32), start


class LSTMModel(nn.Module):
    def __init__(self, input_dim, hidden_dim, num_layers, num_classes):
        super().__init__()
        self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers, batch_first=True)
        self.fc = nn.Linear(hidden_dim, num_classes)

    def forward(self, x):
        out, _ = self.lstm(x)
        out = out[:, -1, :]
        return self.fc(out)


def labels_for_starts(labels_mem, starts):
    return labels_mem[starts + SEQ_LEN - 1].astype(np.int64)


def build_same_test_split(labels_mem):
    n_rows = labels_mem.shape[0]
    max_start = n_rows - SEQ_LEN
    if max_start <= 0:
        raise SystemExit("SEQ_LEN too large for cached dataset")

    label_ends = labels_mem[SEQ_LEN - 1:]
    all_start_indices = np.arange(0, max_start + 1, dtype=np.int64)

    sampled_indices = []
    for cls_idx in np.unique(label_ends):
        idxs = all_start_indices[label_ends == cls_idx]
        take = min(len(idxs), MAX_PER_CLASS)
        chosen = np.random.choice(idxs, size=take, replace=False)
        sampled_indices.append(chosen)

    sampled_indices = np.concatenate(sampled_indices)
    np.random.shuffle(sampled_indices)
    sampled_labels = labels_mem[sampled_indices + SEQ_LEN - 1]

    train_idx, test_idx, _, _ = train_test_split(
        sampled_indices,
        sampled_labels,
        test_size=TEST_SIZE,
        random_state=SEED,
        stratify=sampled_labels,
    )
    return train_idx, test_idx


def infer_model_from_state_dict(state_dict):
    input_dim = state_dict["lstm.weight_ih_l0"].shape[1]
    hidden_dim = state_dict["lstm.weight_hh_l0"].shape[1]
    num_classes = state_dict["fc.bias"].shape[0]
    layer_numbers = {
        int(key.split("_l")[-1].split(".")[0])
        for key in state_dict
        if key.startswith("lstm.weight_ih_l")
    }
    num_layers = max(layer_numbers) + 1
    return input_dim, hidden_dim, num_layers, num_classes


def main():
    print("Loading existing model and cached arrays. No training will run.")
    label_encoder = joblib.load(LABEL_ENCODER_PATH)
    labels_mem = np.load(LABELS_PATH, mmap_mode="r")
    state_dict = torch.load(MODEL_PATH, map_location=DEVICE)

    input_dim, hidden_dim, num_layers, num_classes = infer_model_from_state_dict(state_dict)
    model = LSTMModel(input_dim, hidden_dim, num_layers, num_classes).to(DEVICE)
    model.load_state_dict(state_dict)
    model.eval()

    train_idx, test_idx = build_same_test_split(labels_mem)
    test_dataset = SequenceDataset(FEATURES_PATH, test_idx)
    test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False)

    class_weights = compute_class_weight(
        class_weight="balanced",
        classes=np.arange(num_classes),
        y=labels_for_starts(labels_mem, train_idx),
    )
    criterion = nn.CrossEntropyLoss(
        weight=torch.tensor(class_weights, dtype=torch.float32).to(DEVICE)
    )

    total_loss = 0.0
    all_preds, all_trues = [], []
    with torch.no_grad():
        for seq_batch, starts in test_loader:
            seq_batch = seq_batch.to(DEVICE)
            y_true = labels_for_starts(labels_mem, starts.numpy())
            y_batch = torch.tensor(y_true, dtype=torch.long).to(DEVICE)

            logits = model(seq_batch)
            loss = criterion(logits, y_batch)
            total_loss += loss.item() * seq_batch.size(0)

            preds = torch.argmax(logits, dim=1).cpu().numpy()
            all_preds.append(preds)
            all_trues.append(y_true)

    all_preds = np.concatenate(all_preds)
    all_trues = np.concatenate(all_trues)

    metrics = {
        "test_loss": total_loss / len(test_dataset),
        "test_accuracy": accuracy_score(all_trues, all_preds),
        "test_precision_macro": precision_score(all_trues, all_preds, average="macro", zero_division=0),
        "test_recall_macro": recall_score(all_trues, all_preds, average="macro", zero_division=0),
        "test_f1_macro": f1_score(all_trues, all_preds, average="macro", zero_division=0),
    }
    metrics_df = pd.DataFrame([metrics])
    metrics_df.to_csv(METRICS_CSV, index=False)

    report_df = pd.DataFrame(
        classification_report(
            all_trues,
            all_preds,
            target_names=label_encoder.classes_,
            zero_division=0,
            output_dict=True,
        )
    ).transpose()
    report_df.to_csv(CLASSIFICATION_REPORT_CSV)

    cm = confusion_matrix(all_trues, all_preds, labels=np.arange(num_classes))
    cm_df = pd.DataFrame(cm, index=label_encoder.classes_, columns=label_encoder.classes_)
    cm_df.to_csv(CONFUSION_MATRIX_CSV)

    plt.figure(figsize=(12, 10))
    sns.heatmap(cm_df, annot=True, fmt="d", cmap="Blues", cbar=True)
    plt.xlabel("Predicted label")
    plt.ylabel("True label")
    plt.title("Confusion Matrix")
    plt.xticks(rotation=45, ha="right")
    plt.yticks(rotation=0)
    plt.tight_layout()
    plt.savefig(CONFUSION_MATRIX_PNG, dpi=200)
    plt.close()

    plt.figure(figsize=(7, 5))
    plt.bar(["Test loss", "Test accuracy"], [metrics["test_loss"], metrics["test_accuracy"]])
    plt.title("Saved Model Evaluation")
    plt.tight_layout()
    plt.savefig(LOSS_ACCURACY_PNG, dpi=200)
    plt.close()

    print("Report metrics:")
    for name, value in metrics.items():
        print(f"  {name}: {value:.6f}")
    print("Saved:", METRICS_CSV)
    print("Saved:", CLASSIFICATION_REPORT_CSV)
    print("Saved:", CONFUSION_MATRIX_CSV)
    print("Saved:", CONFUSION_MATRIX_PNG)
    print("Saved:", LOSS_ACCURACY_PNG)


if __name__ == "__main__":
    main()
