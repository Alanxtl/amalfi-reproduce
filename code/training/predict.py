#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import json
import os
import pickle
import re
from collections import defaultdict, Counter

import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score


# ---------- helpers: tarball key normalize ----------
def _basename_any(p: str) -> str:
    if not p:
        return ""
    return os.path.basename(p.replace("\\", "/"))


def _normalize_tarball(name: str) -> str:
    """
    aliyundrive-6.0.4__16.tgz -> aliyundrive-6.0.4.tgz
    只去掉最后一个 '__数字'（紧贴扩展名前）
    """
    name = _basename_any(name)
    return re.sub(r"__\d+(?=\.)", "", name)


# ---------- load ground truth ----------
def load_ground_truth(gt_jsonl_path: str, key_mode: str = "type_bucket"):
    """
    读取 ground_truth.jsonl，构建：
      - tarball_to_types: tarball_basename -> set(types)
      - malicious_set:    tarball_basename -> 是否恶意（ground_truth 里默认都是恶意样本）
    key_mode:
      - type_bucket / malicious_types / both
    注意：同时把 src_archive / dst_path 的 basename，以及它们 normalize 版本都加入映射。
    """
    tarball_to_types = defaultdict(set)
    malicious_set = set()

    with open(gt_jsonl_path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception as e:
                raise RuntimeError(f"ground_truth.jsonl 解析失败，第{line_no}行：{e}")

            src = _basename_any(obj.get("src_archive", ""))
            dst = _basename_any(obj.get("dst_path", ""))

            keys = []
            if src:
                keys += [src, _normalize_tarball(src)]
            if dst:
                keys += [dst, _normalize_tarball(dst)]

            keys = [k for k in keys if k]
            if not keys:
                continue

            # ground_truth 一般记录的是恶意样本
            for k in keys:
                malicious_set.add(k)

            types = set()
            if key_mode in ("type_bucket", "both"):
                tb = obj.get("type_bucket")
                if tb:
                    types.add(str(tb))
            if key_mode in ("malicious_types", "both"):
                mts = obj.get("malicious_types") or []
                for t in mts:
                    if t:
                        types.add(str(t))

            if types:
                for k in keys:
                    tarball_to_types[k].update(types)

    return dict(tarball_to_types), malicious_set


# ---------- read features csv ----------
def read_features_csv(features_csv: str, exclude_features=None):
    """
    返回：
      tarballs: list[str]  (basename)
      X_dicts:  list[dict] (特征字典，供 DictVectorizer transform)
    注意：这里不做 booleanize/positive 等处理——这些在训练时已固化在 model.pkl 里。
    """
    if exclude_features is None:
        exclude_features = []

    tarballs = []
    X_dicts = []

    with open(features_csv, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise RuntimeError("features_csv 没有表头。")

        for row in reader:
            tarball = _basename_any(row.get("tarball", "") or "")
            tarballs.append(tarball)

            feat = {}
            for k, v in row.items():
                if k in ("tarball", "package_name", "package_version"):
                    continue
                if k in exclude_features:
                    continue
                try:
                    feat[k] = float(v)
                except Exception:
                    feat[k] = 0.0
            X_dicts.append(feat)

    return tarballs, X_dicts


# ---------- evaluation: per-type recall ----------
def per_type_report(tarballs, y_true, y_pred, tarball_to_types, key_mode="type_bucket"):
    """
    由于模型输出只有 benign/malicious，不输出“类型”，所以最稳健的按类型指标是：
      - 每类恶意的识别率（Recall）：TP / (TP + FN)，其中 TP/FN 只在真实恶意样本上统计。

    如果你用 key_mode=malicious_types/both（多标签），同一样本会计入多个类型的 TP/FN。
    """
    stats = defaultdict(lambda: {"n": 0, "tp": 0, "fn": 0})

    for tb, yt, yp in zip(tarballs, y_true, y_pred):
        if yt != "malicious":
            continue

        tb_norm = _normalize_tarball(tb)
        types = tarball_to_types.get(tb) or tarball_to_types.get(tb_norm)
        if not types:
            continue

        for t in types:
            stats[t]["n"] += 1
            if yp == "malicious":
                stats[t]["tp"] += 1
            else:
                stats[t]["fn"] += 1

    rows = []
    for t, s in stats.items():
        n, tp, fn = s["n"], s["tp"], s["fn"]
        recall = tp / n if n else 0.0
        rows.append((t, n, tp, fn, recall))

    rows.sort(key=lambda x: (-x[1], x[0]))
    df = pd.DataFrame(rows, columns=["type", "n_malicious", "TP", "FN", "recall"])
    return df


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, help="训练生成的 model.pkl")
    ap.add_argument(
        "--features",
        required=True,
        help="要评估的数据集 features.csv（同训练方法生成）",
    )
    ap.add_argument(
        "--ground-truth-jsonl", required=True, help="均衡抽样生成的 ground_truth.jsonl"
    )
    ap.add_argument(
        "--gt-key-mode",
        choices=["type_bucket", "malicious_types", "both"],
        default="type_bucket",
        help="类型来源字段",
    )
    ap.add_argument(
        "--out-prefix",
        default=None,
        help="可选：输出文件前缀（会写 *_overall.json, *_per_type.csv）",
    )
    ap.add_argument(
        "--threshold",
        type=float,
        default=None,
        help="可选：用概率阈值代替默认0.5（仅对支持 predict_proba 的模型有效）",
    )
    args = ap.parse_args()

    # 1) load model
    with open(args.model, "rb") as f:
        obj = pickle.load(f)

    vec = obj["vectorizer"]
    clf = obj["classifier"]
    clf_name = obj.get("classifier_name", "unknown")

    # 训练时的处理配置（用于复现特征处理）
    booleanize = obj.get("booleanize", False)
    positive = obj.get("positive", False)
    exclude_features = obj.get("exclude_features", [])

    # 2) load ground truth mapping
    tarball_to_types, malicious_set = load_ground_truth(
        args.ground_truth_jsonl, key_mode=args.gt_key_mode
    )

    # 3) load features
    tarballs, X_dicts = read_features_csv(
        args.features, exclude_features=exclude_features
    )
    X = vec.transform(X_dicts)

    # 4) apply booleanize/positive as in training
    # （训练脚本里：booleanize 时把非连续特征转 0/1；并可能 positive 截断负值）
    # 这里的 X 是向量化后的 numpy array，无法知道哪些是连续/离散特征，
    # 但你的训练流程里：如果 booleanize=True，vec 已是在 booleanized dict 上 fit 的。
    # 所以只要这里读入的 features.csv 是同一套生成方式（已是计数/数值），
    # 最稳健做法是：保持 features.csv 和训练时一致，不在预测阶段再二次 booleanize。
    # 若你确实训练时 booleanize=True，那么 features.csv 里的原值（0/1/计数）也能被 vec 正常映射，
    # 不会影响结果（因为训练时拟合的是同一字段集合）。
    # 因此这里不额外处理。

    # 5) build y_true:
    # ground_truth.jsonl 中出现的 tarball（src/dst/normalize）视为 malicious，否则 benign
    y_true = []
    for tb in tarballs:
        tb_norm = _normalize_tarball(tb)
        y_true.append(
            "malicious"
            if (tb in malicious_set or tb_norm in malicious_set)
            else "malicious"
        )

    # 6) predict
    if clf_name == "svm":
        # One-Class SVM: +1 benign, -1 malicious
        y_raw = clf.predict(X)
        y_pred = ["malicious" if v == -1 else "benign" for v in y_raw]
    else:
        if args.threshold is not None and hasattr(clf, "predict_proba"):
            proba = clf.predict_proba(X)
            # 假设类别中有 malicious
            classes = list(clf.classes_)
            if "malicious" not in classes:
                raise RuntimeError(f"模型 classes_ 不包含 'malicious'：{classes}")
            mal_idx = classes.index("malicious")
            p_mal = proba[:, mal_idx]
            thr = float(args.threshold)
            y_pred = ["malicious" if p >= thr else "benign" for p in p_mal]
        else:
            y_pred = clf.predict(X)

    # 7) overall report
    labels_u = ["benign", "malicious"]
    cm = confusion_matrix(y_true, y_pred, labels=labels_u)
    cm_df = pd.DataFrame(cm, index=labels_u, columns=labels_u)

    print("\n=== Overall Confusion Matrix ===")
    print(cm_df)
    print("\n=== Overall Classification Report ===")
    print(classification_report(y_true, y_pred, digits=4))
    print("Accuracy:", accuracy_score(y_true, y_pred))

    # 8) per-type report (recall on malicious only)
    df_type = per_type_report(
        tarballs, y_true, y_pred, tarball_to_types, key_mode=args.gt_key_mode
    )
    print("\n=== Per-type recall on MALICIOUS samples ===")
    if df_type.empty:
        print(
            "No per-type rows. Check tarball naming / ground_truth mapping / gt-key-mode."
        )
    else:
        pd.set_option("display.max_rows", 500)
        print(
            df_type.to_string(
                index=False, justify="left", float_format=lambda x: f"{x:.4f}"
            )
        )

    # 9) optional save
    if args.out_prefix:
        overall = {
            "model": args.model,
            "features": args.features,
            "ground_truth_jsonl": args.ground_truth_jsonl,
            "gt_key_mode": args.gt_key_mode,
            "classifier_name": clf_name,
            "threshold": args.threshold,
            "confusion_matrix": {
                "labels": labels_u,
                "matrix": cm.tolist(),
            },
            "class_distribution": {
                "y_true": dict(Counter(y_true)),
                "y_pred": dict(Counter(y_pred)),
            },
            "accuracy": float(accuracy_score(y_true, y_pred)),
            "classification_report": classification_report(
                y_true, y_pred, digits=4, output_dict=True
            ),
        }
        with open(args.out_prefix + "_overall.json", "w", encoding="utf-8") as f:
            json.dump(overall, f, ensure_ascii=False, indent=2)

        df_type.to_csv(
            args.out_prefix + "_per_type.csv", index=False, encoding="utf-8-sig"
        )
        print(f"\nSaved: {args.out_prefix}_overall.json")
        print(f"Saved: {args.out_prefix}_per_type.csv")


if __name__ == "__main__":
    main()
