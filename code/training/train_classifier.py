#! /usr/bin/env python3
import argparse
import csv
import os
import pickle
import random
from datetime import timedelta
from timeit import default_timer as timer
from collections import Counter

from graphviz import Source
from sklearn import naive_bayes, svm, tree
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.feature_extraction import DictVectorizer
import numpy as np
from collections import Counter
from imblearn.over_sampling import SMOTE
from sklearn.feature_extraction import DictVectorizer as _DV  # 可能未用到，但保留

# 若 booleanize=True 则会排除这些连续特征
CONTINUOUS_FEATURES = ["entropy_average", "entropy_std_dev", "time"]


def _parse_float(x):
    try:
        return float(x)
    except:
        return 0.0


def train_classifier_from_bigcsv(
    classifier,
    malicious_path,
    features_csv,
    output,
    booleanize=False,
    hashing=False,
    exclude_features=None,
    nu=0.001,
    positive=False,
    render=False,
    randomize=False,
    view=False,
    until=None,        # 未用到
    performance=None,
    smote=False,
    smote_k_neighbors=1,
):
    if exclude_features is None:
        exclude_features = [
            "package_name", "package_version", "tarball", "time", "timestamp",
            "source_size", "download_count", "Package Installation Risk"
        ]

    # Naive Bayes 默认二值化
    if classifier == "naive-bayes":
        booleanize = True

    # 读取恶意标注
    malicious = set()
    with open(malicious_path, "r", encoding="utf-8") as mal:
        reader = csv.reader(mal)
        for row in reader:
            if hashing:
                malicious.add(row[0])
            else:
                if len(row) == 1:
                    package = row[0]
                    malicious.add((package, None))
                else:
                    package, version = row[0], row[1]
                    malicious.add((package, version))

    # 收集样本
    records = []   # list[dict] 特征字典
    labels = []    # list[str]  'benign'/'malicious'
    groups = []    # list[str]  用 package 做 group，防止同包跨集
    pkgs = []      # 仅用于必要的 debug/扩展

    with open(features_csv, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            package = row.get("package_name", "")
            version = row.get("package_version", "")

            # 构造特征字典
            feat = {}
            for k, v in row.items():
                if k in ["tarball", "package_name", "package_version"]:
                    continue
                if k in exclude_features:
                    continue

                val = _parse_float(v)

                if positive and val < 0:
                    val = 0.0

                # booleanize 时排除连续特征，并对剩余特征二值化
                if booleanize and (k not in CONTINUOUS_FEATURES):
                    feat[k] = 1.0 if val > 0 else 0.0
                elif not booleanize:
                    feat[k] = val
                # 若 booleanize=True 且 k 在 CONTINUOUS_FEATURES，就直接跳过

            # 标签
            label = "benign"
            if hashing:
                pass
            else:
                if (package, version) in malicious or (package, None) in malicious:
                    label = "malicious"

            records.append(feat)
            labels.append(label)
            groups.append(package)
            pkgs.append((package, version))

    # 若需要随机下采样以平衡正负，仅在内存中同步抽样
    if randomize:
        malignant_count = sum(1 for y in labels if y == "malicious")
        benign_indices = [i for i, y in enumerate(labels) if y == "benign"]
        if malignant_count > 0:
            benign_selected = set(random.sample(benign_indices, min(malignant_count, len(benign_indices))))
            keep = benign_selected | {i for i, y in enumerate(labels) if y == "malicious"}
            records = [r for i, r in enumerate(records) if i in keep]
            labels  = [y for i, y in enumerate(labels)  if i in keep]
            groups  = [g for i, g in enumerate(groups)  if i in keep]
            pkgs    = [p for i, p in enumerate(pkgs)    if i in keep]

    # 分组切分
    n = len(records)
    assert n == len(labels) == len(groups), (len(records), len(labels), len(groups))

    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    idx = np.arange(n)
    train_idx, test_idx = next(gss.split(idx, labels, groups=groups))

    rec_train = [records[i] for i in train_idx]
    y_train = [labels[i] for i in train_idx]
    rec_test  = [records[i] for i in test_idx]
    y_test    = [labels[i] for i in test_idx]

    # 向量化器：仅用训练集拟合
    vec = DictVectorizer(sparse=False)
    X_train = vec.fit_transform(rec_train)
    X_test  = vec.transform(rec_test)

    print(f"Training samples before SMOTE: {len(y_train)} "
          f"(benign: {y_train.count('benign')}, malicious: {y_train.count('malicious')})")

    # ===== 在训练集上应用 SMOTE（避免泄漏）=====
    can_smote = classifier in {"decision-tree", "random-forest", "naive-bayes"}
    if smote and can_smote:
        # y 需要为一维数组
        y_arr = np.array(y_train)
        # 如果少数类样本太少，k_neighbors 需要小于少数类样本数
        minority = min(Counter(y_arr).items(), key=lambda kv: kv[1])[1]
        k_eff = max(1, min(smote_k_neighbors, minority - 1)) if minority > 1 else 1
        sm = SMOTE(random_state=42, k_neighbors=k_eff)
        X_train, y_arr = sm.fit_resample(X_train, y_arr)

        # 若是 BernoulliNB/booleanize，做阈值二值化，避免连续值
        if classifier == "naive-bayes" and booleanize:
            X_train = (X_train >= 0.5).astype(float)

        y_train = list(y_arr)
        cnt = Counter(y_train)
        print(f"Applied SMOTE (k_neighbors={k_eff}). New training distribution: {dict(cnt)}")
    elif smote and classifier == "svm":
        print("Skipping SMOTE for One-Class SVM (not applicable).")

    print(f"Final training samples: {len(y_train)} "
          f"(benign: {y_train.count('benign')}, malicious: {y_train.count('malicious')})")

    # 训练
    start = timer()
    if classifier == "decision-tree":
        clf = tree.DecisionTreeClassifier(criterion="entropy", random_state=42)
        clf.fit(X_train, y_train)
    elif classifier == "random-forest":
        clf = RandomForestClassifier(criterion="entropy", n_estimators=200, random_state=42, n_jobs=-1)
        clf.fit(X_train, y_train)
    elif classifier == "naive-bayes":
        clf = naive_bayes.BernoulliNB()
        clf.fit(X_train, y_train)
    else:  # SVM（One-Class，用训练集良性样本）
        clf = svm.OneClassSVM(gamma='scale', nu=nu, kernel='linear')
        X_train_benign = [x for x, y in zip(X_train, y_train) if y == "benign"]
        clf.fit(X_train_benign)
    end = timer()

    # 性能日志（训练时长）
    if performance:
        with open(performance, "a+", encoding="utf-8", newline="") as pf:
            writer = csv.writer(pf)
            writer.writerow([timedelta(seconds=end - start)])

    # 可选：渲染决策树
    if classifier == "decision-tree" and render:
        file, ext = os.path.splitext(render)
        if ext != ".png":
            print("Rendering tree to PNG requires a .png extension")
        else:
            feature_names = vec.get_feature_names_out()
            dot = tree.export_graphviz(clf, out_file=None, feature_names=feature_names, class_names=True, filled=True)
            outfile = Source(dot, format="png")
            outfile.render(file, view=view, cleanup=True)

    # 评估
    if classifier != "svm":
        y_pred = clf.predict(X_test)
        print("Confusion Matrix:")
        print(confusion_matrix(y_test, y_pred, labels=["benign", "malicious"]))
        print("Classification Report:")
        print(classification_report(y_test, y_pred, digits=4))
        print("Accuracy:", accuracy_score(y_test, y_pred))
    else:
        y_raw = clf.predict(X_test)  # +1 正常, -1 异常
        y_pred = ["malicious" if v == -1 else "benign" for v in y_raw]
        print("Confusion Matrix:")
        print(confusion_matrix(y_test, y_pred, labels=["benign", "malicious"]))
        print("Classification Report:")
        print(classification_report(y_test, y_pred, digits=4))
        print("Accuracy:", accuracy_score(y_test, y_pred))
        counts = Counter(y_pred)
        print("SVM prediction counts:", dict(counts))

    # 保存模型（包含向量器与配置）
    with open(output, "wb") as f:
        pickle.dump(
            {
                "vectorizer": vec,
                "booleanize": booleanize,
                "positive": positive,
                "exclude_features": exclude_features,
                "classifier_name": classifier,
                "classifier": clf,
                "smote": smote,
                "smote_k_neighbors": smote_k_neighbors,
            },
            f,
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train classifier from features CSV")
    parser.add_argument("classifier", choices=["decision-tree", "random-forest", "naive-bayes", "svm"])
    parser.add_argument("malicious", help="CSV with malicious package,version (or just package) per line")
    parser.add_argument("features_csv", help="The CSV file with features for all tarballs")
    parser.add_argument("-o", "--output", required=True, help="Pickled model file")
    parser.add_argument("-b", "--booleanize", choices=["true", "false"], default="false")
    parser.add_argument("--hashing", choices=["true", "false"], default="false")
    parser.add_argument("-x", "--exclude-features", nargs="*", default=[])
    parser.add_argument("-n", "--nu", type=float, default=0.001)
    parser.add_argument("-p", "--positive", choices=["true", "false"], default="false")
    parser.add_argument("-r", "--render", help="Render decision tree to PNG", required=False)
    parser.add_argument("--randomize", choices=["true", "false"], default="false")
    parser.add_argument("-v", "--view", action="store_true")
    parser.add_argument("-u", "--until", default="2100-01-01T00:00:00.000Z")  # 兼容旧参数
    parser.add_argument("--performance", help="CSV to log training time")

    # 新增 SMOTE 相关参数
    parser.add_argument("--smote", choices=["true", "false"], default="false",
                        help="Apply SMOTE on the training set (not for One-Class SVM)")
    parser.add_argument("--smote-k-neighbors", type=int, default=5,
                        help="k_neighbors for SMOTE (auto-capped by minority count)")

    args = parser.parse_args()
    booleanize = args.booleanize == "true"
    hashing = args.hashing == "true"
    positive = args.positive == "true"
    randomize = args.randomize == "true"
    smote = args.smote == "true"

    train_classifier_from_bigcsv(
        args.classifier,
        args.malicious,
        args.features_csv,
        args.output,
        booleanize,
        hashing,
        args.exclude_features,
        args.nu,
        positive,
        args.render,
        randomize,
        args.view,
        args.until,
        args.performance,
        smote,
        args.smote_k_neighbors,
    )
