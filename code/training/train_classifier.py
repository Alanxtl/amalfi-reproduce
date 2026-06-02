#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import json
import os
import pickle
import random
import re
from collections import Counter, defaultdict
from datetime import timedelta
from timeit import default_timer as timer

import numpy as np
import pandas as pd
from graphviz import Source
from imblearn.over_sampling import SMOTE
from sklearn import naive_bayes, svm, tree
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import GroupShuffleSplit

try:
    from sklearn.model_selection import StratifiedGroupKFold

    _HAS_STRAT_GROUP_KFOLD = True
except Exception:
    StratifiedGroupKFold = None
    _HAS_STRAT_GROUP_KFOLD = False


# 若 booleanize=True 则会排除这些连续特征
CONTINUOUS_FEATURES = ["entropy_average", "entropy_std_dev", "time"]


def _parse_float(x):
    try:
        return float(x)
    except Exception:
        return 0.0


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


def _load_ground_truth_map(gt_jsonl_path: str, key_mode: str = "type_bucket"):
    """
    返回 tarball_to_types: dict[str, set[str]]
    关键：同时对齐 src_archive / dst_path 两套文件名，并加入 normalize 版本
    """
    tarball_to_types = defaultdict(set)

    with open(gt_jsonl_path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception as e:
                raise RuntimeError(f"ground_truth.jsonl 解析失败，第{line_no}行：{e}")

            src = _basename_any(obj.get("archive_name", ""))

            keys = []
            if src:
                keys.append(src)
                keys.append(_normalize_tarball(src))

            keys = [k for k in keys if k]
            if not keys:
                continue

            types = set()
            if key_mode in ("type_bucket", "both"):
                tb = obj.get("type_bucket")
                if tb:
                    types.add(str(tb))
            if key_mode in ("malicious_types", "both"):
                annotation = obj.get("annotation")
                mts = annotation.get("malicious_types")
                if not mts:
                    continue
                for t in mts:
                    if t:
                        types.add(str(t))

            if not types:
                continue

            for k in keys:
                tarball_to_types[k].update(types)

    return dict(tarball_to_types)


def _per_type_recall_report(
    tarballs_test,
    y_test,
    y_pred,
    tarball_to_types,
    title="Per-type recall on MALICIOUS in test set",
):
    stats = defaultdict(lambda: {"tp": 0, "fn": 0, "n": 0})

    for tb, yt, yp in zip(tarballs_test, y_test, y_pred):
        if yt != "malicious":
            continue
        types = tarball_to_types.get(tb) or tarball_to_types.get(_normalize_tarball(tb))
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
        n = s["n"]
        tp = s["tp"]
        fn = s["fn"]
        recall = tp / n if n else 0.0
        rows.append((t, n, tp, fn, recall))

    rows.sort(key=lambda x: (-x[1], x[0]))

    print("\n" + "=" * 80)
    print(title)
    if not rows:
        print(
            "No per-type rows. (Most likely: tarball names still don't match ground_truth keys.)"
        )
        print("=" * 80 + "\n")
        return

    df = pd.DataFrame(
        rows, columns=["type", "n_malicious_in_test", "TP", "FN", "recall"]
    )
    pd.set_option("display.max_rows", 500)
    print(df.to_string(index=False, justify="left", float_format=lambda x: f"{x:.4f}"))
    print("=" * 80 + "\n")


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
    until=None,  # 兼容旧参数
    performance=None,
    smote=False,
    smote_k_neighbors=5,
    # 类型相关
    ground_truth_jsonl=None,
    gt_key_mode="type_bucket",  # type_bucket / malicious_types / both
    report_by_type=False,
    # 切分相关
    split_stratify_by_type=False,
):
    if exclude_features is None:
        exclude_features = [
            "package_name",
            "package_version",
            "tarball",
            "time",
            "timestamp",
            "source_size",
            "download_count",
            "Package Installation Risk",
        ]

    if classifier == "naive-bayes":
        booleanize = True

    # 读取二分类恶意列表
    malicious = set()
    with open(malicious_path, "r", encoding="utf-8") as mal:
        reader = csv.reader(mal)
        for row in reader:
            if not row:
                continue
            if hashing:
                malicious.add(row[0])
            else:
                if len(row) == 1:
                    malicious.add((row[0], None))
                else:
                    malicious.add((row[0], row[1]))

    # ground_truth 映射
    tarball_to_types = None
    if report_by_type or split_stratify_by_type:
        if not ground_truth_jsonl:
            raise ValueError(
                "--report-by-type / --split-stratify-by-type 需要提供 --ground-truth-jsonl"
            )
        tarball_to_types = _load_ground_truth_map(
            ground_truth_jsonl, key_mode=gt_key_mode
        )
        if not tarball_to_types:
            raise RuntimeError(
                "ground_truth.jsonl 加载后为空：请检查路径/字段是否正确。"
            )

    # 读 features_csv
    records = []
    labels = []
    groups = []
    tarballs = []
    strata = []

    with open(features_csv, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            raise RuntimeError("features_csv 没有表头。")

        for row in reader:
            package = row.get("package_name", "") or ""
            version = row.get("package_version", "") or ""
            tarball = _basename_any(row.get("tarball", "") or "")
            tarball_norm = _normalize_tarball(tarball)

            # 特征
            feat = {}
            for k, v in row.items():
                if k in ["tarball", "package_name", "package_version"]:
                    continue
                if k in exclude_features:
                    continue

                val = _parse_float(v)
                if positive and val < 0:
                    val = 0.0

                if booleanize and (k not in CONTINUOUS_FEATURES):
                    feat[k] = 1.0 if val > 0 else 0.0
                elif not booleanize:
                    feat[k] = val
                # booleanize 且连续特征 -> 跳过

            # 二分类标签
            label = "benign"
            if not hashing:
                if (package, version) in malicious or (package, None) in malicious:
                    label = "malicious"

            records.append(feat)
            labels.append(label)
            groups.append(package)
            tarballs.append(tarball)

            # strata：用于 split 时考虑类型分布
            if split_stratify_by_type:
                if label != "malicious":
                    strata.append("benign")
                else:
                    ts = None
                    if tarball_to_types is not None:
                        ts = tarball_to_types.get(tarball) or tarball_to_types.get(
                            tarball_norm
                        )
                    if not ts:
                        strata.append("malicious_UNKNOWN")
                    else:
                        # 改进逻辑：如果包含 RESOURCE_ABUSER，优先按它分层
                        if "RESOURCE_ABUSER" in ts:
                            strata.append("RESOURCE_ABUSER")
                        else:
                            strata.append(sorted(list(ts))[0])
            else:
                strata.append(label)

    # 随机下采样（不建议在你已经类型均衡的恶意集合上开）
    if randomize:
        malignant_count = sum(1 for y in labels if y == "malicious")
        benign_indices = [i for i, y in enumerate(labels) if y == "benign"]
        if malignant_count > 0:
            benign_selected = set(
                random.sample(benign_indices, min(malignant_count, len(benign_indices)))
            )
            keep = benign_selected | {
                i for i, y in enumerate(labels) if y == "malicious"
            }
            records = [r for i, r in enumerate(records) if i in keep]
            labels = [y for i, y in enumerate(labels) if i in keep]
            groups = [g for i, g in enumerate(groups) if i in keep]
            tarballs = [t for i, t in enumerate(tarballs) if i in keep]
            strata = [s for i, s in enumerate(strata) if i in keep]

    n = len(records)
    if not (n == len(labels) == len(groups) == len(tarballs) == len(strata)):
        raise RuntimeError("内部数据长度不一致，请检查 CSV/读取逻辑。")

    idx = np.arange(n)
    # 诊断：打印切分前的类别分布
    print("\n[Diagnosis] 原始数据集中的 Stratified 标签分布:")
    dist = Counter(strata)
    for label, count in dist.items():
        print(f"  - {label}: {count}")

    # 切分
    # --- 改进后的切分逻辑 ---
    if split_stratify_by_type:
        # 1. 获取唯一的 package 及其对应的 strata (取每个 package 出现的第一个 strata)
        unique_groups, group_indices = np.unique(groups, return_index=True)
        group_strata = np.array(strata)[group_indices]

        # 2. 按照 80/20 比例切分 Group
        from sklearn.model_selection import train_test_split
        train_groups, test_groups = train_test_split(
            unique_groups, 
            test_size=0.2, 
            stratify=group_strata, 
            random_state=42
        )

        # 3. 映射回原始索引
        train_idx = np.where(np.isin(groups, train_groups))[0]
        test_idx = np.where(np.isin(groups, test_groups))[0]
        print(f"[Split] Stratified Group Split: Train={len(train_idx)}, Test={len(test_idx)}")
    else:
        # 回退逻辑
        gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
        train_idx, test_idx = next(gss.split(idx, labels, groups=groups))

    rec_train = [records[i] for i in train_idx]
    y_train = [labels[i] for i in train_idx]
    rec_test = [records[i] for i in test_idx]
    y_test = [labels[i] for i in test_idx]
    tarballs_test = [tarballs[i] for i in test_idx]

    # 向量化
    vec = DictVectorizer(sparse=False)
    X_train = vec.fit_transform(rec_train)
    X_test = vec.transform(rec_test)

    print(
        f"Training samples before SMOTE: {len(y_train)} "
        f"(benign: {y_train.count('benign')}, malicious: {y_train.count('malicious')})"
    )

    # 训练集 SMOTE（避免泄漏）
    can_smote = classifier in {"decision-tree", "random-forest", "naive-bayes"}
    if smote and can_smote:
        y_arr = np.array(y_train)
        counts = Counter(y_arr)
        if len(counts) < 2:
            print("Skipping SMOTE: only one class in training data")
        else:
            minority = min(counts.values()) if counts else 0
            if minority <= 1:
                print("Skipping SMOTE: minority count <= 1")
            else:
                k_eff = max(1, min(smote_k_neighbors, minority - 1))
                sm = SMOTE(random_state=42, k_neighbors=k_eff)
                X_train, y_arr = sm.fit_resample(X_train, y_arr)

                if classifier == "naive-bayes" and booleanize:
                    X_train = (X_train >= 0.5).astype(float)

                y_train = list(y_arr)
                print(
                    f"Applied SMOTE (k_neighbors={k_eff}). New training distribution: {dict(Counter(y_train))}"
                )
    elif smote and classifier == "svm":
        print("Skipping SMOTE for One-Class SVM (not applicable).")

    print(
        f"Final training samples: {len(y_train)} "
        f"(benign: {y_train.count('benign')}, malicious: {y_train.count('malicious')})"
    )

    # 训练
    start = timer()
    if classifier == "decision-tree":
        clf = tree.DecisionTreeClassifier(criterion="entropy", random_state=42)
        clf.fit(X_train, y_train)
    elif classifier == "random-forest":
        clf = RandomForestClassifier(
            criterion="entropy", n_estimators=200, random_state=42, n_jobs=-1
        )
        clf.fit(X_train, y_train)
    elif classifier == "naive-bayes":
        clf = naive_bayes.BernoulliNB()
        clf.fit(X_train, y_train)
    else:
        clf = svm.OneClassSVM(gamma="scale", nu=nu, kernel="linear")
        X_train_benign = [x for x, y in zip(X_train, y_train) if y == "benign"]
        clf.fit(X_train_benign)
    end = timer()

    if performance:
        with open(performance, "a+", encoding="utf-8", newline="") as pf:
            writer = csv.writer(pf)
            writer.writerow([timedelta(seconds=end - start)])

    # 可选渲染树
    if classifier == "decision-tree" and render:
        file, ext = os.path.splitext(render)
        if ext != ".png":
            print("Rendering tree to PNG requires a .png extension")
        else:
            feature_names = vec.get_feature_names_out()
            dot = tree.export_graphviz(
                clf,
                out_file=None,
                feature_names=feature_names,
                class_names=True,
                filled=True,
            )
            outfile = Source(dot, format="png")
            outfile.render(file, view=view, cleanup=True)

    # 预测 + 二分类报告
    if classifier != "svm":
        y_pred = clf.predict(X_test)
    else:
        y_raw = clf.predict(X_test)  # +1 正常, -1 异常
        y_pred = ["malicious" if v == -1 else "benign" for v in y_raw]

    print("Confusion Matrix:")
    labels_u = np.unique(y_test)
    print(
        pd.DataFrame(
            confusion_matrix(y_test, y_pred, labels=labels_u),
            index=labels_u,
            columns=labels_u,
        )
    )
    print("Classification Report:")
    print(classification_report(y_test, y_pred, digits=4))
    print("Accuracy:", accuracy_score(y_test, y_pred))

    # 按类型报告
    if report_by_type and tarball_to_types is not None:
        _per_type_recall_report(
            tarballs_test=tarballs_test,
            y_test=y_test,
            y_pred=y_pred,
            tarball_to_types=tarball_to_types,
            title=f"Per-type recall on MALICIOUS in test set (gt_key_mode={gt_key_mode})",
        )

    # 保存模型
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


def train_classifier_full_from_bigcsv(
    classifier,
    malicious_path,
    features_csv,
    output,
    booleanize=False,
    hashing=False,
    exclude_features=None,
    nu=0.001,
    positive=False,
    performance=None,
    smote=False,
    smote_k_neighbors=5,
):
    if exclude_features is None:
        exclude_features = [
            "package_name",
            "package_version",
            "tarball",
            "time",
            "timestamp",
            "source_size",
            "download_count",
            "Package Installation Risk",
        ]

    if classifier == "naive-bayes":
        booleanize = True

    malicious = set()
    with open(malicious_path, "r", encoding="utf-8") as mal:
        reader = csv.reader(mal)
        for row in reader:
            if not row:
                continue
            if hashing:
                malicious.add(row[0])
            elif len(row) == 1:
                malicious.add((row[0], None))
            else:
                malicious.add((row[0], row[1]))

    records = []
    labels = []
    with open(features_csv, "r", encoding="utf-8") as feature_file:
        reader = csv.DictReader(feature_file)
        if reader.fieldnames is None:
            raise RuntimeError("features_csv 没有表头。")

        for row in reader:
            package = row.get("package_name", "") or ""
            version = row.get("package_version", "") or ""
            feat = {}
            for key, value in row.items():
                if key in ["tarball", "package_name", "package_version"]:
                    continue
                if key in exclude_features:
                    continue

                numeric_value = _parse_float(value)
                if positive and numeric_value < 0:
                    numeric_value = 0.0

                if booleanize and (key not in CONTINUOUS_FEATURES):
                    feat[key] = 1.0 if numeric_value > 0 else 0.0
                elif not booleanize:
                    feat[key] = numeric_value

            label = "benign"
            if not hashing and (
                (package, version) in malicious or (package, None) in malicious
            ):
                label = "malicious"

            records.append(feat)
            labels.append(label)

    if not records:
        raise RuntimeError("No training rows were loaded from features_csv.")

    vec = DictVectorizer(sparse=False)
    X_train = vec.fit_transform(records)
    y_train = list(labels)

    print(
        f"Training full dataset: {len(y_train)} "
        f"(benign: {y_train.count('benign')}, malicious: {y_train.count('malicious')})"
    )

    can_smote = classifier in {"decision-tree", "random-forest", "naive-bayes"}
    if smote and can_smote:
        y_arr = np.array(y_train)
        counts = Counter(y_arr)
        if len(counts) >= 2:
            minority = min(counts.values())
            if minority > 1:
                k_eff = max(1, min(smote_k_neighbors, minority - 1))
                sampler = SMOTE(random_state=42, k_neighbors=k_eff)
                X_train, y_arr = sampler.fit_resample(X_train, y_arr)
                if classifier == "naive-bayes" and booleanize:
                    X_train = (X_train >= 0.5).astype(float)
                y_train = list(y_arr)

    start = timer()
    if classifier == "decision-tree":
        clf = tree.DecisionTreeClassifier(criterion="entropy", random_state=42)
        clf.fit(X_train, y_train)
    elif classifier == "random-forest":
        clf = RandomForestClassifier(
            criterion="entropy", n_estimators=200, random_state=42, n_jobs=-1
        )
        clf.fit(X_train, y_train)
    elif classifier == "naive-bayes":
        clf = naive_bayes.BernoulliNB()
        clf.fit(X_train, y_train)
    else:
        clf = svm.OneClassSVM(gamma="scale", nu=nu, kernel="linear")
        X_train_benign = [x for x, y in zip(X_train, y_train) if y == "benign"]
        clf.fit(X_train_benign)
    end = timer()

    if performance:
        with open(performance, "a+", encoding="utf-8", newline="") as pf:
            writer = csv.writer(pf)
            writer.writerow([timedelta(seconds=end - start)])

    with open(output, "wb") as model_file:
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
            model_file,
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train classifier from features CSV")

    parser.add_argument(
        "classifier", choices=["decision-tree", "random-forest", "naive-bayes", "svm"]
    )
    parser.add_argument(
        "malicious",
        help="CSV with malicious package,version (or just package) per line",
    )
    parser.add_argument(
        "features_csv", help="The CSV file with features for all tarballs"
    )
    parser.add_argument("-o", "--output", required=True, help="Pickled model file")

    parser.add_argument(
        "-b", "--booleanize", choices=["true", "false"], default="false"
    )
    parser.add_argument("--hashing", choices=["true", "false"], default="false")
    parser.add_argument("-x", "--exclude-features", nargs="*", default=[])
    parser.add_argument("-n", "--nu", type=float, default=0.001)
    parser.add_argument("-p", "--positive", choices=["true", "false"], default="false")
    parser.add_argument(
        "-r", "--render", help="Render decision tree to PNG", required=False
    )
    parser.add_argument("--randomize", choices=["true", "false"], default="false")
    parser.add_argument("-v", "--view", action="store_true")
    parser.add_argument("-u", "--until", default="2100-01-01T00:00:00.000Z")
    parser.add_argument("--performance", help="CSV to log training time")

    parser.add_argument(
        "--smote",
        choices=["true", "false"],
        default="false",
        help="Apply SMOTE on the training set (not for One-Class SVM)",
    )
    parser.add_argument(
        "--smote-k-neighbors",
        type=int,
        default=5,
        help="k_neighbors for SMOTE (auto-capped by minority count)",
    )

    # ===== 类型相关 =====
    parser.add_argument(
        "--report-by-type",
        action="store_true",
        help="输出测试集恶意样本按类型的 Recall 统计",
    )
    parser.add_argument(
        "--ground-truth-jsonl",
        default=None,
        help="均衡数据集的 ground_truth.jsonl 路径",
    )
    parser.add_argument(
        "--gt-key-mode",
        choices=["type_bucket", "malicious_types", "both"],
        default="type_bucket",
        help="按哪种字段来做类型分组：type_bucket(推荐)/malicious_types/both",
    )

    parser.add_argument(
        "--split-stratify-by-type",
        action="store_true",
        help="划分 train/test 时同时考虑恶意类型分布（group=package + strata=type/benign）",
    )
    parser.add_argument(
        "--fit-full",
        action="store_true",
        help="Fit on the full provided dataset without creating an internal split.",
    )

    args = parser.parse_args()
    booleanize = args.booleanize == "true"
    hashing = args.hashing == "true"
    positive = args.positive == "true"
    randomize = args.randomize == "true"
    smote = args.smote == "true"

    if args.fit_full:
        train_classifier_full_from_bigcsv(
            args.classifier,
            args.malicious,
            args.features_csv,
            args.output,
            booleanize=booleanize,
            hashing=hashing,
            exclude_features=args.exclude_features,
            nu=args.nu,
            positive=positive,
            performance=args.performance,
            smote=smote,
            smote_k_neighbors=args.smote_k_neighbors,
        )
    else:
        train_classifier_from_bigcsv(
            args.classifier,
            args.malicious,
            args.features_csv,
            args.output,
            booleanize=booleanize,
            hashing=hashing,
            exclude_features=args.exclude_features,
            nu=args.nu,
            positive=positive,
            render=args.render,
            randomize=randomize,
            view=args.view,
            until=args.until,
            performance=args.performance,
            smote=smote,
            smote_k_neighbors=args.smote_k_neighbors,
            ground_truth_jsonl=args.ground_truth_jsonl,
            gt_key_mode=args.gt_key_mode,
            report_by_type=args.report_by_type,
            split_stratify_by_type=args.split_stratify_by_type,
        )
