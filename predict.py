#! /usr/bin/env python3

import argparse
import csv
import pickle


def predict_from_bigcsv(model_path, features_csv, output_csv):
    # 载入模型
    with open(model_path, "rb") as f:
        model_data = pickle.load(f)

    clf = model_data["classifier"]
    feature_names = model_data["feature_names"]
    booleanize = model_data.get("booleanize", False)
    positive = model_data.get("positive", False)

    results = []

    with open(features_csv, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        for row in reader:
            # 构建特征向量
            feature_vec = [0] * len(feature_names)

            for feat in feature_names:
                if feat not in row:
                    continue
                try:
                    val = float(row[feat])
                except:
                    val = 0.0
                if positive and val < 0:
                    val = 0
                if booleanize:
                    val = 1 if val > 0 else 0
                idx = feature_names.index(feat)
                feature_vec[idx] = val

            # 调用分类器预测
            if hasattr(clf, "predict"):
                pred = clf.predict([feature_vec])[0]
                if pred == -1:  # one-class SVM 的异常检测输出
                    pred = "malicious"
                elif pred == 1 or pred == "benign":
                    pred = "benign"
                elif pred == "malicious":
                    pred = "malicious"
            else:
                pred = "benign"  # fallback

            results.append({
                "tarball": row["tarball"],
                "package_name": row["package_name"],
                "package_version": row["package_version"],
                "prediction": pred
            })

    # 写出预测结果
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["tarball", "package_name", "package_version", "prediction"])
        writer.writeheader()
        writer.writerows(results)

    print(f"✅ Predictions saved to {output_csv}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Predict malicious/benign from features CSV")
    parser.add_argument("model", help="Pickled model file (from training)")
    parser.add_argument("features_csv", help="CSV file with extracted features (all-features.csv)")
    parser.add_argument("-o", "--output", required=True, help="CSV file to save predictions")
    args = parser.parse_args()

    predict_from_bigcsv(args.model, args.features_csv, args.output)
