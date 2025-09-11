#! /usr/bin/env python3

import argparse
import csv
import os
import pickle
import random
from datetime import timedelta
from timeit import default_timer as timer

from graphviz import Source
from sklearn import naive_bayes, svm, tree
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix)
from sklearn.model_selection import train_test_split
from util import parse_date  

CONTINUOUS_FEATURES = ["entropy_average", "entropy_std_dev", "time"]


def train_classifier_from_bigcsv(classifier, malicious_path, features_csv, output,
                                 booleanize=False, hashing=False, exclude_features=None,
                                 nu=0.001, positive=False, render=False,
                                 randomize=False, view=False, until=None, performance=None):

    if exclude_features is None:
        exclude_features = []

    if classifier == "naive-bayes":
        booleanize = True

    if booleanize:
        exclude_features.extend(CONTINUOUS_FEATURES)

    feature_names = []
    training_set = []
    labels = []

    # 读取恶意标注 (package, version)
    malicious = set()
    with open(malicious_path, "r") as mal:
        reader = csv.reader(mal)
        for row in reader:
            if hashing:
                malicious.add(row[0])
            else:
                package, version = row
                malicious.add((package, version))

    if randomize:
        malicious_len = 0

    with open(features_csv, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            package = row["package_name"]
            version = row["package_version"]

            feature_dict = {}
            for k, v in row.items():
                if k in ["tarball", "package_name", "package_version"]:
                    continue
                try:
                    value = float(v)
                except:
                    value = 0.0
                if positive and value < 0:
                    value = 0
                if booleanize and k not in exclude_features:
                    value = 1 if value > 0 else 0
                if k not in exclude_features:
                    feature_dict[k] = value

            for feat in feature_dict.keys():
                if feat not in feature_names:
                    feature_names.append(feat)

            feature_vec = [0] * len(feature_names)
            for feat, val in feature_dict.items():
                idx = feature_names.index(feat)
                feature_vec[idx] = val

            training_set.append(feature_vec)

            label = "benign"
            if hashing:
                # TODO:
                pass
            else:
                if (package, version) in malicious:
                    label = "malicious"

            labels.append(label)
            if label == "malicious" and randomize:
                malicious_len += 1

    num_features = len(feature_names)
    for vec in training_set:
        if len(vec) < num_features:
            vec.extend([0] * (num_features - len(vec)))

    if randomize:
        benign_indices = [i for i, lab in enumerate(labels) if lab == "benign"]
        benign_selected = random.sample(benign_indices, malicious_len)
        training_set = [s for i, s in enumerate(training_set) if i in benign_selected or labels[i] == "malicious"]
        labels = [lab for i, lab in enumerate(labels) if i in benign_selected or lab == "malicious"]

    X_train, X_test, y_train, y_test = train_test_split(training_set, labels, test_size=0.2, random_state=42, stratify=labels)

    start = timer()
    if classifier == "decision-tree":
        clf = tree.DecisionTreeClassifier(criterion="entropy")
        clf.fit(X_train, y_train)
    elif classifier == "random-forest":
        clf = RandomForestClassifier(criterion="entropy")
        clf.fit(X_train, y_train)
    elif classifier == "naive-bayes":
        clf = naive_bayes.BernoulliNB()
        clf.fit(X_train, y_train)
    else:  # SVM
        clf = svm.OneClassSVM(gamma='scale', nu=nu, kernel='linear')
        clf.fit([datum for i, datum in enumerate(training_set) if labels[i] == "benign"])
    end = timer()

    if performance:
        with open(performance, "a+") as pf:
            writer = csv.writer(pf)
            writer.writerow([timedelta(seconds=end-start)])

    if classifier == "decision-tree" and render:
        file, ext = os.path.splitext(render)
        if ext != ".png":
            print("Rendering tree to PNG requires a .png extension")
        else:
            outfile = Source(tree.export_graphviz(clf, out_file=None, feature_names=feature_names), format="png")
            outfile.render(file, view=view, cleanup=True)

    y_pred = clf.predict(X_test)
    if classifier != "svm":
        print("Confusion Matrix:")
        print(confusion_matrix(y_test, y_pred))
        print("Classification Report:")
        print(classification_report(y_test, y_pred))
        print("Accuracy:", accuracy_score(y_test, y_pred))
    else:
        mapped_pred = ["malicious" if v == -1 else "benign" for v in y_pred]
        print(classification_report(y_test, mapped_pred))
        print("Accuracy:", accuracy_score(y_test, mapped_pred))
        print("SVM prediction counts:", {label: mapped_pred.count(label) for label in set(mapped_pred)})

    with open(output, "wb") as f:
        pickle.dump({
            "feature_names": feature_names,
            "booleanize": booleanize,
            "positive": positive,
            "classifier": clf
        }, f)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train classifier from all-features.csv")
    parser.add_argument("classifier", choices=["decision-tree", "random-forest", "naive-bayes", "svm"])
    parser.add_argument("malicious", help="CSV with malicious package,version pairs")
    parser.add_argument("features_csv", help="The big CSV file with features for all tarballs")
    parser.add_argument("-o", "--output", required=True, help="Pickled model file")
    parser.add_argument("-b", "--booleanize", choices=["true", "false"], default="false")
    parser.add_argument("--hashing", choices=["true", "false"], default="false")
    parser.add_argument("-x", "--exclude-features", nargs="*", default=[])
    parser.add_argument("-n", "--nu", type=float, default=0.001)
    parser.add_argument("-p", "--positive", choices=["true", "false"], default="false")
    parser.add_argument("-r", "--render", help="Render decision tree to PNG", required=False)
    parser.add_argument("--randomize", choices=["true", "false"], default="false")
    parser.add_argument("-v", "--view", action="store_true")
    parser.add_argument("-u", "--until", default="2100-01-01T00:00:00.000Z")
    parser.add_argument("--performance", help="CSV to log training time")

    args = parser.parse_args()
    booleanize = args.booleanize == "true"
    hashing = args.hashing == "true"
    positive = args.positive == "true"
    randomize = args.randomize == "true"
    until = parse_date(args.until)

    train_classifier_from_bigcsv(args.classifier, args.malicious, args.features_csv,
                                 args.output, booleanize, hashing, args.exclude_features,
                                 args.nu, positive, args.render, randomize, args.view, until,
                                 args.performance)
