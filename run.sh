# python ./code/training/feature_extractor.py --max_workers 1 --dataset C:/Users/Alan.lxt-redmi/Desktop/work/backstabber --out ./features/backstabber.csv
# python ./code/training/feature_extractor.py --max_workers 1 --dataset C:/Users/Alan.lxt-redmi/Desktop/deduplicate/backstabber_deduplicate --out ./features/backstabber_deduplicate.csv
# python ./code/training/feature_extractor.py --max_workers 1 --dataset C:/Users/Alan.lxt-redmi/Desktop/work/maloss --out ./features/maloss.csv
# python ./code/training/feature_extractor.py --max_workers 1 --dataset C:/Users/Alan.lxt-redmi/Desktop/deduplicate/maloss_deduplicate --out ./features/maloss_deduplicate.csv
# python ./code/training/feature_extractor.py --max_workers 1 --dataset C:/Users/Alan.lxt-redmi/Desktop/work/new --out ./features/new.csv
python ./code/training/feature_extractor.py --max_workers 1 --dataset C:/Users/Alan.lxt-redmi/Desktop/work/top10k/random2k --out ./features/10k_2k.csv
python ./code/training/feature_extractor.py --max_workers 1 --dataset C:/Users/Alan.lxt-redmi/Desktop/work/top10k/8k --out ./features/10k_8k.csv
python ./code/training/feature_extractor.py --max_workers 1 --dataset C:/Users/Alan.lxt-redmi/Desktop/work/DataDog --out ./features/datadog.csv




# python ./code/training/train_classifier.py random-forest ./features/train_true_value.csv ./features/train.csv -o model.pkl
# # python predict.py ./model.pkl ./features/datadog.csv -o datadog_predict.csv
# # echo "datadog done"
# # python ./calc.py ./datadog_predict.csv -m ./features/datadog_true_value.csv
# python predict.py ./model.pkl ./features/maloss.csv -o maloss_predict.csv
# echo "maloss done"
# python ./calc.py ./maloss_predict.csv -m ./features/maloss_true_value.csv
# python predict.py ./model.pkl ./features/new.csv -o new_predict.csv
# echo "new done"
# python ./calc.py ./new_predict.csv -m ./features/maloss_true_value.csv
# python predict.py ./model.pkl ./features/8k-6k.csv -o 8k_predict.csv
# echo "8k done"
# python ./calc.py ./8k_predict.csv -m ./features/maloss_true_value.csv

# python ./code/training/train_classifier.py random-forest ./features/train_true_value.csv ./features/train_deduplicate.csv -o model_deduplicate.pkl
# # python predict.py ./model_deduplicate.pkl ./features/datadog.csv -o datadog_deduplicate_predict.csv
# # echo "datadog done"
# # python ./calc.py ./datadog_deduplicate_predict.csv -m ./features/datadog_true_value.csv
# python predict.py ./model_deduplicate.pkl ./features/maloss.csv -o maloss_deduplicate_predict.csv
# echo "maloss done"
# python ./calc.py ./maloss_deduplicate_predict.csv -m ./features/maloss_true_value.csv
# python predict.py ./model_deduplicate.pkl ./features/new.csv -o new_deduplicate_predict.csv
# echo "new done"
# python ./calc.py ./new_deduplicate_predict.csv -m ./features/maloss_true_value.csv
# python predict.py ./model_deduplicate.pkl ./features/8k-6k.csv -o 8k_deduplicate_predict.csv
# echo "8k done"
# python ./calc.py ./8k_deduplicate_predict.csv -m ./features/maloss_true_value.csv

# python ./code/training/train_classifier.py random-forest ./features/train_true_value.csv ./features/train_deduplicate_notbalance.csv -o model_deduplicate_notbalance.pkl
# # python predict.py ./model_deduplicate_notbalance.pkl ./features/datadog.csv -o datadog_deduplicate_notbalance_predict.csv
# # echo "datadog done"
# # python ./calc.py ./datadog_deduplicate_notbalance_predict.csv -m ./features/datadog_true_value.csv
# python predict.py ./model_deduplicate_notbalance.pkl ./features/maloss.csv -o maloss_deduplicate_notbalance_predict.csv
# echo "maloss done"
# python ./calc.py ./maloss_deduplicate_notbalance_predict.csv -m ./features/maloss_true_value.csv
# python predict.py ./model_deduplicate_notbalance.pkl ./features/new.csv -o new_deduplicate_notbalance_predict.csv
# echo "new done"
# python ./calc.py ./new_deduplicate_notbalance_predict.csv -m ./features/maloss_true_value.csv
# python predict.py ./model_deduplicate_notbalance.pkl ./features/8k-6k.csv -o 8k_deduplicate_notbalance_predict.csv
# echo "8k done"
# python ./calc.py ./8k_deduplicate_notbalance_predict.csv -m ./features/maloss_true_value.csv


# python ./code/training/train_classifier.py random-forest ./features/train_true_value.csv ./features/train_deduplicate_notbalance_5k.csv -o model_deduplicate_notbalance_5k.pkl
# python predict.py ./model_deduplicate_notbalance_5k.pkl ./features/maloss.csv -o maloss_deduplicate_notbalance_5k_predict.csv
# echo "maloss done"
# python ./calc.py ./maloss_deduplicate_notbalance_5k_predict.csv -m ./features/maloss_true_value.csv
# python predict.py ./model_deduplicate_notbalance_5k.pkl ./features/new.csv -o new_deduplicate_notbalance_5k_predict.csv
# echo "new done"
# python ./calc.py ./new_deduplicate_notbalance_5k_predict.csv -m ./features/maloss_true_value.csv
# python predict.py ./model_deduplicate_notbalance_5k.pkl ./features/8k-6k.csv -o 8k_deduplicate_notbalance_5k_predict.csv
# echo "8k done"
# python ./calc.py ./8k_deduplicate_notbalance_5k_predict.csv -m ./features/maloss_true_value.csv
