import pandas as pd
import numpy as np
import joblib

from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score
from xgboost import XGBClassifier

columns = [
"duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
"wrong_fragment","urgent","hot","num_failed_logins","logged_in",
"num_compromised","root_shell","su_attempted","num_root",
"num_file_creations","num_shells","num_access_files","num_outbound_cmds",
"is_host_login","is_guest_login","count","srv_count","serror_rate",
"srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
"diff_srv_rate","srv_diff_host_rate","dst_host_count",
"dst_host_srv_count","dst_host_same_srv_rate",
"dst_host_diff_srv_rate","dst_host_same_src_port_rate",
"dst_host_srv_diff_host_rate","dst_host_serror_rate",
"dst_host_srv_serror_rate","dst_host_rerror_rate",
"dst_host_srv_rerror_rate","label","difficulty"
]


train_data = pd.read_csv("data/KDDTrain+.txt", names=columns)
test_data = pd.read_csv("data/KDDTest+.txt", names=columns)

train_data.drop(columns=["difficulty"], inplace=True)
test_data.drop(columns=["difficulty"], inplace=True)

dos = ["back","land","neptune","pod","smurf","teardrop",
       "mailbomb","apache2","processtable","udpstorm"]

probe = ["satan","ipsweep","nmap","portsweep","mscan","saint"]

r2l = ["guess_passwd","ftp_write","imap","phf",
       "multihop","warezmaster","warezclient",
       "spy","xlock","xsnoop","snmpguess","snmpgetattack",
       "httptunnel","sendmail","named"]

u2r = ["buffer_overflow","loadmodule","rootkit",
       "perl","sqlattack","xterm","ps"]

def map_attack(label):
    if label == "normal":
        return "normal"
    elif label in dos:
        return "dos"
    elif label in probe:
        return "probe"
    elif label in r2l:
        return "r2l"
    elif label in u2r:
        return "u2r"
    else:
        return None   

train_data["label"] = train_data["label"].apply(map_attack)
test_data["label"] = test_data["label"].apply(map_attack)

train_data.dropna(subset=["label"], inplace=True)
test_data.dropna(subset=["label"], inplace=True)


le_label = LabelEncoder()

all_labels = pd.concat([train_data["label"], test_data["label"]])
le_label.fit(all_labels)

train_data["label"] = le_label.transform(train_data["label"])
test_data["label"] = le_label.transform(test_data["label"])


X_train = train_data.drop(columns=["label"])
y_train = train_data["label"]

X_test = test_data.drop(columns=["label"])
y_test = test_data["label"]

for col in ["src_bytes", "dst_bytes"]:
    X_train[col] = np.log1p(X_train[col])
    X_test[col] = np.log1p(X_test[col])


categorical_cols = ["protocol_type", "service", "flag"]
numerical_cols = [col for col in X_train.columns if col not in categorical_cols]

from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer


ohe_cols = ["protocol_type", "flag"]
le_col = "service"

ct = ColumnTransformer(
    [("ohe", OneHotEncoder(handle_unknown='ignore', sparse_output=False), ohe_cols)],
    remainder='passthrough'
)

le_service = LabelEncoder()
combined_service = pd.concat([X_train[le_col], X_test[le_col]])
le_service.fit(combined_service)
X_train[le_col] = le_service.transform(X_train[le_col])
X_test[le_col] = le_service.transform(X_test[le_col])

X_train_ohe = ct.fit_transform(X_train)
X_test_ohe = ct.transform(X_test)

ohe_feature_names = ct.get_feature_names_out()
X_train = pd.DataFrame(X_train_ohe, columns=ohe_feature_names)
X_test = pd.DataFrame(X_test_ohe, columns=ohe_feature_names)

numerical_cols = [col for col in X_train.columns if "ohe__" not in col and col != "remainder__service"]

from imblearn.over_sampling import SMOTE

smote = SMOTE(
    sampling_strategy={
        0: 67000,   # dos
        2: 20000,   # probe
        3: 15000,   # r2l
        4: 2000     # u2r 
    },
    random_state=42
)

X_train, y_train = smote.fit_resample(X_train, y_train)
print("After SMOTE class distribution:")
print(pd.Series(y_train).value_counts())

from sklearn.model_selection import RandomizedSearchCV

xgb_model = XGBClassifier(
    objective="multi:softprob",
    num_class=len(le_label.classes_),
    eval_metric="mlogloss",
    random_state=42
)

param_dist = {
    'n_estimators': [500, 700],
    'max_depth': [8, 10, 12],
    'learning_rate': [0.03, 0.05, 0.1],
    'subsample': [0.8, 0.9],
    'colsample_bytree': [0.8, 0.9]
}

random_search = RandomizedSearchCV(
    xgb_model, 
    param_distributions=param_dist, 
    n_iter=6, 
    cv=3, 
    scoring='f1_weighted', 
    verbose=1, 
    n_jobs=-1,
    random_state=42
)

random_search.fit(X_train, y_train)
model = random_search.best_estimator_

print(f"Best parameters: {random_search.best_params_}")


y_pred = model.predict(X_test)

print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n")
print(classification_report(y_test, y_pred, target_names=le_label.classes_))

joblib.dump(model, "model.pkl")
joblib.dump(le_label, "label_encoder.pkl")
joblib.dump(ct, "column_transformer.pkl")
joblib.dump(le_service, "service_encoder.pkl")

joblib.dump(X_test, "X_test.pkl")
joblib.dump(y_test, "y_test.pkl")

print("\nModel trained and saved successfully with all components.")