import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.multioutput import MultiOutputClassifier
import joblib

file_name = r"\training\train_set_after.csv"
data = pd.read_csv(file_name, low_memory=False)

X = data.iloc[:, :-2]  

y = data.iloc[:, -2:]  

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

dt_model = DecisionTreeClassifier(random_state=42)
rf_model = MultiOutputClassifier(RandomForestClassifier(random_state=42))

dt_model.fit(X_train, y_train)
rf_model.fit(X_train, y_train)



model_file = "decision_tree_model.pkl"
joblib.dump(dt_model, model_file)

model_file = "random_forest_model.pkl"
joblib.dump(rf_model, model_file)
