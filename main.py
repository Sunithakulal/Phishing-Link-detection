import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import pickle

# Load CSV
df = pd.read_csv("phishing.csv")

# Convert 'class' to binary label
df['label'] = df['class'].apply(lambda x: 1 if x == 1 else 0)

# Drop non-feature columns
X = df.drop(['Index', 'class', 'label'], axis=1)
y = df['label']

# Train/Test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = RandomForestClassifier()
model.fit(X_train, y_train)

# Predict
y_pred = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))

# ✅ Save model
with open("model.pkl", "wb") as file:
    pickle.dump(model, file)
