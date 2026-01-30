import pandas as pd
import pickle  # <--- CHANGED FROM JOBLIB
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

# 1. Load Data
print("Loading processed data...")
df = pd.read_csv('processed_data.csv')
df = df.dropna()

X = df.drop('target', axis=1)
y = df['target']

# 2. Split
print("Splitting data...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 3. Train
print("Training Random Forest... (This might take 1-2 minutes)")
model = RandomForestClassifier(n_estimators=50, max_depth=20, n_jobs=-1, random_state=42)
model.fit(X_train, y_train)

# 4. Evaluate
print("Evaluating...")
y_pred = model.predict(X_test)
print(f"✅ Accuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%")

# 5. Save with PICKLE (Built-in)
print("Saving model...")
with open('phishing_model.pkl', 'wb') as file:  # <--- CHANGED
    pickle.dump(model, file)
    
print("✅ Model saved as 'phishing_model.pkl' using Pickle")