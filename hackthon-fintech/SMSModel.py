# hackthon-fintech
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

# Load dataset using exact Downloads path
file_path = r'C:\Users\hp\Downloads\spam_ham_india (2).csv'
df = pd.read_csv(file_path, encoding='latin-1')

# Map targets
df['target'] = df['Label'].map({'ham': 0, 'spam': 1})
df = df.dropna(subset=['Msg', 'target'])

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(df['Msg'], df['target'], test_size=0.2, random_state=42)

# TF-IDF
tfidf = TfidfVectorizer(stop_words='english', max_features=3000)
X_train_tfidf = tfidf.fit_transform(X_train)
X_test_tfidf = tfidf.transform(X_test)

# Logistic Regression
lr = LogisticRegression()
lr.fit(X_train_tfidf, y_train)
print("--- Logistic Regression ---")
print(f"Accuracy: {accuracy_score(y_test, lr.predict(X_test_tfidf)):.4f}")

# Random Forest
rf = RandomForestClassifier(n_estimators=100, random_state=42)
rf.fit(X_train_tfidf, y_train)
print("--- Random Forest ---")
print(f"Accuracy: {accuracy_score(y_test, rf.predict(X_test_tfidf)):.4f}")
import joblib

# Save the best model (Random Forest) and vectorizer
joblib.dump(rf, 'spam_model.pkl')
joblib.dump(tfidf, 'tfidf_vectorizer.pkl')

print("Model and vectorizer saved successfully!")

# Predict on a sample SMS
sample_sms = ["CONGRATULATIONS! You won a free gift card. Click link to claim."]
sample_tfidf = tfidf.transform(sample_sms)
prediction = rf.predict(sample_tfidf)

print("Result:", "Spam/Fraud" if prediction[0] == 1 else "Legitimatimate")