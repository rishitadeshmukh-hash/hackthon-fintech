# hackthon-fintech
Fintech_hackthon_project
import pandas as pd

# Load dataset (using UCI SMS dataset as example)
df = pd.read_csv('spam.csv', encoding='latin-1')

# Map targets: 'ham' -> 0 (Legitimate), 'spam' -> 1 (Fraud/Spam)
df['label'] = df['v1'].map({'ham': 0, 'spam': 1})
df['text'] = df['v2']

# Final clean format
data = df[['text', 'label']]
print(data.head())