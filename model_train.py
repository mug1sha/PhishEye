# Train a basic logistic regression on synthetic URL features
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
import joblib
from analyzer import extract_features


# load sample data
df = pd.read_csv('data/sample_urls.csv')


# simple feature extraction
X = []
for url in df['url']:
    X.append(extract_features(url))


y = df['label']


X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)


clf = LogisticRegression(max_iter=1000)
clf.fit(X_train, y_train)


pred = clf.predict(X_test)
probs = clf.predict_proba(X_test)[:, 1]


print(classification_report(y_test, pred))
print('AUC:', roc_auc_score(y_test, probs))


joblib.dump(clf, 'model.pkl')
print('Saved model to model.pkl')
