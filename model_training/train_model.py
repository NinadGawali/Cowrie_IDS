import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# -----------------------------
# Feature Extraction Function
# -----------------------------
def extract_features(cmd):
    cmd = cmd.lower()

    return [
        len(cmd),
        int("wget" in cmd),
        int("curl" in cmd),
        int("cat" in cmd),
        int("sudo" in cmd),
        int("chmod" in cmd),
        int("nc" in cmd),
        int("bash" in cmd or "sh" in cmd),
        int("/etc/passwd" in cmd),
        int("crontab" in cmd or "@reboot" in cmd),
        int("python" in cmd or "perl" in cmd or "php" in cmd),
        cmd.count(" "),
        cmd.count("/"),
    ]


# -----------------------------
# Load Dataset
# -----------------------------
df = pd.read_csv("dataset_commands_advanced.csv")

# Convert commands → features
X = df["command"].apply(extract_features).tolist()
y = df["label"]

# -----------------------------
# Train/Test Split
# -----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# -----------------------------
# Train Model
# -----------------------------
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# -----------------------------
# Evaluate
# -----------------------------
y_pred = model.predict(X_test)

print("\n📊 Classification Report:\n")
print(classification_report(y_test, y_pred))

# -----------------------------
# Save Model
# -----------------------------
joblib.dump(model, "model.pkl")

print("\n✅ Model trained and saved as model.pkl")