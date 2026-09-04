import pandas as pd
import os

DATA_DIR = "nlp_classifier/data"

FILES = {
    "CEAS_08.csv": "body",
    "Enron.csv": "body",
    "Nazario.csv": "body",
    "SpamAssasin.csv": "body",
    "Nigerian_Fraud.csv": "body",
    "Ling.csv": "body",
    "phishing_email.csv": "text_combined",
}

frames = []

for filename, text_col in FILES.items():
    path = os.path.join(DATA_DIR, filename)
    df = pd.read_csv(path)
    df = df[[text_col, "label"]].rename(columns={text_col: "body_text"})
    df["source"] = filename
    frames.append(df)

combined = pd.concat(frames, ignore_index=True)
combined = combined.dropna(subset=["body_text"])
combined["body_text"] = combined["body_text"].astype(str)
combined = combined.drop_duplicates(subset=["body_text"])

print("Total rows:", len(combined))
print(combined["label"].value_counts())

out_path = os.path.join(DATA_DIR, "combined.csv")
combined.to_csv(out_path, index=False)
print("Saved to", out_path)