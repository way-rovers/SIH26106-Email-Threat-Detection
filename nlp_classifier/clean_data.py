import pandas as pd
import re
import os

DATA_DIR = "nlp_classifier/data"

def clean_text(text):
    text = re.sub(r"<[^>]+>", " ", text)          # strip HTML tags
    text = re.sub(r"http\S+|www\.\S+", " URL ", text)  # normalize URLs
    text = re.sub(r"\s+", " ", text)               # collapse whitespace
    return text.strip().lower()

df = pd.read_csv(os.path.join(DATA_DIR, "combined.csv"))
df["body_text"] = df["body_text"].apply(clean_text)
df = df[df["body_text"].str.len() > 10]  # drop near-empty rows

print("Rows after cleaning:", len(df))
print(df["label"].value_counts())

out_path = os.path.join(DATA_DIR, "cleaned.csv")
df.to_csv(out_path, index=False)
print("Saved to", out_path)