import pandas as pd

files = ["CEAS_08.csv", "Enron.csv", "Nazario.csv", "SpamAssasin.csv",
         "Nigerian_Fraud.csv", "Ling.csv", "phishing_email.csv"]

for f in files:
    df = pd.read_csv(f"nlp_classifier/data/{f}")
    print(f, "->", df["label"].unique())