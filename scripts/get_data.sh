#!/usr/bin/env bash
# Downloads the public "Phishing_Email.csv" dataset (18,650 emails: 11,322 safe / 7,328 phishing; Kaggle
# "Phishing Email Detection" by Subhajournal, mirrored on GitHub) into data/real/.
# You can drop more CSVs into data/real/ (e.g. Kaggle naserabdullahalam/phishing-email-dataset:
# CEAS_08.csv, Nazario.csv, Nigerian_Fraud.csv, SpamAssassin.csv, Enron.csv, Ling.csv) -- the loader
# auto-detects their columns.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p data/real
curl -fL -o data/real/Phishing_Email.csv \
  "https://raw.githubusercontent.com/uzmabb182/Data_622/refs/heads/main/final_project_data_622/Phishing_Email.csv"
echo "saved data/real/Phishing_Email.csv"
