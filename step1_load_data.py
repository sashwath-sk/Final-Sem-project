import pandas as pd

# 1. Load the dataset
print("Loading dataset... this might take a second.")
df = pd.read_csv('phishing_site_urls.csv')

# 2. Check the first 5 rows
print("\n--- First 5 Rows ---")
print(df.head())

# 3. Check the balance (How many Safe vs. Bad?)
print("\n--- Label Distribution ---")
print(df['Label'].value_counts())

# 4. Check for missing values
print("\n--- Missing Values ---")
print(df.isnull().sum())