import pandas as pd
from scipy.io import arff

# load ARFF dataset
data = arff.loadarff("datasets/Training Dataset.arff")

df = pd.DataFrame(data[0])

# convert byte columns to string
for col in df.select_dtypes([object]):
    df[col] = df[col].apply(lambda x: x.decode("utf-8"))

# save as CSV
df.to_csv("datasets/phishing.csv", index=False)

print("Dataset converted successfully")
print("Shape:", df.shape)
print(df.head())