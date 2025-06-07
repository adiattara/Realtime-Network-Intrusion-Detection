# feature_engineering.py

import pandas as pd
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
import seaborn as sns

def nettoyer(df):
    df = df.drop(columns=['flow_key', 'start_ts', 'end_ts', 'window_start', 'window_end','urg_count'])
    return df
