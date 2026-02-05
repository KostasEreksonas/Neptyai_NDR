# Neptyai_NDR
Infrastructure, ML/DL workflows, UI

Start Jupyter notebook with `uv run jupyter notebook`

# Comprehensive Exploratory Data Analysis (EDA) for the UWF Zeek Dataset

## Overview of the UWF Zeek Dataset

The University of West Florida (UWF) hosts several Zeek-based network traffic datasets at [datasets.uwf.edu](https://datasets.uwf.edu/), including UWF-ZeekData22, UWF-ZeekDataFall22, and UWF-ZeekData24 [cite:page:0]. These datasets are labeled using the **MITRE ATT&CK Framework**, making them particularly valuable for cybersecurity research and intrusion detection system (IDS) development [cite:web:11][cite:web:15].

The datasets contain Zeek Connection Logs (conn.log) collected using Security Onion 2 network security monitor, available in both PCAP and Parquet formats, with CSV subsets for accessibility [cite:page:0]. The CSV files contain approximately 1 million rows with an 80/20 benign/attack ratio, primarily focusing on Reconnaissance and Discovery tactics [cite:page:0].

---

## Dataset Structure and Key Features

### Core Zeek conn.log Fields

The UWF datasets contain approximately 24 columns derived from Zeek's connection logs [cite:web:23]. The essential fields include:

| Field | Type | Description |
|-------|------|-------------|
| `ts` | timestamp | Connection start time [cite:web:72] |
| `uid` | string | Unique connection identifier [cite:web:72] |
| `id.orig_h` | IP address | Source/originator IP [cite:web:72] |
| `id.orig_p` | port | Source port [cite:web:72] |
| `id.resp_h` | IP address | Destination/responder IP [cite:web:72] |
| `id.resp_p` | port | Destination port [cite:web:72] |
| `proto` | enum | Protocol (TCP, UDP, ICMP) [cite:web:72] |
| `service` | string | Detected application protocol (HTTP, DNS, etc.) [cite:web:72] |
| `duration` | interval | Connection duration [cite:web:72] |
| `orig_bytes` | count | Bytes sent by originator [cite:web:72] |
| `resp_bytes` | count | Bytes sent by responder [cite:web:72] |
| `conn_state` | string | Connection state code (SF, S0, REJ, etc.) [cite:web:72] |
| `missed_bytes` | count | Bytes missed during capture [cite:web:72] |
| `history` | string | Connection state history [cite:web:72] |
| `orig_pkts` | count | Packets from originator [cite:web:72] |
| `resp_pkts` | count | Packets from responder [cite:web:72] |

### MITRE ATT&CK Labels

The dataset includes attack tactic labels aligned with the MITRE ATT&CK framework, primarily covering:
- **Reconnaissance** - Information gathering tactics
- **Discovery** - Techniques to explore the environment
- **Benign** - Normal network traffic [cite:page:0]

---

## Recommended EDA Workflow

### Phase 1: Data Loading and Initial Assessment

```python
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

# Load the dataset
df = pd.read_csv('zeek_data.csv')

# Basic inspection
print(df.shape)
print(df.info())
print(df.describe())
print(df.head())
```

**Key assessments:**
- Check dataset dimensions and memory usage
- Identify data types for each column
- Generate descriptive statistics for numerical features [cite:web:57]

### Phase 2: Data Quality Assessment

**Missing Value Analysis:**
- Check for unset fields (represented as `-` in Zeek logs) [cite:web:69]
- Identify the percentage of missing values per column
- Visualize missing patterns using heatmaps

```python
# Missing value analysis
missing = df.isnull().sum() / len(df) * 100
missing_df = pd.DataFrame({'Column': missing.index, 'Missing %': missing.values})
missing_df = missing_df[missing_df['Missing %'] > 0].sort_values('Missing %', ascending=False)
```

**Duplicate Detection:**
- Check for duplicate connection records
- Verify UID uniqueness (should be unique per connection) [cite:web:82]

### Phase 3: Class Distribution Analysis

The UWF Zeek datasets exhibit significant **class imbalance**, which is a common challenge in cybersecurity datasets [cite:web:52][cite:web:55]. The data maintains approximately an 80/20 benign-to-attack ratio [cite:page:0].

```python
# Target class distribution
class_dist = df['label'].value_counts()
plt.figure(figsize=(10, 6))
sns.barplot(x=class_dist.index, y=class_dist.values)
plt.title('Attack Tactic Distribution')
plt.xlabel('Tactic')
plt.ylabel('Count')
plt.xticks(rotation=45)
plt.tight_layout()
```

**Important considerations:**
- Reconnaissance and Discovery tactics dominate the attack labels
- Other tactics have very low representation due to Excel row limitations [cite:page:0]
- Document the imbalance ratio for later resampling strategies [cite:web:52]

### Phase 4: Feature Analysis

#### Numerical Features

Analyze continuous variables: `duration`, `orig_bytes`, `resp_bytes`, `orig_pkts`, `resp_pkts`, `missed_bytes` [cite:web:75].

```python
numerical_cols = ['duration', 'orig_bytes', 'resp_bytes', 'orig_pkts', 'resp_pkts']

# Distribution plots
fig, axes = plt.subplots(2, 3, figsize=(15, 10))
for idx, col in enumerate(numerical_cols):
    ax = axes[idx // 3, idx % 3]
    df[col].hist(bins=50, ax=ax, log=True)
    ax.set_title(f'{col} Distribution (log scale)')
```

**Key observations to make:**
- Zeek conn logs contain continuous, nominal, IP addresses, and port numbers requiring different preprocessing approaches [cite:web:20]
- Connection features often have heavy-tailed distributions requiring log transformation or binning [cite:web:20]
- Use trimmed mean and standard deviation (10% trim recommended) to handle skewness [cite:web:20]

#### Categorical Features

Analyze protocol, service, and connection state distributions:

```python
# Protocol distribution
protocol_dist = df['proto'].value_counts()
plt.figure(figsize=(8, 6))
plt.pie(protocol_dist.values, labels=protocol_dist.index, autopct='%1.1f%%')
plt.title('Protocol Distribution')
```

**Connection State Analysis:**
| State | Meaning |
|-------|---------|
| SF | Normal, connection established and terminated |
| S0 | Connection attempt, no reply |
| REJ | Connection rejected |
| RSTO | Connection reset by originator |
| RSTR | Connection reset by responder [cite:web:71] |

### Phase 5: Correlation Analysis

Generate correlation heatmaps to identify relationships between features [cite:web:57]:

```python
# Correlation matrix for numerical features
plt.figure(figsize=(12, 10))
correlation_matrix = df[numerical_cols].corr()
sns.heatmap(correlation_matrix, annot=True, fmt='.2f', cmap='coolwarm', 
            linewidths=0.5, center=0)
plt.title('Feature Correlation Heatmap')
```

**Expected correlations:**
- `orig_bytes` and `orig_pkts` (positive correlation)
- `resp_bytes` and `resp_pkts` (positive correlation)
- `duration` with byte/packet counts (variable correlation)

### Phase 6: Temporal Pattern Analysis

The timestamp field (`ts`) enables time-series analysis [cite:web:86]:

```python
# Convert timestamp
df['ts'] = pd.to_datetime(df['ts'], unit='s')
df['hour'] = df['ts'].dt.hour
df['day_of_week'] = df['ts'].dt.dayofweek

# Hourly traffic patterns
hourly_traffic = df.groupby(['hour', 'label']).size().unstack(fill_value=0)
hourly_traffic.plot(kind='bar', stacked=True, figsize=(12, 6))
plt.title('Traffic Volume by Hour and Attack Type')
plt.xlabel('Hour of Day')
plt.ylabel('Connection Count')
```

The UWF dataset covers specific time periods (Feb 10, 2022, hours 3-5, 9, and 14), which should be noted for temporal analysis [cite:page:0].

### Phase 7: Network Behavior Profiling

#### IP Address Analysis

```python
# Top source IPs
top_sources = df['id.orig_h'].value_counts().head(20)

# Top destination IPs
top_destinations = df['id.resp_h'].value_counts().head(20)

# Unique connections per source
connections_per_source = df.groupby('id.orig_h').size().describe()
```

#### Port Analysis

Analyze destination port distributions to identify targeted services:

```python
# Common destination ports
port_dist = df['id.resp_p'].value_counts().head(30)
plt.figure(figsize=(12, 6))
sns.barplot(x=port_dist.index, y=port_dist.values)
plt.xticks(rotation=45)
plt.title('Top Destination Ports')
plt.xlabel('Port')
plt.ylabel('Connection Count')
```

**Common ports in network traffic:**
- 80 (HTTP)
- 443 (HTTPS)
- 53 (DNS)
- 3389 (RDP)
- 22 (SSH)

### Phase 8: Attack Pattern Analysis

Compare feature distributions between benign and malicious traffic:

```python
# Feature comparison by class
fig, axes = plt.subplots(2, 2, figsize=(14, 12))

for idx, feature in enumerate(['duration', 'orig_bytes', 'resp_bytes', 'orig_pkts']):
    ax = axes[idx // 2, idx % 2]
    for label in df['label'].unique():
        subset = df[df['label'] == label][feature]
        ax.hist(subset, bins=50, alpha=0.5, label=label, log=True)
    ax.set_title(f'{feature} by Attack Type')
    ax.legend()
```

---

## Handling Class Imbalance

The severe class imbalance in cybersecurity datasets requires specific techniques [cite:web:52][cite:web:55]:

### Resampling Strategies

1. **SMOTE (Synthetic Minority Over-Sampling Technique)** - Generates synthetic samples for minority classes [cite:web:55]
2. **BSMOTE (Borderline-SMOTE)** - Focuses on boundary samples [cite:web:11]
3. **SVM-SMOTE** - Uses SVM to guide sample generation [cite:web:11]
4. **Tomek Links** - Under-sampling method to remove noisy majority samples [cite:web:55]

```python
from imblearn.over_sampling import SMOTE
from imblearn.combine import SMOTETomek

# Apply SMOTE + Tomek Links combination
smote_tomek = SMOTETomek(random_state=42)
X_resampled, y_resampled = smote_tomek.fit_resample(X, y)
```

### Cost-Sensitive Learning

Assign different misclassification penalties to favor minority class detection [cite:web:52].

---

## Feature Engineering Recommendations

### Derived Features

Create new features to enhance model performance [cite:web:85]:

1. **Bytes per packet:**
   ```python
   df['bytes_per_pkt_orig'] = df['orig_bytes'] / (df['orig_pkts'] + 1)
   df['bytes_per_pkt_resp'] = df['resp_bytes'] / (df['resp_pkts'] + 1)
   ```

2. **Traffic ratio:**
   ```python
   df['traffic_ratio'] = df['orig_bytes'] / (df['resp_bytes'] + 1)
   ```

3. **Packet ratio:**
   ```python
   df['pkt_ratio'] = df['orig_pkts'] / (df['resp_pkts'] + 1)
   ```

4. **Connection volume features:**
   ```python
   df['total_bytes'] = df['orig_bytes'] + df['resp_bytes']
   df['total_pkts'] = df['orig_pkts'] + df['resp_pkts']
   ```

### Encoding Strategies

For preprocessing Zeek data for machine learning [cite:web:20]:

1. **Binning continuous attributes** using trimmed statistics to handle skewness
2. **One-hot encoding** for categorical variables (protocol, service, conn_state)
3. **IP address encoding** - Convert to numerical or use embedding techniques
4. **Port categorization** - Group into well-known (0-1023), registered (1024-49151), and dynamic (49152-65535)

---

## Visualization Summary

| Visualization Type | Purpose | Features |
|-------------------|---------|----------|
| Histograms | Distribution analysis | All numerical features |
| Box plots | Outlier detection | duration, bytes, packets |
| Bar charts | Class distribution | attack labels |
| Heatmaps | Correlation analysis | All numerical features |
| Scatter plots | Relationship exploration | bytes vs. packets, duration vs. bytes |
| Time series | Temporal patterns | timestamp-based aggregations |
| Pie charts | Protocol/service breakdown | proto, service |
| Network graphs | Connection patterns | IP relationships [cite:web:48] |

---

## Tools and Libraries

**Recommended Python stack for Zeek EDA:**
- **pandas** - Data manipulation and analysis [cite:web:83]
- **numpy** - Numerical computations
- **matplotlib** - Basic visualizations [cite:web:57]
- **seaborn** - Statistical visualizations [cite:web:57]
- **plotly** - Interactive visualizations [cite:web:63]
- **scikit-learn** - Preprocessing and machine learning
- **imbalanced-learn** - Resampling techniques

**For large-scale analysis:**
- **Apache Spark** - Distributed processing (used in UWF research) [cite:web:11]
- **Zeek Analysis Toolkit (ZAT)** - Specialized Zeek log analysis [cite:web:22]

---

## Key Insights from Prior Research

Research on the UWF-ZeekData22 dataset has revealed [cite:web:20]:

1. **Algorithm performance varies by feature set** - Decision Tree, Gradient Boosted Trees, and Random Forest consistently outperform SVM, Naive Bayes, and Logistic Regression for all feature subsets
2. **Recall patterns differ** - GBT, NB, and LR show higher recall across feature sets for Discovery tactics
3. **Feature importance** - Traffic volume, packet timing, and protocol characteristics are most effective for attack classification [cite:web:1]
4. **Graph-based analysis** - Using only three graph features (in-degree, out-degree, PageRank), effective node classification is achievable [cite:web:48]

---

## References to Cite

When using the UWF datasets, citation of the original research is required [cite:page:0]:

- [Bagui, S.S., et al. (2023). "Introducing UWF-ZeekData22: A Comprehensive Network Traffic Dataset Based on the MITRE ATT&CK Framework." *Data*, 8(1), 18.](https://www.mdpi.com/2306-5729/8/1/18)
- [Bagui, S.S., et al. (2022). "Detecting Reconnaissance and Discovery Tactics from the MITRE ATT&CK Framework in Zeek Conn Logs Using Spark's Machine Learning in the Big Data Framework." *Sensors*, 22(20), 7999.](https://www.mdpi.com/2079-9292/12/24/5039)
- [Elam, M., et al. (2025). "Introducing UWF-ZeekData24: An Enterprise MITRE ATT&CK Labeled Network Attack Traffic Dataset for Machine Learning/AI." *Data*, 10(5), 59.](https://www.mdpi.com/2306-5729/10/5/59)
