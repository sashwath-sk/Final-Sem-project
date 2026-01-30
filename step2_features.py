import pandas as pd
import re
from urllib.parse import urlparse
from Levenshtein import distance as lev_distance
import tldextract

# 1. Load the data
print("Loading data... (This might take 10-20 seconds)")
df = pd.read_csv('phishing_site_urls.csv')

# --- CONFIG: Targeted Brands for Typosquatting ---
# We check if the URL looks "almost" like these but isn't exact.
TARGET_BRANDS = ['google.com', 'paypal.com', 'facebook.com', 'microsoft.com', 'apple.com', 'amazon.com']

def extract_features(url):
    features = {}
    
    # Clean URL slightly to avoid parsing errors
    if not isinstance(url, str):
        url = str(url)
    
    # A. Parse the URL
    try:
        parsed = urlparse(url)
        # If no scheme (http/https), urlparse treats everything as path. Fix:
        if not parsed.netloc:
            parsed = urlparse('http://' + url)
    except:
        return None # Skip broken URLs

    hostname = parsed.netloc
    path = parsed.path

    # --- FEATURE 1-3: Lengths ---
    features['url_length'] = len(url)
    features['hostname_length'] = len(hostname)
    features['path_length'] = len(path)

    # --- FEATURE 4: Structure ---
    features['dot_count'] = url.count('.')
    features['at_symbol'] = 1 if '@' in url else 0
    features['dash_symbol'] = 1 if '-' in hostname else 0
    features['directory_count'] = path.count('/')

    # --- FEATURE 5: Abnormal content ---
    # Does it use an IP address instead of a domain?
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    features['has_ip'] = 1 if re.search(ip_pattern, hostname) else 0
    
    # Is 'https' hidden in the text part? (e.g. http://paypal-https-secure.com)
    features['https_in_text'] = 1 if 'https' in hostname else 0

    # --- FEATURE 6: Typosquatting (The Advanced Logic) ---
    # Calculate Levenshtein distance to top brands
    # If distance is small (1-3) but not 0, it's likely a fake copy.
    min_dist = 100
    for brand in TARGET_BRANDS:
        # Extract main domain (e.g. 'google' from 'mail.google.com')
        extracted = tldextract.extract(hostname)
        main_domain = f"{extracted.domain}.{extracted.suffix}"
        
        dist = lev_distance(main_domain, brand)
        if dist < min_dist:
            min_dist = dist
            
    features['min_levenshtein_dist'] = min_dist

    return features

# 2. Apply the extraction (The heavy lifting)
print("Extracting features from 500k URLs... this will take about 2-3 minutes.")
print("Grab a coffee ☕")

# Apply function to every row
feature_df = df['URL'].apply(lambda x: pd.Series(extract_features(x)))

# 3. Combine with Labels
# Convert 'bad' to 1 and 'good' to 0
df['target'] = df['Label'].apply(lambda x: 1 if x == 'bad' else 0)

# Merge features with the target label
final_df = pd.concat([feature_df, df['target']], axis=1)

# 4. Save processed data
print("Saving processed data...")
final_df.to_csv('processed_data.csv', index=False)
print("✅ DONE! Data saved as 'processed_data.csv'")
print(final_df.head())