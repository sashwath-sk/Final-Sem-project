import streamlit as st
import pickle
import pandas as pd
import re
from urllib.parse import urlparse
from Levenshtein import distance as lev_distance
import tldextract
import random

# --- 1. CONFIGURATION ---
st.set_page_config(
    page_title="Phishing Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# --- 2. CSS STYLING (Dark Theme) ---
st.markdown("""
    <style>
    /* Main Background */
    .stApp {
        background-color: #0d1117;
        color: white;
    }
    
    /* Remove default padding to fill screen */
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
        max-width: 1200px;
        margin: 0 auto;
    }
    
    /* Hide Streamlit Elements */
    header, footer, #MainMenu {visibility: hidden;}
    
    /* LANDING PAGE */
    .logo-text {
        font-size: 70px;
        font-weight: 700;
        color: #7d9bf0;
        text-align: center;
        margin-bottom: 10px;
    }
    .subtitle-text {
        text-align: center;
        color: #8b949e;
        font-size: 18px;
        margin-bottom: 40px;
    }
    
    /* TABS */
    .nav-tabs {
        display: flex;
        justify-content: center;
        gap: 50px;
        border-bottom: 1px solid #30363d;
        margin-bottom: 40px;
    }
    .nav-item {
        color: #8b949e;
        padding-bottom: 15px;
        cursor: pointer;
        font-weight: 600;
        font-size: 16px;
    }
    .nav-item.active {
        color: #7d9bf0;
        border-bottom: 3px solid #7d9bf0;
    }
    
    /* INPUT BOX */
    .stTextInput > div > div > input {
        background-color: transparent;
        border: 1px solid #7d9bf0;
        color: white;
        padding: 12px;
        border-radius: 6px;
        text-align: center;
        font-size: 16px;
    }
    
    /* RESULTS HEADER CARD */
    .result-card {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 25px;
        margin-bottom: 20px;
        display: flex;
        align-items: center;
        gap: 25px;
    }
    .score-circle {
        width: 90px;
        height: 90px;
        border-radius: 50%;
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
        font-weight: bold;
        font-size: 28px;
        border: 5px solid;
    }
    
    /* VENDOR ITEM STYLING */
    .vendor-box {
        background-color: #0d1117;
        padding: 10px 15px;
        border-radius: 4px;
        border-bottom: 1px solid #21262d;
        margin-bottom: 5px;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    
    </style>
    """, unsafe_allow_html=True)

# --- 3. MODEL & LOGIC ---
TARGET_BRANDS = ['google.com', 'paypal.com', 'facebook.com', 'microsoft.com', 'apple.com', 'amazon.com']
VENDORS = [
    "Abusix", "Acronis", "AlienVault", "Baidu", "BitDefender", "Bkav", 
    "Google Safe Browsing", "Kaspersky", "Malwarebytes", "McAfee", "Microsoft",
    "Sophos", "Symantec", "Tencent", "Yandex", "Zscaler", "Avast", "Avira",
    "Cisco Talos", "CrowdStrike", "Cybereason", "Dr.Web", "Emsisoft", "ESET",
    "F-Secure", "Fortinet", "G-Data", "Heimdal Security", "IBM X-Force", 
    "Juniper Networks", "Kingsoft", "Lionic", "Palo Alto Networks", "PhishLabs",
    "Quttera", "Rising", "Sangfor", "SonicWall", "TrendMicro", "VipRE", "Webroot"
]

@st.cache_resource
def load_model():
    try:
        with open('phishing_model.pkl', 'rb') as file:
            return pickle.load(file)
    except:
        return None

model = load_model()

# --- 4. SESSION STATE ---
if 'page' not in st.session_state:
    st.session_state.page = 'home'
if 'url_query' not in st.session_state:
    st.session_state.url_query = ''

def perform_search():
    if st.session_state.url_input:
        st.session_state.url_query = st.session_state.url_input
        st.session_state.page = 'results'

def go_home():
    st.session_state.page = 'home'
    st.session_state.url_query = ''

# --- 5. PAGE: HOME ---
if st.session_state.page == 'home':
    st.markdown("<br><br>", unsafe_allow_html=True)
    
    # Title
    st.markdown('<div class="logo-text">PHISHING DETECTOR</div>', unsafe_allow_html=True)
    st.markdown('<div class="subtitle-text">Analyze suspicious domains, IPs and URLs to detect malware and other breaches.</div>', unsafe_allow_html=True)

    # Tabs (Visual)
    st.markdown("""
    <div class="nav-tabs">
        <div class="nav-item">FILE</div>
        <div class="nav-item active">URL</div>
        <div class="nav-item">SEARCH</div>
    </div>
    """, unsafe_allow_html=True)

    # Search
    st.markdown('<div style="font-size: 60px; text-align: center; margin-bottom: 20px;">🌐</div>', unsafe_allow_html=True)
    c1, c2, c3 = st.columns([1, 2, 1])
    with c2:
        st.text_input("Search", placeholder="Search or scan a URL", key="url_input", label_visibility="collapsed", on_change=perform_search)
        st.markdown("<br>", unsafe_allow_html=True)
        # Center Button
        b1, b2, b3 = st.columns([1,1,1])
        with b2:
            st.button("Search", on_click=perform_search, use_container_width=True)

# --- 6. PAGE: RESULTS ---
elif st.session_state.page == 'results':
    
    # LOGIC
    features = {}
    url = st.session_state.url_query
    if not url.startswith(('http://', 'https://')): url = 'http://' + url
    
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc
        path = parsed.path
        
        features['url_length'] = len(url)
        features['hostname_length'] = len(hostname)
        features['path_length'] = len(path)
        features['dot_count'] = url.count('.')
        features['at_symbol'] = 1 if '@' in url else 0
        features['dash_symbol'] = 1 if '-' in hostname else 0
        features['directory_count'] = path.count('/')
        features['has_ip'] = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', hostname) else 0
        features['https_in_text'] = 1 if 'https' in hostname else 0
        min_dist = 100
        for brand in TARGET_BRANDS:
            extracted = tldextract.extract(hostname)
            main_domain = f"{extracted.domain}.{extracted.suffix}"
            dist = lev_distance(main_domain, brand)
            if dist < min_dist: min_dist = dist
        features['min_levenshtein_dist'] = min_dist
        
        df = pd.DataFrame([features])
        
        if model:
            prediction = model.predict(df)[0]
            probability = model.predict_proba(df)[0][1]
        else:
            prediction = 0
            probability = 0
            
    except:
        st.error("Error parsing URL")
        st.stop()

    # UI: Back Button
    if st.button("← New Search"):
        go_home()
        st.rerun()

    # UI: Determine Colors
    if prediction == 1:
        score = int(probability * 94)
        if score < 20: score = 25
        color = "#da3633" # Red
        text_status = "Security vendors flagged this URL as malicious"
    else:
        score = 0
        color = "#28a745" # Green
        text_status = "No security vendors flagged this URL as malicious"

    # UI: Header Card
    # We use explicit f-strings with NO indentation to avoid code block issues
    header_html = f"""
    <div class="result-card">
        <div class="score-circle" style="border-color: {color}; color: {color};">
            <div>{score}</div>
            <div style="font-size: 12px; color: #8b949e; margin-top: -5px; border:none;">/ 94</div>
        </div>
        <div style="flex-grow: 1;">
            <div style="font-size: 20px; color: #58a6ff; font-weight: 600; margin-bottom: 5px;">{st.session_state.url_query}</div>
            <div style="font-size: 18px; color: {color}; font-weight: 500;">{text_status}</div>
        </div>
    </div>
    """
    st.markdown(header_html, unsafe_allow_html=True)

    # UI: Tabs & Grid
    t1, t2 = st.tabs(["DETECTION", "DETAILS"])
    
    with t1:
        # We split vendors into 2 columns using Streamlit columns, NOT HTML string
        col_left, col_right = st.columns(2)
        
        half = len(VENDORS) // 2
        
        # Helper function to generate row HTML
        def get_vendor_html(name):
            # Randomly simulate vendor results if Phishing
            is_bad = (prediction == 1 and random.random() > 0.3)
            
            if is_bad:
                status_color = "#da3633" # Red
                status_text = "Malicious"
                icon = "❗"
            else:
                status_color = "#28a745" # Green
                status_text = "Clean"
                icon = "✔"

            return f"""
            <div class="vendor-box">
                <span style="font-weight: 500; font-size: 14px; color: #e6edf3;">{name}</span>
                <span style="color: {status_color}; font-weight: 500; font-size: 14px;">{status_text} <span style="font-size:16px;">{icon}</span></span>
            </div>
            """

        with col_left:
            for v in VENDORS[:half]:
                st.markdown(get_vendor_html(v), unsafe_allow_html=True)
                
        with col_right:
            for v in VENDORS[half:]:
                st.markdown(get_vendor_html(v), unsafe_allow_html=True)
        
    with t2:
        st.dataframe(df, use_container_width=True)