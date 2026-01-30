PROJECT TITLE: PhishGuard - Advanced AI-Driven Phishing URL Detector
DEGREE: MSc Data Science (Final Semester Project)
DEVELOPER: [Your Name]

========================================================================
1. PROJECT OVERVIEW
========================================================================
PhishGuard is a machine learning-powered cybersecurity tool designed to detect 
malicious URLs. Unlike simple blocklists, it uses Artificial Intelligence 
(Random Forest Classifier) to analyze the structure and "DNA" of a URL to 
predict if it is safe or phishing.

The project features a professional dashboard inspired by VirusTotal, providing 
real-time detection and technical analysis.

========================================================================
2. KEY FEATURES & NOVELTY
========================================================================
* Advanced AI Brain: Trained on over 500,000 legitimate and phishing URLs.
* Typosquatting Detection: Uses "Levenshtein Distance" to detect fake 
  brands (e.g., detecting "googl3.com" trying to look like "google.com").
* Explainable AI: The interface explains WHY a URL was flagged (e.g., "URL 
  is too long" or "Contains IP address").
* Professional UI: A dark-themed, responsive interface built with Streamlit.

========================================================================
3. TECHNICAL STACK
========================================================================
* Language: Python 3.13
* Interface: Streamlit (Web Dashboard)
* Machine Learning: Scikit-Learn (Random Forest)
* Data Processing: Pandas, NumPy
* Feature Engineering: Tldextract, Python-Levenshtein, Re (Regex)

========================================================================
4. PROJECT STRUCTURE
========================================================================
Phishing_Detector/
│
├── phishing_site_urls.csv    # Raw dataset (The fuel for the AI)
├── processed_data.csv        # The mathematical version of the data
├── phishing_model.pkl        # The saved "Brain" of the AI
├── step1_load_data.py        # Script to load and check data
├── step2_features.py         # Script to extract features (The logic)
├── step3_train_model.py      # Script to train the Random Forest
└── app.py                    # The Main Application (Run this!)

========================================================================
5. HOW TO RUN THE PROJECT
========================================================================
Step 1: Open your terminal (PowerShell or CMD).

Step 2: Navigate to the project folder:
   cd Desktop\Phishing_Detector

Step 3: Run the application:
   streamlit run app.py

The application will open automatically in your web browser.

========================================================================
6. MODEL PERFORMANCE
========================================================================
* Accuracy: 88.07%
* Primary Predictive Features: 
  1. Path Length (Phishing links often have long, complex paths)
  2. URL Length
  3. Levenshtein Distance (Brand impersonation check)

========================================================================
