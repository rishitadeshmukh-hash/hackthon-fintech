#SMS DETECTION
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

# Load dataset using exact Downloads path
file_path = r'C:\Users\hp\Downloads\spam_ham_india (2).csv'
df = pd.read_csv(file_path, encoding='latin-1')

# Map targets
df['target'] = df['Label'].map({'ham': 0, 'spam': 1})
df = df.dropna(subset=['Msg', 'target'])

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(df['Msg'], df['target'], test_size=0.2, random_state=42)

# TF-IDF
tfidf = TfidfVectorizer(stop_words='english', max_features=3000)
X_train_tfidf = tfidf.fit_transform(X_train)
X_test_tfidf = tfidf.transform(X_test)

# Logistic Regression
lr = LogisticRegression()
lr.fit(X_train_tfidf, y_train)
print("--- Logistic Regression ---")
print(f"Accuracy: {accuracy_score(y_test, lr.predict(X_test_tfidf)):.4f}")

# Random Forest
rf = RandomForestClassifier(n_estimators=100, random_state=42)
rf.fit(X_train_tfidf, y_train)
print("--- Random Forest ---")
print(f"Accuracy: {accuracy_score(y_test, rf.predict(X_test_tfidf)):.4f}")
import joblib

# Save the best model (Random Forest) and vectorizer
joblib.dump(rf, 'spam_model.pkl')
joblib.dump(tfidf, 'tfidf_vectorizer.pkl')

print("Model and vectorizer saved successfully!")

# Predict on a sample SMS
sample_sms = ["CONGRATULATIONS! You won a free gift card. Click link to claim."]
sample_tfidf = tfidf.transform(sample_sms)
prediction = rf.predict(sample_tfidf)

print("Result:", "Spam/Fraud" if prediction[0] == 1 else "Legitimatimate")


#OTP SCAM
def detect_otp_scam(message):
    message = message.lower()

    scam_words = [
        "otp",
        "urgent",
        "verify",
        "account blocked",
        "click here",
        "send otp",
        "share otp",
        "bank",
        "kyc",
        "suspended",
        "refund",
        "prize",
        "winner"
    ]

    score = 0
    reasons = []

    for word in scam_words:
        if word in message:
            score += 8
            reasons.append(f"Suspicious keyword: {word}")

    # Keep score between 0 and 100
    score = min(score, 100)

    if score <= 30:
        risk = "LOW"
    elif score <= 70:
        risk = "MEDIUM"
    else:
        risk = "HIGH"

    return score, risk, reasons


print("UPI Shield - OTP Scam Detector")
print("--------------------------------")

message = input("Enter an SMS message: ")

score, risk, reasons = detect_otp_scam(message)

print("\nRisk Score:", score, "/ 100")
print("Risk Level:", risk)

if reasons:
    print("\nWhy?")
    for reason in reasons:
        print("-", reason)
else:
    print("\nNo suspicious keywords detected.")


#URL
from urllib.parse import urlparse


def detect_phishing_url(url):
    score = 0
    reasons = []

    url_lower = url.lower()

    # Check for HTTPS
    if not url_lower.startswith("https://"):
        score += 20
        reasons.append("Website does not use HTTPS")

    # Suspicious words often used in scam links
    suspicious_words = [
        "verify",
        "account",
        "login",
        "update",
        "kyc",
        "bank",
        "payment",
        "refund",
        "prize",
        "winner",
        "urgent"
    ]

    for word in suspicious_words:
        if word in url_lower:
            score += 10
            reasons.append(f"Suspicious word found: {word}")

    # Check for @ symbol
    if "@" in url:
        score += 20
        reasons.append("URL contains @ symbol")

    # Check for unusually long URL
    if len(url) > 75:
        score += 15
        reasons.append("URL is unusually long")

    score = min(score, 100)

    if score <= 30:
        risk = "LOW"
    elif score <= 70:
        risk = "MEDIUM"
    else:
        risk = "HIGH"

    return score, risk, reasons


print("UPI Shield - Phishing URL Detector")
print("-----------------------------------")

url = input("Enter a URL: ")

score, risk, reasons = detect_phishing_url(url)

print("\nRisk Score:", score, "/ 100")
print("Risk Level:", risk)

if reasons:
    print("\nWhy?")
    for reason in reasons:
        print("-", reason)
else:
    print("\nNo suspicious patterns detected.")


    #clear
    #interface
    import os
import json
import base64
import requests
import streamlit as st
from PIL import Image
import io

st.set_page_config(
    page_title="GuardianShield - OTP & Phishing Risk Analyzer",
    page_icon="🛡️",
    layout="wide"
)

# Custom CSS for custom UI elements
st.markdown("""
<style>
    .metric-box {
        background-color: #0f172a;
        border: 1px solid #1e293b;
        padding: 20px;
        border-radius: 12px;
        text-align: center;
    }
    .risk-low { color: #10b981; border-color: #10b981; }
    .risk-medium { color: #f59e0b; border-color: #f59e0b; }
    .risk-high { color: #ef4444; border-color: #ef4444; }
    .risk-critical { color: #dc2626; border-color: #dc2626; }
    .flag-item {
        background-color: #1e1b4b;
        border-left: 4px solid #ef4444;
        padding: 8px 12px;
        margin-bottom: 6px;
        border-radius: 4px;
        font-size: 14px;
    }
    .safety-item {
        background-color: #064e3b;
        border-left: 4px solid #10b981;
        padding: 8px 12px;
        margin-bottom: 6px;
        border-radius: 4px;
        font-size: 14px;
    }
</style>
""", unsafe_allow_html=True)

def analyze_threat(text_content=None, image_bytes=None, api_key=""):
    """
    Sends message text or image payload to Gemini 3 Flash model
    and returns structured security assessment data.
    """
    system_prompt = (
        "You are a world-class cybersecurity expert specializing in anti-phishing, "
        "OTP fraud detection, and social engineering analysis.\n"
        "Analyze the provided text message or screenshot and return a structured JSON response containing:\n"
        "- riskScore: number between 0 and 100\n"
        "- riskLevel: 'LOW', 'MEDIUM', 'HIGH', or 'CRITICAL'\n"
        "- summary: concise sentence explaining why this message is safe or unsafe\n"
        "- redFlags: array of strings detailing specific warning signs\n"
        "- safetySigns: array of strings detailing positive safety indicators\n"
        "- actionableAdvice: clear recommendation on what action the recipient should take next.\n\n"
        "Strict Safety Rule: Non-disclosure warnings like 'Do NOT share this code with anyone' "
        "are LEGITIMATE SAFETY INSTRUCTIONS and indicate LOW RISK unless accompanied by pressure "
        "to call an unofficial phone number or click a scam link."
    )

    parts = []
    if text_content:
        parts.append({"text": f"Analyze this message text: \"{text_content}\""})
    if image_bytes:
        parts.append({"text": "Analyze this message screenshot image:"})
        parts.append({
            "inlineData": {
                "mimeType": "image/png",
                "data": base64.b64encode(image_bytes).decode('utf-8')
            }
        })

    payload = {
        "contents": [{"parts": parts}],
        "systemInstruction": {"parts": [{"text": system_prompt}]},
        "generationConfig": {
            "responseMimeType": "application/json",
            "responseSchema": {
                "type": "OBJECT",
                "properties": {
                    "riskScore": {"type": "NUMBER"},
                    "riskLevel": {"type": "STRING"},
                    "summary": {"type": "STRING"},
                    "redFlags": {"type": "ARRAY", "items": {"type": "STRING"}},
                    "safetySigns": {"type": "ARRAY", "items": {"type": "STRING"}},
                    "actionableAdvice": {"type": "STRING"}
                },
                "required": ["riskScore", "riskLevel", "summary", "redFlags", "safetySigns", "actionableAdvice"]
            }
        }
    }

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash-preview:generateContent?key={api_key}"
    headers = {"Content-Type": "application/json"}

    response = requests.post(url, headers=headers, json=payload)
    if response.status_code != 200:
        raise Exception(f"Gemini API Error {response.status_code}: {response.text}")

    data = response.json()
    json_str = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "{}")
    return json.loads(json_str)

def heuristic_fallback(text):
    """Fallback pattern-matching analyzer when running without an API key."""
    lower = (text or "").lower()
    score = 15
    red_flags = []
    safety_signs = []

    if any(k in lower for k in ["do not share", "don't share", "never share"]):
        safety_signs.append("Standard legitimate OTP non-disclosure advisory detected")
        score -= 10

    if any(k in lower for k in ["urgent", "immediately", "locked", "blocked", "suspended"]):
        red_flags.append("Artificial urgency or account suspension threat detected")
        score += 35

    if any(k in lower for k in ["call", "share otp", "tell us your code", "verify now"]):
        red_flags.append("Request to share OTP code or call external number")
        score += 45

    if any(k in lower for k in ["http://", ".xyz", ".top", "bit.ly", "claims"]):
        red_flags.append("Unverified or suspicious URL domain link detected")
        score += 30

    score = max(5, min(98, score))
    level = "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "MEDIUM" if score >= 30 else "LOW"

    return {
        "riskScore": score,
        "riskLevel": level,
        "summary": "High threat detected due to credential harvesting indicators." if score >= 50 else "Low risk message matching standard transaction alerts.",
        "redFlags": red_flags if red_flags else ["No critical threat indicators flagged."],
        "safetySigns": safety_signs if safety_signs else ["No explicit safety disclaimers detected."],
        "actionableAdvice": "Do NOT share OTP codes or click links. Verify directly with official app." if score >= 50 else "Safe to proceed. Keep your OTP confidential."
    }

st.sidebar.title("🛡️ GuardianShield API")
st.sidebar.markdown("Configure your environment settings for custom interface integration.")
api_key = st.sidebar.text_input("Google Gemini API Key", type="password", help="Get a free key from Google AI Studio (aistudio.google.com)")

if not api_key:
    st.sidebar.info("💡 Running in **Heuristic Fallback Mode**. Provide an API key for full AI analysis.")

st.title("🛡️ OTP & Phishing Threat Analyzer")
st.caption("Customizable Developer Interface for Real-Time Scam & Social Engineering Risk Assessment")

col1, col2 = st.columns([1, 1], gap="large")

with col1:
    st.subheader("📥 Input Data")
    input_mode = st.radio("Select Input Format:", ["Text Message / Email", "Screenshot Image"], horizontal=True)

    user_text = ""
    uploaded_image_bytes = None

    if input_mode == "Text Message / Email":
        user_text = st.text_area(
            "Paste suspicious message content:",
            height=180,
            placeholder="e.g. URGENT: Your bank account is locked! Call bank support at 9876543210 immediately and share OTP 12345 to unblock."
        )
    else:
        uploaded_file = st.file_uploader("Upload SMS or WhatsApp screenshot:", type=["png", "jpg", "jpeg"])
        if uploaded_file is not None:
            image = Image.open(uploaded_file)
            st.image(image, caption="Uploaded Screenshot", use_column_width=True)
            img_byte_arr = io.BytesIO()
            image.save(img_byte_arr, format='PNG')
            uploaded_image_bytes = img_byte_arr.getvalue()

    # Preset Test Buttons
    st.markdown("**Test Presets:**")
    preset_cols = st.columns(2)
    with preset_cols[0]:
        if st.button("🚨 High-Risk Urgent Scam"):
            st.session_state['preset_text'] = "URGENT: Your account is locked! Call 9876543210 and share OTP 12345 to unblock."
    with preset_cols[1]:
        if st.button("✅ Legitimate OTP Alert"):
            st.session_state['preset_text'] = "Your HDFC Bank netbanking OTP is 849201 for Rs.4,500. Do NOT share this code with anyone."

    if 'preset_text' in st.session_state and not user_text and input_mode == "Text Message / Email":
        user_text = st.session_state['preset_text']

    analyze_clicked = st.button("🔍 Analyze Risk Level", type="primary", use_container_width=True)

with col2:
    st.subheader("📊 Threat Risk Dashboard")
    
    if analyze_clicked:
        if input_mode == "Text Message / Email" and not user_text:
            st.warning("Please enter text or choose a test scenario to evaluate.")
        elif input_mode == "Screenshot Image" and not uploaded_image_bytes:
            st.warning("Please upload a screenshot image to analyze.")
        else:
            with st.spinner("Analyzing threat vectors with AI..."):
                try:
                    if api_key:
                        result = analyze_threat(text_content=user_text, image_bytes=uploaded_image_bytes, api_key=api_key)
                    else:
                        result = heuristic_fallback(user_text)
                except Exception as e:
                    st.error(f"API Error: {str(e)}")
                    result = heuristic_fallback(user_text)

            score = int(result.get("riskScore", 0))
            level = result.get("riskLevel", "UNKNOWN")

            score_col, level_col = st.columns(2)
            with score_col:
                st.metric(label="Risk Score", value=f"{score}%")
            with level_col:
                st.metric(label="Threat Level", value=level)

            st.progress(score / 100)

            st.markdown("### Executive Summary")
            st.info(result.get("summary", "No summary provided."))

            st.markdown("### ⚠️ Red Flags")
            for flag in result.get("redFlags", []):
                st.markdown(f"<div class='flag-item'>❌ {flag}</div>", unsafe_allow_html=True)

            st.markdown("### 🛡️ Safety Signs")
            for sign in result.get("safetySigns", []):
                st.markdown(f"<div class='safety-item'>✅ {sign}</div>", unsafe_allow_html=True)

            st.markdown("### 💡 Recommended Action")
            st.success(result.get("actionableAdvice", "Follow standard security protocols."))
    else:
        st.info("Paste a message or upload a screenshot on the left and click **Analyze Risk Level** to view the interactive breakdown.")import os
import json
import base64
import requests
import streamlit as st
from PIL import Image
import io

st.set_page_config(
    page_title="GuardianShield - OTP & Phishing Risk Analyzer",
    page_icon="🛡️",
    layout="wide"
)

# Custom CSS for custom UI elements
st.markdown("""
<style>
    .metric-box {
        background-color: #0f172a;
        border: 1px solid #1e293b;
        padding: 20px;
        border-radius: 12px;
        text-align: center;
    }
    .risk-low { color: #10b981; border-color: #10b981; }
    .risk-medium { color: #f59e0b; border-color: #f59e0b; }
    .risk-high { color: #ef4444; border-color: #ef4444; }
    .risk-critical { color: #dc2626; border-color: #dc2626; }
    .flag-item {
        background-color: #1e1b4b;
        border-left: 4px solid #ef4444;
        padding: 8px 12px;
        margin-bottom: 6px;
        border-radius: 4px;
        font-size: 14px;
    }
    .safety-item {
        background-color: #064e3b;
        border-left: 4px solid #10b981;
        padding: 8px 12px;
        margin-bottom: 6px;
        border-radius: 4px;
        font-size: 14px;
    }
</style>
""", unsafe_allow_html=True)

def analyze_threat(text_content=None, image_bytes=None, api_key=""):
    """
    Sends message text or image payload to Gemini 3 Flash model
    and returns structured security assessment data.
    """
    system_prompt = (
        "You are a world-class cybersecurity expert specializing in anti-phishing, "
        "OTP fraud detection, and social engineering analysis.\n"
        "Analyze the provided text message or screenshot and return a structured JSON response containing:\n"
        "- riskScore: number between 0 and 100\n"
        "- riskLevel: 'LOW', 'MEDIUM', 'HIGH', or 'CRITICAL'\n"
        "- summary: concise sentence explaining why this message is safe or unsafe\n"
        "- redFlags: array of strings detailing specific warning signs\n"
        "- safetySigns: array of strings detailing positive safety indicators\n"
        "- actionableAdvice: clear recommendation on what action the recipient should take next.\n\n"
        "Strict Safety Rule: Non-disclosure warnings like 'Do NOT share this code with anyone' "
        "are LEGITIMATE SAFETY INSTRUCTIONS and indicate LOW RISK unless accompanied by pressure "
        "to call an unofficial phone number or click a scam link."
    )

    parts = []
    if text_content:
        parts.append({"text": f"Analyze this message text: \"{text_content}\""})
    if image_bytes:
        parts.append({"text": "Analyze this message screenshot image:"})
        parts.append({
            "inlineData": {
                "mimeType": "image/png",
                "data": base64.b64encode(image_bytes).decode('utf-8')
            }
        })

    payload = {
        "contents": [{"parts": parts}],
        "systemInstruction": {"parts": [{"text": system_prompt}]},
        "generationConfig": {
            "responseMimeType": "application/json",
            "responseSchema": {
                "type": "OBJECT",
                "properties": {
                    "riskScore": {"type": "NUMBER"},
                    "riskLevel": {"type": "STRING"},
                    "summary": {"type": "STRING"},
                    "redFlags": {"type": "ARRAY", "items": {"type": "STRING"}},
                    "safetySigns": {"type": "ARRAY", "items": {"type": "STRING"}},
                    "actionableAdvice": {"type": "STRING"}
                },
                "required": ["riskScore", "riskLevel", "summary", "redFlags", "safetySigns", "actionableAdvice"]
            }
        }
    }

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash-preview:generateContent?key={api_key}"
    headers = {"Content-Type": "application/json"}

    response = requests.post(url, headers=headers, json=payload)
    if response.status_code != 200:
        raise Exception(f"Gemini API Error {response.status_code}: {response.text}")

    data = response.json()
    json_str = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "{}")
    return json.loads(json_str)

def heuristic_fallback(text):
    """Fallback pattern-matching analyzer when running without an API key."""
    lower = (text or "").lower()
    score = 15
    red_flags = []
    safety_signs = []

    if any(k in lower for k in ["do not share", "don't share", "never share"]):
        safety_signs.append("Standard legitimate OTP non-disclosure advisory detected")
        score -= 10

    if any(k in lower for k in ["urgent", "immediately", "locked", "blocked", "suspended"]):
        red_flags.append("Artificial urgency or account suspension threat detected")
        score += 35

    if any(k in lower for k in ["call", "share otp", "tell us your code", "verify now"]):
        red_flags.append("Request to share OTP code or call external number")
        score += 45

    if any(k in lower for k in ["http://", ".xyz", ".top", "bit.ly", "claims"]):
        red_flags.append("Unverified or suspicious URL domain link detected")
        score += 30

    score = max(5, min(98, score))
    level = "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "MEDIUM" if score >= 30 else "LOW"

    return {
        "riskScore": score,
        "riskLevel": level,
        "summary": "High threat detected due to credential harvesting indicators." if score >= 50 else "Low risk message matching standard transaction alerts.",
        "redFlags": red_flags if red_flags else ["No critical threat indicators flagged."],
        "safetySigns": safety_signs if safety_signs else ["No explicit safety disclaimers detected."],
        "actionableAdvice": "Do NOT share OTP codes or click links. Verify directly with official app." if score >= 50 else "Safe to proceed. Keep your OTP confidential."
    }

st.sidebar.title("🛡️ GuardianShield API")
st.sidebar.markdown("Configure your environment settings for custom interface integration.")
api_key = st.sidebar.text_input("Google Gemini API Key", type="password", help="Get a free key from Google AI Studio (aistudio.google.com)")

if not api_key:
    st.sidebar.info("💡 Running in **Heuristic Fallback Mode**. Provide an API key for full AI analysis.")

st.title("🛡️ OTP & Phishing Threat Analyzer")
st.caption("Customizable Developer Interface for Real-Time Scam & Social Engineering Risk Assessment")

col1, col2 = st.columns([1, 1], gap="large")

with col1:
    st.subheader("📥 Input Data")
    input_mode = st.radio("Select Input Format:", ["Text Message / Email", "Screenshot Image"], horizontal=True)

    user_text = ""
    uploaded_image_bytes = None

    if input_mode == "Text Message / Email":
        user_text = st.text_area(
            "Paste suspicious message content:",
            height=180,
            placeholder="e.g. URGENT: Your bank account is locked! Call bank support at 9876543210 immediately and share OTP 12345 to unblock."
        )
    else:
        uploaded_file = st.file_uploader("Upload SMS or WhatsApp screenshot:", type=["png", "jpg", "jpeg"])
        if uploaded_file is not None:
            image = Image.open(uploaded_file)
            st.image(image, caption="Uploaded Screenshot", use_column_width=True)
            img_byte_arr = io.BytesIO()
            image.save(img_byte_arr, format='PNG')
            uploaded_image_bytes = img_byte_arr.getvalue()

    # Preset Test Buttons
    st.markdown("**Test Presets:**")
    preset_cols = st.columns(2)
    with preset_cols[0]:
        if st.button("🚨 High-Risk Urgent Scam"):
            st.session_state['preset_text'] = "URGENT: Your account is locked! Call 9876543210 and share OTP 12345 to unblock."
    with preset_cols[1]:
        if st.button("✅ Legitimate OTP Alert"):
            st.session_state['preset_text'] = "Your HDFC Bank netbanking OTP is 849201 for Rs.4,500. Do NOT share this code with anyone."

    if 'preset_text' in st.session_state and not user_text and input_mode == "Text Message / Email":
        user_text = st.session_state['preset_text']

    analyze_clicked = st.button("🔍 Analyze Risk Level", type="primary", use_container_width=True)

with col2:
    st.subheader("📊 Threat Risk Dashboard")
    
    if analyze_clicked:
        if input_mode == "Text Message / Email" and not user_text:
            st.warning("Please enter text or choose a test scenario to evaluate.")
        elif input_mode == "Screenshot Image" and not uploaded_image_bytes:
            st.warning("Please upload a screenshot image to analyze.")
        else:
            with st.spinner("Analyzing threat vectors with AI..."):
                try:
                    if api_key:
                        result = analyze_threat(text_content=user_text, image_bytes=uploaded_image_bytes, api_key=api_key)
                    else:
                        result = heuristic_fallback(user_text)
                except Exception as e:
                    st.error(f"API Error: {str(e)}")
                    result = heuristic_fallback(user_text)

            score = int(result.get("riskScore", 0))
            level = result.get("riskLevel", "UNKNOWN")

            score_col, level_col = st.columns(2)
            with score_col:
                st.metric(label="Risk Score", value=f"{score}%")
            with level_col:
                st.metric(label="Threat Level", value=level)

            st.progress(score / 100)

            st.markdown("### Executive Summary")
            st.info(result.get("summary", "No summary provided."))

            st.markdown("### ⚠️ Red Flags")
            for flag in result.get("redFlags", []):
                st.markdown(f"<div class='flag-item'>❌ {flag}</div>", unsafe_allow_html=True)

            st.markdown("### 🛡️ Safety Signs")
            for sign in result.get("safetySigns", []):
                st.markdown(f"<div class='safety-item'>✅ {sign}</div>", unsafe_allow_html=True)

            st.markdown("### 💡 Recommended Action")
            st.success(result.get("actionableAdvice", "Follow standard security protocols."))
    else:
        st.info("Paste a message or upload a screenshot on the left and click **Analyze Risk Level** to view the interactive breakdown.")