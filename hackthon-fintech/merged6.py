import pandas as pd
import re
import joblib
import os
import csv
from datetime import time
import streamlit as st
from translate import Translator

# ============================================================
# PAGE CONFIGURATION
# ============================================================
st.set_page_config(
    page_title="UPI Shield - Fraud Detection",
    page_icon="🛡️",
    layout="wide"
)

# ============================================================
# BASE DIRECTORY
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ============================================================
# LOAD ML MODEL AND TF-IDF VECTORIZER
# ============================================================
@st.cache_resource
def load_models():
    model_path = os.path.join(BASE_DIR, "spam_model.pkl")
    vectorizer_path = os.path.join(BASE_DIR, "tfidf_vectorizer.pkl")
    rf_model = joblib.load(model_path)
    tfidf_vec = joblib.load(vectorizer_path)
    return rf_model, tfidf_vec

try:
    rf, tfidf = load_models()
except Exception:
    rf = None
    tfidf = None

# ============================================================
# LANGUAGE SETUP & TRANSLATION
# ============================================================
language_codes = {
    "English": "en",
    "Hindi": "hi",
    "Marathi": "mr",
    "Bengali": "bn",
    "Gujarati": "gu",
    "Kannada": "kn",
    "Malayalam": "ml",
    "Punjabi": "pa",
    "Tamil": "ta",
    "Telugu": "te",
    "Urdu": "ur",
    "Assamese": "as",
    "Odia": "or",
    "Konkani": "gom",
    "Nepali": "ne",
    "Kashmiri": "ks",
    "Sindhi": "sd",
    "Maithili": "mai",
    "Manipuri": "mni",
    "Bodo": "brx",
    "Dogri": "doi",
    "Santali": "sat"
}

def translate_text(text, language):
    if language == "English":
        return text
    try:
        translator = Translator(
            from_lang="en",
            to_lang=language_codes.get(language, "en")
        )
        result = translator.translate(text)
        return result if result else text
    except Exception:
        return text

# ============================================================
# DETECTOR FUNCTIONS
# ============================================================
def detect_otp_scam(message):
    message = message.lower()
    scam_words = [
        "otp", "urgent", "verify", "account blocked", "click here",
        "send otp", "share otp", "bank", "kyc", "suspended",
        "refund", "prize", "winner", "pin", "verification", "free"
    ]
    score = 0
    reasons = []
    for word in scam_words:
        if word in message:
            score += 8
            reasons.append(f"Suspicious keyword found: '{word}'")
    score = min(score, 100)
    risk = "LOW" if score <= 30 else ("MEDIUM" if score <= 70 else "HIGH")
    return score, risk, reasons

def detect_phishing_url(url):
    score = 0
    reasons = []
    url_lower = url.lower()
    if not url_lower.startswith("https://"):
        score += 20
        reasons.append("Website does not use HTTPS")
    suspicious_words = [
        "verify", "account", "login", "update", "kyc",
        "bank", "payment", "refund", "prize", "winner", "urgent"
    ]
    for word in suspicious_words:
        if word in url_lower:
            score += 10
            reasons.append(f"Suspicious word found: '{word}'")
    if "@" in url:
        score += 20
        reasons.append("URL contains '@' symbol")
    if len(url) > 75:
        score += 15
        reasons.append("URL is unusually long")
    score = min(score, 100)
    risk = "LOW" if score <= 30 else ("MEDIUM" if score <= 70 else "HIGH")
    return score, risk, reasons

# ============================================================
# HISTORICAL BEHAVIOR PROFILE
# ============================================================
def load_transactions():
    transactions = []
    file_path = os.path.join(BASE_DIR, "transactions.csv")
    if not os.path.exists(file_path):
        # Fallback to alternate filename if present
        file_path = os.path.join(BASE_DIR, "transaction.csv")
    
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8-sig") as file:
            reader = csv.DictReader(file)
            for row in reader:
                transactions.append(row)
    return transactions

def create_user_profile(transactions):
    amounts = []
    recipient_counts = {}
    daily_counts = {}
    for transaction in transactions:
        try:
            amount = float(transaction["amount"])
        except Exception:
            continue
        amounts.append(amount)
        recipient = transaction.get("recipient", "Unknown")
        recipient_counts[recipient] = recipient_counts.get(recipient, 0) + 1
        date = transaction.get("date", "Unknown")
        daily_counts[date] = daily_counts.get(date, 0) + 1

    if len(amounts) == 0:
        return {
            "average_amount": 0, "minimum_amount": 0, "maximum_amount": 0,
            "recipient_counts": {}, "daily_counts": {}, "average_daily_transactions": 0
        }

    return {
        "average_amount": sum(amounts) / len(amounts),
        "minimum_amount": min(amounts),
        "maximum_amount": max(amounts),
        "recipient_counts": recipient_counts,
        "daily_counts": daily_counts,
        "average_daily_transactions": sum(daily_counts.values()) / len(daily_counts) if daily_counts else 0
    }

# ============================================================
# SIDEBAR NAVIGATION & GLOBAL SETTINGS
# ============================================================
st.sidebar.title("🛡️ UPI SHIELD")
st.sidebar.write("AI-Powered Fraud & Scam Detection")
st.sidebar.markdown("---")

selected_language = st.sidebar.selectbox(
    "🌐 Select Alert Language",
    list(language_codes.keys())
)

menu_choice = st.sidebar.radio(
    "Select Feature",
    [
        "📲 Check SMS",
        "🔗 Check URL",
        "💳 UPI Transaction Risk",
        "🧠 Unified Risk Engine",
        "🎬 Fraud Demo Scenario",
        "📊 Analytics Dashboard"
    ]
)

st.title("🛡️ UPI SHIELD")
st.caption("Multilingual AI-Powered Fraud Detection & Risk Analysis Dashboard")

# ============================================================
# 1. SMS DETECTION MODULE
# ============================================================
if menu_choice == "📲 Check SMS":
    st.header("📲 SMS Scam Detection")
    st.write("Analyze suspicious messages for OTP scams, phishing, and fraud keywords.")

    message = st.text_area(
        "Enter the SMS Message:",
        placeholder="Example: Dear customer, your account is blocked. Share OTP to unblock.",
        height=120
    )

    if st.button("🔍 Analyze SMS", type="primary"):
        if message.strip() == "":
            st.warning("Please enter a message to analyze.")
        else:
            st.markdown("---")
            st.subheader("📊 Analysis Result")

            if rf is not None and tfidf is not None:
                try:
                    message_tfidf = tfidf.transform([message])
                    prediction = rf.predict(message_tfidf)[0]
                    if prediction == 1:
                        st.error("🚨 ML Prediction: SPAM / POSSIBLE FRAUD")
                    else:
                        st.success("✅ ML Prediction: LEGITIMATE")
                except Exception:
                    st.warning("ML model could not analyze this message.")
            else:
                st.warning("ML model files were not loaded.")

            score, risk, reasons = detect_otp_scam(message)
            st.metric("Risk Score", f"{score}/100")

            if risk == "LOW":
                st.success("🟢 LOW RISK")
            elif risk == "MEDIUM":
                st.warning("🟡 MEDIUM RISK")
            else:
                st.error("🔴 HIGH RISK")

            if reasons:
                st.subheader("⚠️ Warning Signs Identified")
                for reason in reasons:
                    st.write(f"• {translate_text(reason, selected_language)}")

# ============================================================
# 2. URL DETECTION MODULE
# ============================================================
elif menu_choice == "🔗 Check URL":
    st.header("🔗 Phishing Link Detection")
    st.write("Check whether a website link contains suspicious patterns.")

    url = st.text_input("Enter Web URL:", placeholder="http://login-verify-bank.com/update")

    if st.button("🔍 Analyze URL", type="primary"):
        if url.strip() == "":
            st.warning("Please enter a URL to check.")
        else:
            score, risk, reasons = detect_phishing_url(url)
            st.markdown("---")
            st.subheader("🔗 URL Analysis Result")
            st.metric("Risk Score", f"{score}/100")
            st.progress(score / 100)

            if risk == "LOW":
                st.success("🟢 LOW RISK")
            elif risk == "MEDIUM":
                st.warning("🟡 MEDIUM RISK")
            else:
                st.error("🔴 HIGH RISK")

            if reasons:
                st.subheader("⚠️ Detected Risk Factors")
                for reason in reasons:
                    st.write(f"• {translate_text(reason, selected_language)}")

# ============================================================
# 3. UPI TRANSACTION RISK & BEHAVIOR ANALYSIS
# ============================================================
elif menu_choice == "💳 UPI Transaction Risk":
    st.header("💳 UPI Transaction Risk Analysis")
    st.write("Analyze transaction risk using rule checks and historical user behavior.")

    transactions = load_transactions()
    profile = create_user_profile(transactions)

    if profile["average_amount"] > 0:
        st.subheader("📊 Historical Behavioral Profile")
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Average Txn", f"₹{profile['average_amount']:.0f}")
        col2.metric("Min Txn", f"₹{profile['minimum_amount']:.0f}")
        col3.metric("Max Txn", f"₹{profile['maximum_amount']:.0f}")
        col4.metric("Avg Daily Txns", f"{profile['average_daily_transactions']:.1f}")
        st.markdown("---")

    col1, col2 = st.columns(2)
    with col1:
        transaction_amount = st.number_input("Transaction Amount (₹)", min_value=0.0, value=25000.0, step=500.0)
        previous_average = st.number_input("Previous Average Transaction (₹)", min_value=0.0, value=float(profile.get("average_amount", 2000)), step=500.0)
        transaction_frequency = st.number_input("Transaction Frequency Today", min_value=0, value=1, step=1)
        recipient = st.selectbox("Recipient Status", ["Known", "New"])
    with col2:
        device = st.selectbox("Device", ["Known", "New"])
        transaction_time = st.time_input("Transaction Time", value=time(14, 0))

    risk_score = 0
    score_breakdown = []

    if previous_average > 0 and transaction_amount > previous_average * 5:
        risk_score += 25
        score_breakdown.append("Very high transaction amount detected")
    if recipient == "New":
        risk_score += 20
        score_breakdown.append("New recipient detected")
    if transaction_time.hour < 6 or transaction_time.hour >= 23:
        risk_score += 15
        score_breakdown.append("Unusual transaction time detected")
    if device == "New":
        risk_score += 20
        score_breakdown.append("New device detected")
    if transaction_frequency > 5:
        risk_score += 20
        score_breakdown.append("Abnormal transaction frequency detected")

    risk_score = min(risk_score, 100)
    risk_level = "LOW" if risk_score <= 30 else ("MEDIUM" if risk_score <= 70 else "HIGH")

    st.markdown("---")
    st.subheader("💳 Risk Assessment")
    st.metric("UPI Risk Score", f"{risk_score}/100")
    st.progress(risk_score / 100)

    if risk_level == "LOW":
        st.success("🟢 LOW RISK")
    elif risk_level == "MEDIUM":
        st.warning("🟡 MEDIUM RISK")
    else:
        st.error("🔴 HIGH RISK")

    st.subheader("🔍 Breakdown & Warnings")
    for factor in score_breakdown:
        st.write(f"⚠️ {translate_text(factor, selected_language)}")

# ============================================================
# 4. UNIFIED RISK ENGINE
# ============================================================
elif menu_choice == "🧠 Unified Risk Engine":
    st.header("🧠 Multi-Vector Fraud Risk Engine")
    st.caption("Combines risk scores across SMS, OTP, URL, UPI, and Behavior channels.")

    col1, col2 = st.columns(2)
    with col1:
        sms_risk = st.slider("SMS Risk", 0, 100, 20)
        otp_risk = st.slider("OTP Risk", 0, 100, 10)
        url_risk = st.slider("URL Risk", 0, 100, 15)
    with col2:
        upi_risk = st.slider("UPI Transaction Risk", 0, 100, 40)
        behavior_risk = st.slider("Behavior Risk", 0, 100, 25)

    final_risk_score = round((sms_risk + otp_risk + url_risk + upi_risk + behavior_risk) / 5)
    final_risk_level = "LOW" if final_risk_score <= 30 else ("MEDIUM" if final_risk_score <= 70 else "HIGH")

    st.markdown("---")
    st.metric("Final Risk Score", f"{final_risk_score}/100")
    
    if final_risk_level == "HIGH":
        st.error("🔴 HIGH RISK: " + translate_text("High risk: Multiple warning signs were detected.", selected_language))
    elif final_risk_level == "MEDIUM":
        st.warning("🟡 MEDIUM RISK: " + translate_text("Medium risk: Unusual activity detected.", selected_language))
    else:
        st.success("🟢 LOW RISK: " + translate_text("Low risk: Transaction appears normal.", selected_language))

# ============================================================
# 5. FRAUD DEMO SCENARIO
# ============================================================
elif menu_choice == "🎬 Fraud Demo Scenario":
    st.header("🎬 Realistic Fraud Scenario")
    st.write("Demonstrates how UPI Shield catches complex multi-step scams in real time.")

    if st.button("🚨 Run Realistic Fraud Scenario", type="primary"):
        st.markdown("### 📖 Scenario Story")
        st.info("User receives an SMS claiming their SBI KYC expired with a link to update details.")
        st.code("Your SBI KYC has expired. Update immediately: http://login-verify-bank.com/update", language="text")

        st.markdown("### 🔎 Signals Detected")
        col1, col2, col3 = st.columns(3)
        col1.metric("SMS Risk", "85/100")
        col2.metric("OTP Risk", "80/100")
        col3.metric("URL Risk", "90/100")

        st.markdown("### 💳 Simulated UPI Transaction Attempt")
        st.write("💰 **Amount:** ₹25,000 | 👤 **Recipient:** New | 🕐 **Time:** 02:00 AM")

        st.markdown("### 🛡️ Final Decision")
        st.metric("Unified Risk Score", "87/100")
        st.error("🔴 HIGH RISK DETECTED")
        st.warning("⚠️ " + translate_text("Warning: High risk transaction. Do not share your OTP.", selected_language))

# ============================================================
# 6. ANALYTICS DASHBOARD
# ============================================================
elif menu_choice == "📊 Analytics Dashboard":
    st.header("📊 Dashboard Analytics")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Analyzed", "120")
    col2.metric("Safe", "65")
    col3.metric("Suspicious", "32")
    col4.metric("Fraud", "23")

    st.markdown("---")
    st.subheader("📈 Detection Overview")
    chart_data = pd.DataFrame({
        "Status": ["Safe", "Suspicious", "Fraud"],
        "Count": [65, 32, 23]
    })
    st.bar_chart(chart_data, x="Status", y="Count")

# ============================================================
# FOOTER
# ============================================================
st.sidebar.markdown("---")
st.sidebar.caption("UPI Shield | Fraud Detection System")