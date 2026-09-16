import streamlit as st

st.set_page_config(page_title="UPI SHIELD", page_icon="🛡️", layout="centered")

# Header Section
st.title("🛡️ UPI SHIELD")
st.caption("AI-Powered Fraud Protection")
st.divider()

# Detection Method Selection
st.subheader("Choose Detection Method")
detection_method = st.radio(
    label="Select an option:",
    options=["UPI Transaction", "SMS / OTP", "Check URL"],
    horizontal=True,
    label_visibility="collapsed",
)

st.divider()
 
# Simulated Risk Results (Replace with actual module output when connected)
risk_score = 85

st.markdown("### FRAUD RISK SCORE")
st.markdown(f"# **{risk_score}/100**")

if risk_score >= 70:
    st.error("🔴 HIGH RISK")
elif risk_score >= 30:
    st.warning("🟠 MEDIUM RISK")
else:
    st.success("🟢 LOW RISK")

st.divider()

# Explainable AI Section
st.subheader("Why?")
reasons = [
    "New recipient",
    "Unusual transaction amount",
    "Suspicious SMS",
    "Phishing URL",
]

for reason in reasons:
    st.write(f"⚠️ {reason}")

st.divider()

# Action Buttons
col1, col2 = st.columns(2)
with col1:
    if st.button("VERIFY", use_container_width=True, type="primary"):
        st.success("Verification initiated.")
with col2:
    if st.button("CANCEL", use_container_width=True):
        st.info("Transaction cancelled.")