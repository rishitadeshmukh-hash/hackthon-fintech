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