import re
from urllib.parse import urlparse

# ---------------------------------------------------------
# PHISHING EMAIL RISK ANALYZER
# ---------------------------------------------------------

emails = [
    {
        "id": "EMAIL-001",
        "sender": "support@amazon.com",
        "subject": "Your order has been shipped",
        "body": """
        Your Amazon order has been shipped.
        You can track your order using the link below.
        https://www.amazon.com/orders
        """
    },

    {
        "id": "EMAIL-002",
        "sender": "security-alert@paypa1-login.com",
        "subject": "URGENT: Your account will be suspended!",
        "body": """
        Your account will be suspended within 24 hours.
        Verify your account immediately.
        Please provide your username and password.
        Click here:
        http://paypa1-login.com/verify
        """
    },

    {
        "id": "EMAIL-003",
        "sender": "hr@company.com",
        "subject": "Updated employee meeting schedule",
        "body": """
        The employee meeting has been moved to Friday at 10 AM.
        Please review the updated schedule.
        """
    },

    {
        "id": "EMAIL-004",
        "sender": "admin@secure-bank-support.xyz",
        "subject": "Immediate action required - verify your account",
        "body": """
        WARNING! Your banking account will be permanently locked.
        You must verify your credentials immediately.
        Enter your username, password and OTP here:
        https://secure-bank-support.xyz/login
        """
    }
]


# ---------------------------------------------------------
# SUSPICIOUS INDICATORS
# ---------------------------------------------------------

urgency_words = [
    "urgent",
    "immediately",
    "act now",
    "within 24 hours",
    "expires",
    "suspended",
    "suspension",
    "final warning",
    "immediate action",
    "permanently locked"
]

credential_words = [
    "password",
    "username",
    "login",
    "credentials",
    "otp",
    "one-time password",
    "verify your account",
    "confirm your identity"
]

suspicious_tlds = [
    ".xyz",
    ".top",
    ".click",
    ".tk",
    ".ml",
    ".ga",
    ".cf"
]

trusted_domains = [
    "amazon.com",
    "google.com",
    "microsoft.com",
    "apple.com",
    "paypal.com"
]


# ---------------------------------------------------------
# FUNCTION: Extract hyperlinks
# ---------------------------------------------------------

def extract_links(text):
    pattern = r'https?://[^\s]+'
    return re.findall(pattern, text)


# ---------------------------------------------------------
# FUNCTION: Analyze an email
# ---------------------------------------------------------

def analyze_email(email):

    score = 0
    indicators = []

    sender = email["sender"].lower()
    subject = email["subject"].lower()
    body = email["body"].lower()

    # -----------------------------------------------------
    # 1. Analyze sender address
    # -----------------------------------------------------

    sender_domain = sender.split("@")[-1]

    if any(tld in sender_domain for tld in suspicious_tlds):
        score += 3
        indicators.append(
            f"Suspicious sender domain: {sender_domain} (+3)"
        )

    # Detect misleading numbers in domains
    if re.search(r'\d', sender_domain):
        score += 2
        indicators.append(
            f"Sender domain contains unusual numbers: {sender_domain} (+2)"
        )

    # -----------------------------------------------------
    # 2. Analyze subject line
    # -----------------------------------------------------

    urgency_subject = []

    for word in urgency_words:
        if word in subject:
            urgency_subject.append(word)

    if urgency_subject:
        score += 2
        indicators.append(
            "Urgency detected in subject: "
            + ", ".join(urgency_subject)
            + " (+2)"
        )

    # Excessive exclamation marks
    if subject.count("!") >= 2:
        score += 1
        indicators.append(
            "Excessive exclamation marks in subject (+1)"
        )

    # -----------------------------------------------------
    # 3. Analyze message body for urgency
    # -----------------------------------------------------

    urgency_body = []

    for word in urgency_words:
        if word in body:
            urgency_body.append(word)

    if urgency_body:
        score += 2
        indicators.append(
            "Urgency-related language in body: "
            + ", ".join(set(urgency_body))
            + " (+2)"
        )

    # -----------------------------------------------------
    # 4. Analyze credential requests
    # -----------------------------------------------------

    credentials = []

    for word in credential_words:
        if word in body:
            credentials.append(word)

    if credentials:
        score += 3
        indicators.append(
            "Credential/account information requested: "
            + ", ".join(set(credentials))
            + " (+3)"
        )

    # -----------------------------------------------------
    # 5. Analyze hyperlinks
    # -----------------------------------------------------

    links = extract_links(email["body"])

    for link in links:

        domain = urlparse(link).netloc.lower()

        # Remove www.
        domain = domain.replace("www.", "")

        if any(tld in domain for tld in suspicious_tlds):
            score += 3
            indicators.append(
                f"Hyperlink uses suspicious domain: {domain} (+3)"
            )

        # Check for trusted brand impersonation
        for trusted in trusted_domains:

            brand = trusted.split(".")[0]

            if brand in domain and domain != trusted:
                score += 3
                indicators.append(
                    f"Possible brand impersonation in link: {domain} (+3)"
                )

    # -----------------------------------------------------
    # 6. Analyze sender vs hyperlink domain
    # -----------------------------------------------------

    for link in links:

        link_domain = urlparse(link).netloc.lower()
        link_domain = link_domain.replace("www.", "")

        if link_domain != sender_domain:
            score += 2
            indicators.append(
                "Sender domain and hyperlink domain do not match (+2)"
            )

            break

    # -----------------------------------------------------
    # 7. Determine risk classification
    # -----------------------------------------------------

    if score >= 8:
        classification = "HIGH RISK"

    elif score >= 4:
        classification = "MEDIUM RISK"

    else:
        classification = "LOW RISK"

    return score, classification, indicators, links


# ---------------------------------------------------------
# MAIN PROGRAM
# ---------------------------------------------------------

print("=" * 70)
print("             PHISHING EMAIL RISK ANALYZER")
print("=" * 70)

for email in emails:

    score, classification, indicators, links = analyze_email(email)

    print("\n" + "=" * 70)

    print("Email ID :", email["id"])
    print("Sender   :", email["sender"])
    print("Subject  :", email["subject"])

    print("\nDetected Hyperlinks:")

    if links:
        for link in links:
            print("  -", link)
    else:
        print("  No hyperlinks detected")

    print("\nDetected Indicators:")

    if indicators:
        for indicator in indicators:
            print("  -", indicator)
    else:
        print("  - No significant suspicious indicators")

    print("\nRisk Score     :", score)
    print("Classification :", classification)

    print("\nWhy this classification?")

    if classification == "HIGH RISK":
        print(
            "Multiple strong phishing indicators were detected, "
            "such as suspicious domains, urgency, credential requests "
            "or suspicious hyperlinks."
        )

    elif classification == "MEDIUM RISK":
        print(
            "Some suspicious indicators were detected, but the evidence "
            "is not strong enough to classify the message as high risk."
        )

    else:
        print(
            "Few or no suspicious indicators were detected. "
            "The message is classified as low risk."
        )

print("\n" + "=" * 70)
print("Analysis completed.")
print("=" * 70)
