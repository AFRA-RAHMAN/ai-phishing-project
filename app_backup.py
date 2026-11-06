import re
import json
import os
import ollama

from flask import Flask, render_template, request

app = Flask(__name__)

MODEL = "qwen2.5:3b"


def check_email(sender, subject, body):
    email_text = f"{subject} {body}".lower()

    findings = []
    rule_score = 0

    # Check for suspicious links
    if re.search(r"https?://", email_text):
        findings.append("Email contains a URL.")
        rule_score += 10

    # Check for urgency
    urgency_words = [
        "urgent", "immediately", "expires",
        "act now", "account suspended"
    ]

    for word in urgency_words:
        if word in email_text:
            findings.append(f"Urgency language detected: {word}")
            rule_score += 10
            break

    # Check for password or OTP requests
    credential_words = [
        "password", "otp", "verification code",
        "login details"
    ]

    for word in credential_words:
        if word in email_text:
            findings.append(f"Sensitive information request: {word}")
            rule_score += 15
            break

    # Check for payment requests
    payment_words = [
        "bank details", "credit card",
        "payment", "transfer money"
    ]

    for word in payment_words:
        if word in email_text:
            findings.append(f"Payment-related language: {word}")
            rule_score += 15
            break

    rule_score = min(rule_score, 60)

    # Ask the local AI model to analyse the email
    prompt = f"""
    Analyse this email for possible phishing.

    Sender: {sender}
    Subject: {subject}
    Email body: {body}

    Return ONLY valid JSON in this format:
    {{
        "verdict": "Suspicious or Likely Safe",
        "ai_score": 0,
        "reasons": ["reason 1", "reason 2"],
        "confidence": "Low, Medium or High",
        "advice": "Safety recommendation"
    }}

    ai_score must be an integer between 0 and 40.
    Do not assume an email is safe just because it looks professional.
    Explain uncertainty when evidence is insufficient.
    """

    ai_result = ollama.chat(
        model=MODEL,
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ]
    )

    response_text = ai_result["message"]["content"]

    # Validate the AI's JSON response
    try:
        ai_data = json.loads(response_text)

        if not isinstance(ai_data, dict):
            raise ValueError("AI response is not an object")

        if not isinstance(ai_data.get("ai_score"), int):
            raise ValueError("Invalid AI score")

        ai_data["ai_score"] = max(
            0, min(ai_data["ai_score"], 40)
        )

        if not isinstance(ai_data.get("reasons"), list):
            raise ValueError("Invalid AI reasons")

        if not isinstance(ai_data.get("advice"), str):
            raise ValueError("Invalid AI advice")

    except (json.JSONDecodeError, ValueError, TypeError):
        ai_data = {
            "verdict": "Analysis incomplete",
            "ai_score": 0,
            "reasons": ["AI returned an invalid response."],
            "confidence": "Low",
            "advice": "Please try the analysis again."
        }

    total_score = min(
        100, rule_score + ai_data["ai_score"]
    )

    if total_score <= 24:
        category = "Low"
    elif total_score <= 49:
        category = "Medium"
    elif total_score <= 74:
        category = "High"
    else:
        category = "Critical"

    return {
        "score": total_score,
        "category": category,
        "rule_findings": findings,
        "ai": ai_data
    }


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    error = None

    if request.method == "POST":
        sender = request.form.get("sender", "").strip()
        subject = request.form.get("subject", "").strip()
        body = request.form.get("body", "").strip()

        if not sender or not subject or not body:
            error = "Please complete all three fields."

        else:
            try:
                result = check_email(sender, subject, body)

            except Exception:
                error = (
                    "Could not connect to the local AI model. "
                    "Check that Ollama is running and the model "
                    "qwen2.5:3b is installed."
                )

    return render_template(
        "index.html",
        result=result,
        error=error
    )


if __name__ == "__main__":
    app.run(
        debug=os.environ.get("FLASK_DEBUG", "").lower() in {"1", "true", "yes"}
    )