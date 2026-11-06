import ollama

print("================================")
print(" AI PHISHING EMAIL DETECTOR")
print("================================")

email = input("\nEnter the email message: ")

response = ollama.chat(
    model='qwen2.5:3b',
    messages=[
        {
            'role': 'system',
            'content': """
            You are an AI Phishing Email Detector.
            Analyse the email provided by the user.

            Identify suspicious signs such as:
            - Fake links
            - Urgent requests
            - Requests for passwords
            - Suspicious attachments
            - Fake offers

            Give your result as:
            1. SAFE or SUSPICIOUS
            2. Reasons
            3. Safety advice

            Never claim an email is definitely safe
            based only on its text.
            """
        },
        {
            'role': 'user',
            'content': email
        }
    ]
)

print("\n===== ANALYSIS RESULT =====")
print(response['message']['content'])