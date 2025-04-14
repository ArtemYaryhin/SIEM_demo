import os
import openai
import json
import traceback

openai.api_key = os.getenv("OPENAI_API_KEY")

def analyze_with_openai(data, history=None):
    try:
        event_type = data.get("event_type", "Unknown")
        source_ip = data.get("source_ip", "Unknown")
        destination_ip = data.get("destination_ip", "Unknown")
        extra_info = data.get("extra_info", "N/A")
        timestamp = data.get("timestamp", "N/A")
        severity = data.get("severity", "N/A")

        # Подготовим history, если есть
        history_text = ""
        if history:
            history_text = "Recent related events:\n" + json.dumps(history[-5:], indent=2) + "\n\n"

        system_message = {
            "role": "system",
            "content": (
                "You are an AI security analyst. Based on the input, return a JSON object with:\n"
                "1. 'summary': a one-line summary of the threat like:\n"
                "   '[timestamp] [severity] [event_type] attack from [source_ip] targeting [destination_ip]: [extra_info]'\n"
                "2. 'confidence_score': a float from 0.0 to 1.0 indicating how confident you are.\n"
                "Return valid JSON only."
            )
        }

        user_message = {
            "role": "user",
            "content": history_text + (
                f"Timestamp: {timestamp}\n"
                f"Severity: {severity}\n"
                f"Type: {event_type}\n"
                f"Source: {source_ip}\n"
                f"Destination: {destination_ip}\n"
                f"Details: {extra_info}"
            )
        }

        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[system_message, user_message],
            temperature=0.2,
            max_tokens=150,
        )

        response_text = response.choices[0].message["content"].strip()
        print("✅ OpenAI raw response:", response_text)

        try:
            return json.loads(response_text)
        except json.JSONDecodeError as je:
            return {"error": f"Invalid JSON response: {response_text}"}

    except Exception as e:
        return {"error": traceback.format_exc()}
