import os
import openai
import json
import traceback

openai.api_key = os.getenv("OPENAI_API_KEY")

def analyze_with_llm(data):
    try:
        event_type = data.get("event_type", "Unknown")
        source_ip = data.get("source_ip", "Unknown")
        destination_ip = data.get("destination_ip", "Unknown")
        extra_info = data.get("extra_info", "N/A")
        timestamp = data.get("timestamp", "N/A")
        severity = data.get("severity", "N/A")

        system_message = {
            "role": "system",
            "content": (
                "You are an AI security analyst. Based on the input, return a JSON object with:\n"
                "1. 'summary': one-line summary of the event\n"
                "2. 'confidence_score': float from 0.0 to 1.0\n"
                "Return only valid JSON."
            )
        }

        user_message = {
            "role": "user",
            "content": (
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

        raw = response.choices[0].message["content"].strip()
        try:
            return json.loads(raw)
        except json.JSONDecodeError as e:
            return {"error": f"Invalid JSON: {raw}"}

    except Exception as e:
        return {"error": traceback.format_exc()}
