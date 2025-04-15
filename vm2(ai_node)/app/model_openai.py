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

        # Подготовим историю
        history_text = ""
        if history:
            history_text += "Previous events from this IP:\n"
            for h in history[-5:]:
                history_text += f"- [{h.get('timestamp', '?')}] {h.get('extra_info', '')}\n"
            history_text += "\n"

        system_message = {
            "role": "system",
            "content": (
                "You are a cybersecurity analyst AI with 20 years experience. Based on the event, please, provide a response strictly in valid JSON format with **all 4 fields**:\n"
                "1. `summary`: a short one-line explanation of the threat.\n"
                "2. `confidence_score`: integer from 1 to 100. Be honest and realistic. If you are fully confident, return 100.\n"
                "   This score should reflect how reliable your own summary and understanding are.\n"
                "3. `source`: a URL, CVE, or documentation if available. Otherwise say 'internal reasoning'.\n"
                "4. `recommendations`: clear, practical steps to respond to the issue.\n\n"
                "Return only a JSON object. No explanations, no markdown, no preambles."
            )
        }

        user_message = {
            "role": "user",
            "content": history_text + (
                f"Event Details:\n"
                f"Timestamp: {timestamp}\n"
                f"Severity: {severity}\n"
                f"Event Type: {event_type}\n"
                f"Source IP: {source_ip}\n"
                f"Destination IP: {destination_ip}\n"
                f"Extra Info: {extra_info}"
            )
        }

        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[system_message, user_message],
            temperature=0.3,
            max_tokens=300
        )

        raw_output = response.choices[0].message["content"].strip()
        print("✅ OpenAI raw response:", raw_output)

        try:
            result = json.loads(raw_output)
            result["model_used"] = "openai"
            return result
        except json.JSONDecodeError as je:
            print("❌ JSON parse error:", je)
            return {"error": f"Invalid JSON response: {raw_output}"}

    except Exception as e:
        print("❌ OpenAI Exception:", traceback.format_exc())
        return {"error": str(e)}
