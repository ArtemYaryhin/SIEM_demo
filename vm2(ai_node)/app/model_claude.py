import os
import requests
import json

ANTHROPIC_API_KEY = os.getenv("CLAUDE_API_KEY")

def analyze_with_claude(data, history=None):
    endpoint = "https://api.anthropic.com/v1/messages"
    headers = {
        "x-api-key": ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json"
    }

    messages = [
        {
            "role": "user",
            "content": (
                "Analyze this suspicious event and respond ONLY in valid JSON with keys "
                "`summary` and `confidence_score` (0.0–1.0)."
                "\n\nEvent:\n"
                f"{json.dumps(data, indent=2)}"
            )
        }
    ]

    if history:
        messages.insert(0, {
            "role": "user",
            "content": "History of previous events:\n" + json.dumps(history[-5:], indent=2)
        })

    payload = {
        "model": "claude-2",
        "max_tokens": 300,
        "temperature": 0.2,
        "messages": messages
    }

    response = requests.post(endpoint, headers=headers, json=payload)
    result = response.json()

    try:
        raw = result["content"][0]["text"].strip()
        return json.loads(raw)
    except Exception as e:
        return {"error": f"Claude JSON error: {str(e)}", "raw": result}
