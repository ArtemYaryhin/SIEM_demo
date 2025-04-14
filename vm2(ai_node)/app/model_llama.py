import os
import json
import requests

TOGETHER_API_KEY = os.getenv("TOGETHER_API_KEY")
LLAMA_API_URL = "https://api.together.xyz/v1/chat/completions"

def analyze_with_llama(data, history=None):
    # Подготовка prompt
    messages = [
        {
            "role": "system",
            "content": (
                "You are an AI security analyst. Based on the input, respond ONLY in valid JSON format:\n"
                "{ \"summary\": \"...\", \"confidence_score\": 0.0-1.0 }\n"
                "Be concise and accurate."
            )
        },
        {
            "role": "user",
            "content": f"Event data:\n{json.dumps(data, indent=2)}"
        }
    ]

    if history:
        messages.insert(1, {
            "role": "user",
            "content": "Recent history:\n" + json.dumps(history[-5:], indent=2)
        })

    # Запрос к Together.ai
    payload = {
        "model": "meta-llama/Llama-3-8B-Instruct",
        "messages": messages,
        "temperature": 0.2,
        "max_tokens": 300,
        "top_p": 0.9
    }

    headers = {
        "Authorization": f"Bearer {TOGETHER_API_KEY}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(LLAMA_API_URL, headers=headers, json=payload)
        result = response.json()
        response_text = result["choices"][0]["message"]["content"].strip()

        try:
            return json.loads(response_text)
        except json.JSONDecodeError as e:
            return {"error": f"LLaMA JSON parse error: {str(e)}", "raw": response_text}

    except Exception as e:
        return {"error": f"LLaMA API error: {str(e)}"}
