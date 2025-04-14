from app.model_openai import analyze_with_openai
from app.model_claude import analyze_with_claude
from app.model_local_llama import analyze_with_llama

def analyze_with_best_model(data, history=None):
    try:
        return analyze_with_openai(data, history=history)
    except Exception as e:
        print("⚠️ OpenAI failed:", e)

    try:
        return analyze_with_claude(data, history=history)
    except Exception as e:
        print("⚠️ Claude failed:", e)

    try:
        return analyze_with_llama(data, history=history)
    except Exception as e:
        print("❌ All models failed:", e)

    return {"error": "All models unavailable"}
