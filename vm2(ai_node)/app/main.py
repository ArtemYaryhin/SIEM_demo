from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import requests
import os
from dotenv import load_dotenv
from datetime import datetime
import json
from app.model_llm import analyze_with_llm
from elasticsearch import Elasticsearch

load_dotenv('/etc/telegram_alert.env')

app = FastAPI()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
ES_HOST = os.getenv("ES_HOST", "http://$ELASTIC_HOST:9200")

es = Elasticsearch([{'scheme': 'http', 'host': '$ELASTIC_HOST', 'port': 9200}])

def send_telegram_message(text: str, reply_markup=None):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "parse_mode": "MarkdownV2"
    }
    if reply_markup:
        payload["reply_markup"] = reply_markup
    requests.post(url, json=payload)

def esc(s):
    if not isinstance(s, str):
        s = str(s)
    return s.translate(str.maketrans({
        '_': '\\_', '*': '\\*', '[': '\\[', ']': '\\]',
        '(': '\\(', ')': '\\)', '~': '\\~', '`': '\\`',
        '>': '\\>', '#': '\\#', '+': '\\+', '-': '\\-',
        '=': '\\=', '|': '\\|', '{': '\\{', '}': '\\}',
        '.': '\\.', '!': '\\!'
    }))

def save_to_elasticsearch(index, document):
    try:
        es.index(index=index, body=document)
    except Exception as e:
        print("❌ Error saving to Elasticsearch:", str(e))

def save_analysis(data, analysis, confidence_pct):
    doc = {
        "event_type": data.get("event_type", "N/A"),
        "source_ip": data.get("source_ip", "N/A"),
        "destination_ip": data.get("destination_ip", "N/A"),
        "extra_info": data.get("extra_info", "N/A"),
        "confidence": confidence_pct,
        "analysis": analysis,
        "timestamp": datetime.utcnow().isoformat()
    }
    save_to_elasticsearch("ai_analysis", doc)

def save_feedback(identifier, feedback_type, user):
    feedback = {
        "id": identifier,
        "feedback": feedback_type,
        "user": user,
        "timestamp": datetime.utcnow().isoformat()
    }
    save_to_elasticsearch("feedback", feedback)

    emoji = "✅" if feedback_type == "true" else "❌"
    msg = f"{emoji} *Feedback processed*\n\n*User:* `{esc(user)}`\n*Feedback:* `{feedback_type}`\n*Source IP:* `{identifier}`"
    send_telegram_message(msg)

@app.get("/")
def root():
    return {"message": "AI Log Analyzer is alive"}

@app.post("/alert")
async def receive_alert(request: Request):
    data = await request.json()

    event_type = esc(data.get("event_type", "N/A"))
    source_ip = esc(data.get("source_ip", "N/A"))
    destination_ip = esc(data.get("destination_ip", "N/A"))
    extra_info = esc(data.get("extra_info", "N/A"))
    severity = esc(data.get("severity", "N/A"))
    host = esc(data.get("host", "N/A"))
    timestamp = esc(data.get("timestamp", datetime.utcnow().isoformat()))

    msg1 = (
        "⚠️ *Suspicious log received*\n\n"
        f"*Timestamp:* {timestamp}\n"
        f"*Host:* {host}\n"
        f"*Type:* {event_type}\n"
        f"*Source:* {source_ip} → {destination_ip}\n"
        f"*Severity:* {severity}\n"
        f"*Details:* {extra_info}"
    )
    send_telegram_message(msg1)

    llm_result = analyze_with_llm(data)

    if 'summary' in llm_result:
        analysis = esc(llm_result['summary'])
        confidence_pct = round(llm_result.get("confidence_score", 0) * 100)
        source = esc(llm_result.get('source', 'Unknown'))
        recommendations = esc(llm_result.get('recommendations', 'No recommendations'))

        emoji = "🔴" if confidence_pct < 25 else "🟠" if confidence_pct < 50 else "🟡" if confidence_pct < 75 else "🟢"
        mood = "Critical" if confidence_pct < 25 else "Low" if confidence_pct < 50 else "Medium" if confidence_pct < 75 else "High"

        msg2 = (
            "✅ *Log analyzed with GPT*\n\n"
            f"*Confidence:* {emoji} {confidence_pct}% {mood}\n"
            f"*Summary:*\n{analysis}\n\n"
            f"*Reference:* {source}\n"
            f"*Mitigation:* {recommendations}"
        )

        save_analysis(data, analysis, confidence_pct)

        reply_markup = {
            "inline_keyboard": [
                [
                    {"text": "✅ True Positive", "callback_data": f"feedback|true|{source_ip}"},
                    {"text": "❌ False Positive", "callback_data": f"feedback|false|{source_ip}"}
                ]
            ]
        }

        send_telegram_message(msg2, reply_markup=json.dumps(reply_markup))
    else:
        error = esc(llm_result.get('error', 'Unknown error'))
        send_telegram_message(f"❗ *GPT Analysis Failed*\n\n*Reason:* {error}")

    return {"status": "received", "analyzed": True}

@app.post("/webhook")
async def telegram_webhook(request: Request):
    payload = await request.json()
    if "callback_query" in payload:
        query = payload["callback_query"]
        data = query["data"]
        user = query["from"]["username"]
        query_id = query["id"]
        parts = data.split("|")

        if parts[0] == "feedback":
            feedback_type = parts[1]
            identifier = parts[2]

            try:
                requests.post(
                    f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/answerCallbackQuery",
                    json={"callback_query_id": query_id, "text": "✅ Feedback received"}
                )
            except Exception as e:
                print("❌ Callback error:", str(e))

            save_feedback(identifier, feedback_type, user)

    return JSONResponse({"ok": True})
