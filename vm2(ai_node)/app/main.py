from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import requests
import os
from dotenv import load_dotenv
from datetime import datetime
import json
from app.model_router import analyze_with_best_model
from elasticsearch import Elasticsearch

load_dotenv('/etc/telegram_alert.env')

app = FastAPI()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")

es = Elasticsearch([{'scheme': 'http', 'host': ES_HOST.replace("http://", "").replace("https://", ""), 'port': 9200}])

def send_telegram_message(text: str, reply_markup=None):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "parse_mode": "MarkdownV2"
    }
    if reply_markup:
        payload["reply_markup"] = reply_markup
    response = requests.post(url, json=payload)
    print("📬 Telegram status:", response.status_code, response.text)
    return response.status_code == 200

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
        response = es.index(index=index, body=document)
        print("✅ Data saved to Elasticsearch:", response)
    except Exception as e:
        print("❌ Error saving to Elasticsearch:", str(e))

def fetch_history(source_ip):
    query = {
        "query": {
            "match": {
                "source_ip": source_ip
            }
        },
        "size": 10,
        "sort": [
            {"timestamp": {"order": "desc"}}
        ]
    }
    try:
        res = es.search(index="ai_analysis", body=query)
        return [hit["_source"] for hit in res["hits"]["hits"]]
    except:
        return []

def save_analysis(data, analysis, confidence_pct):
    analysis_entry = {
        "event_type": data.get("event_type", "N/A"),
        "source_ip": data.get("source_ip", "N/A"),
        "destination_ip": data.get("destination_ip", "N/A"),
        "extra_info": data.get("extra_info", "N/A"),
        "confidence": confidence_pct,
        "analysis": analysis,
        "timestamp": datetime.utcnow().isoformat()
    }
    save_to_elasticsearch("ai_analysis", analysis_entry)

def save_feedback(identifier, feedback_type, user):
    feedback_entry = {
        "id": identifier,
        "feedback": feedback_type,
        "user": user,
        "timestamp": datetime.utcnow().isoformat()
    }
    save_to_elasticsearch("feedback", feedback_entry)

    emoji = "✅" if feedback_type == "true" else "❌"
    confirmation_message = (
        f"{emoji} *Feedback processed*\n\n"
        f"*User:* `{esc(user)}`\n"
        f"*Feedback:* `{feedback_type}`\n"
        f"*Source IP:* `{identifier}`"
    )
    send_telegram_message(confirmation_message)

@app.get("/")
def root():
    return {"message": "AI Log Analyzer is alive"}

@app.post("/alert")
async def receive_alert(request: Request):
    data = await request.json()
    print("🔍 RAW PAYLOAD:", data)

    event_type = esc(data.get("event_type", "N/A"))
    source_ip = esc(data.get("source_ip", "N/A"))
    destination_ip = esc(data.get("destination_ip", "N/A"))
    extra_info = esc(data.get("extra_info", "N/A"))
    severity = esc(data.get("severity", "N/A"))
    host = esc(data.get("host", "N/A"))
    timestamp = esc(data.get("timestamp", datetime.utcnow().isoformat()))

    message1 = (
        "⚠️ *Suspicious log received*\n\n"
        f"*Timestamp:* {timestamp}\n"
        f"*Host:* {host}\n"
        f"*Type:* {event_type}\n"
        f"*Source:* {source_ip} → {destination_ip}\n"
        f"*Severity:* {severity}\n"
        f"*Details:* {extra_info}"
    )
    send_telegram_message(message1)

    history = fetch_history(data.get("source_ip", ""))
    llm_result = analyze_with_best_model(data, history=history)

    if 'summary' in llm_result:
        analysis = esc(llm_result['summary'])
        raw_confidence = llm_result.get("confidence_score", 0)
        confidence_pct = round(raw_confidence * 100)
        source = esc(llm_result.get('source', 'Unknown source'))
        recommendations = esc(llm_result.get('recommendations', 'No recommendations available'))

        if confidence_pct < 25:
            emoji, mood = "🔴", "Critical"
        elif confidence_pct < 50:
            emoji, mood = "🟠", "Low"
        elif confidence_pct < 75:
            emoji, mood = "🟡", "Medium"
        else:
            emoji, mood = "🟢", "High"

        message2 = (
            "✅ *Log analyzed with AI*\n\n"
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

        send_telegram_message(message2, reply_markup=json.dumps(reply_markup))
    else:
        error = esc(llm_result.get('error', 'Unknown error'))
        message2 = (
            "❗ *AI Analysis Failed*\n\n"
            f"*Reason:* {error}"
        )
        send_telegram_message(message2)

    return {"status": "received", "analyzed": True}

@app.post("/webhook")
async def telegram_webhook(request: Request):
    payload = await request.json()
    print("🤖 Webhook payload:", payload)

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
                r = requests.post(
                    f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/answerCallbackQuery",
                    json={"callback_query_id": query_id, "text": "✅ Feedback received"}
                )
                print("📩 Telegram callback status:", r.status_code, r.text)
            except Exception as e:
                print("❌ Callback error:", str(e))

            save_feedback(identifier, feedback_type, user)

    return JSONResponse({"ok": True})
