#!/bin/bash

OUTPUT_DIR="/var/log/generated_logs"
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
LOG_FILE="${OUTPUT_DIR}/synthetic_ot_logs_${TIMESTAMP}.log"
LOG_GENERATOR_SCRIPT="/home/s27590/generate_ot_traffic.py"

TELEGRAM_TOKEN="$TELEGRAM_BOT_TOKEN"
CHAT_ID="$TELEGRAM_CHAT_ID"

send_telegram() {
  curl -s -X POST https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage \
    -d chat_id="${CHAT_ID}" \
    -d text="$1"
}

mkdir -p "$OUTPUT_DIR"
echo "[$(date)] 🔄 Generating synthetic OT logs..."
python3 "$LOG_GENERATOR_SCRIPT" "$LOG_FILE"

if [[ $? -ne 0 ]]; then
  send_telegram "❌ Log generation failed at $TIMESTAMP"
  exit 1
fi

echo "[$(date)] ✅ Logs saved to: $LOG_FILE"
send_telegram "✅ Generated synthetic logs and saved to: $LOG_FILE"

echo "[$(date)] 📤 Sending logs to Logstash..."
while IFS= read -r line; do
  curl -s -X POST http://$LOGSTASH_HOST:5044 \
    -H "Content-Type: application/json" \
    -d "$line" > /dev/null
done < "$LOG_FILE"

send_telegram "📤 Sent all logs to Logstash from: $LOG_FILE"
