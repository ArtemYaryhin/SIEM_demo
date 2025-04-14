import json, time, random
from datetime import datetime

OS_CHOICES = ["Linux", "Windows", "RTOS", "FreeRTOS"]
SYSTEMS = ["PLC", "HMI", "SCADA", "Sensor", "Controller"]
FLAGS = ["ACK", "SYN", "FIN", "RST", "URG", "PSH"]
LOG_FILE_PATH = "/var/log/ot-traffic.log"

def generate_log(is_suspicious=False):
    src_ip = f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
    dst_ip = f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"
    port = random.choice([502, 20000, 44818, 23, 21, 4444, 3389, 5900]) if is_suspicious else random.randint(1024, 65535)
    ttl = random.choice([10, 20, 255, 5, 129]) if is_suspicious else random.randint(40, 120)
    severity = "high" if is_suspicious else "low"
    system = random.choice(SYSTEMS)
    os = random.choice(OS_CHOICES)
    flags = random.sample(FLAGS, k=random.randint(1, 3))
    info = "Potential brute force" if is_suspicious else "Normal polling request"

    return {
        "event_type": "network_traffic",
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "port": port,
        "ttl": ttl,
        "severity": severity,
        "extra_info": info,
        "system": system,
        "os": os,
        "flags": flags,
        "timestamp": datetime.utcnow().isoformat()
    }

def generate_logs_batch(batch_size=100, suspicious_ratio=0.1):
    return [generate_log(random.random() < suspicious_ratio) for _ in range(batch_size)]

def main():
    while True:
        logs = generate_logs_batch()
        with open(LOG_FILE_PATH, "a") as f:
            for log in logs:
                f.write(json.dumps(log) + "\n")
        print(f"[{datetime.utcnow().isoformat()}] ✅ Saved {len(logs)} logs to {LOG_FILE_PATH}")
        time.sleep(30)

if __name__ == "__main__":
    main()
