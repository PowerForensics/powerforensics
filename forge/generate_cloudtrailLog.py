import json
import random
from datetime import datetime, timedelta

# --- CONFIGURACIÓN DEL ESCENARIO ---
START_TIME = datetime(2025, 2, 9, 8, 0, 0)
ATTACKER_IP_1 = "203.0.113.50"
ATTACKER_IP_2 = "45.33.22.11"
CORP_IP = "10.50.2.40"
SYSTEM_IPS = ["127.0.0.1", "internal", "52.94.0.15"]

# --- EVENTOS DEL INCIDENTE (LA AGUJA) ---
incident_events = [
    {"t": 12, "name": "ConsoleLogin", "src": "signin", "ip": ATTACKER_IP_1, "user": "iot_service", "res": "Failure"},
    {"t": 13, "name": "ConsoleLogin", "src": "signin", "ip": ATTACKER_IP_1, "user": "iot_service", "res": "Success"},
    {"t": 14, "name": "ListUsers", "src": "iam", "ip": ATTACKER_IP_1, "user": "iot_service"},
    {"t": 15, "name": "ListBuckets", "src": "s3", "ip": ATTACKER_IP_1, "user": "iot_service"},
    {"t": 17, "name": "CreateAccessKey", "src": "iam", "ip": ATTACKER_IP_1, "user": "iot_service", "extra": {"accessKeyId": "AKIA_HACK_2025"}},
    {"t": 18, "name": "AttachUserPolicy", "src": "iam", "ip": ATTACKER_IP_1, "user": "iot_service", "extra": {"policy": "AdministratorAccess"}},
    {"t": 20, "name": "GetObject", "src": "s3", "ip": ATTACKER_IP_1, "user": "iot_service", "extra": {"key": "secrets/db_passwords.txt"}},
    {"t": 30, "name": "CreateUser", "src": "iam", "ip": ATTACKER_IP_2, "user": "iot_service", "key": "AKIA_HACK_2025", "extra": {"new_user": "backup_support_acc"}},
    {"t": 40, "name": "RunInstances", "src": "ec2", "ip": ATTACKER_IP_2, "user": "iot_service", "key": "AKIA_HACK_2025", "extra": {"type": "p3.8xlarge"}},
    {"t": 60, "name": "DeleteBucket", "src": "s3", "ip": ATTACKER_IP_2, "user": "iot_service", "key": "AKIA_HACK_2025", "extra": {"bucket": "iot-prod-backups"}}
]

# --- GENERADOR DE RUIDO (EL PAJAR) ---
noise_actions = [
    ("DescribeInstances", "ec2"), ("ListMetrics", "monitoring"), ("GetMetricData", "monitoring"),
    ("DescribeVolumes", "ec2"), ("DescribeSecurityGroups", "ec2"), ("GetSendStatistics", "ses"),
    ("DescribeVpcs", "ec2"), ("ListPolicies", "iam"), ("GetAccountSnapshot", "config")
]

all_logs = []

# Generar 1000 eventos de ruido
for i in range(1000):
    action, service = random.choice(noise_actions)
    timestamp = START_TIME + timedelta(seconds=random.randint(0, 3600))
    ip = random.choice([CORP_IP] + SYSTEM_IPS)
    user = random.choice(["admin_real", "system_worker", "readonly_user"])
    
    all_logs.append({
        "eventTime": timestamp.isoformat() + "Z",
        "eventName": action,
        "eventSource": f"{service}.amazonaws.com",
        "sourceIPAddress": ip,
        "userIdentity": {"type": "IAMUser", "userName": user}
    })

# Inyectar los eventos del incidente
for ev in incident_events:
    t_str = (START_TIME + timedelta(minutes=ev["t"])).isoformat() + "Z"
    entry = {
        "eventTime": t_str,
        "eventName": ev["name"],
        "eventSource": f"{ev['src']}.amazonaws.com",
        "sourceIPAddress": ev["ip"],
        "userIdentity": {"type": "IAMUser", "userName": ev["user"]}
    }
    if "res" in ev: entry["responseElements"] = {ev["name"]: ev["res"]}
    if "extra" in ev: entry["requestParameters"] = ev["extra"]
    if "key" in ev: entry["userIdentity"]["accessKeyId"] = ev["key"]
    all_logs.append(entry)

# Ordenar por tiempo y guardar en formato JSONL (una línea por objeto)
all_logs.sort(key=lambda x: x['eventTime'])

with open('cloudtrail_big_noise.json', 'w') as f:
    json.dump(all_logs, f, indent=2)

print("Archivo 'cloudtrail_big_noise.json' generado con 1010 eventos.")