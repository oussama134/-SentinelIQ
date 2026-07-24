from dataclasses import dataclass
from collections import defaultdict
from datetime import datetime

@dataclass
class Rule:
    rule_id: str
    threshold: int
    window_seconds: int
    alert_name: str
    user_agent: str


DEFAULT_RULES = [
    Rule(
        rule_id="R001",
        threshold=10,
        window_seconds=5,
        alert_name="BURST_ATTACK"
    ),
    Rule(
        rule_id="R002",
        threshold=5,        
        window_seconds=10,
        alert_name="PORT_SCAN"
    ),
    Rule(
        rule_id="R003",
        threshold=20,
        window_seconds=120,
        alert_name="slow attack"
    ),
    Rule(
        rule_id="R004",
        threshold=15,
        window_seconds=120,
        alert_name="BRUTEFORCE_ATTACK"
    )

]


profiles = defaultdict(lambda: {
    "timestamps": [],
    "ports":[],
    "ips" : set()
    
})

def evaluate_rules(ip):
    now = datetime.now()
    profile = profiles[ip]

    alerts = []

    for rule in DEFAULT_RULES:
        # Filter timestamps inside window
        recent = [
            t for t in profile["timestamps"]
            if (now - t).seconds <= rule.window_seconds
        ]

        if len(recent) > rule.threshold:
            alerts.append({
                "ip": ip,
                "rule": rule.rule_id,
                "alert": rule.alert_name,
                "count": len(recent)
            })

    return alerts

def detect_portscan(ip,port):
    profile=profiles[ip]
    profile["ports"].append(port)

    # Example: if we see 5 different ports in 10 seconds, alert
    now = datetime.now()
    for rule in DEFAULT_RULES:
        recent_10 =[t for t in profile["timestamps"] if (now - t).seconds <= rule.window_seconds]
        if len((profile["ports"])) > 10 and len(recent_10) > rule.threshold:
            return f"Port scan detected for IP: {ip}"

def detect_slowris (ip):
    profile = profiles[ip]
    now = datetime.now()
    profile["timestamps"].append(now)
    # Example: if we see 20 connections in 2 minutes, alert , 15 portswithin 2 minutes BUT never more than 2 requests per second#
    total_requests = len(profile["timestamps"])
    recent = [t for t in profile["timestamps"] if (now - t).seconds <= rule.window_seconds]    
    total_seconds = (now - profile["timestamps"][0]).seconds
    unique_ports = set(profile["ports"])
    if total_seconds == 0:
        rate = 0
    else:
        rate = total_requests / total_seconds

    if len(unique_ports) > 15 and recent and rate < 2 :
        return f"slowris detected from ip : {ip}"
    


def   detecect_distrubuted_attack(user_agent,ip):
    profile = profiles[user_agent]
    now = datetime.now()
    profile["ips"].add((ip))
    profile["timestamps"].append(now)
    recent = [t for t in profile['timestamps'] if (now - t).seconds >= 30 ]

    if len(profile["user_agent"]) == 1 and len(profile["ips"]) > 15 and len(recent) > 30:
        return f"Distributed attack detected from user agent: {user_agent} with IPs: {profile['ips']}"



    # Example: if we see 15 unique IPs in 2 minutes, alert
