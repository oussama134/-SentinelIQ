from dataclasses import dataclass
from collections import defaultdict
from datetime import datetime, timedelta

@dataclass
class Rule : 
    rule_id : str
    treshold : float 
    window_seconds : int 
    alert_name : str


DEFAULT_RULES = [
    Rule(
        rule_id = "R01",
        treshold = 1,
        window_seconds = 5,
        alert_name = "BURST_ATTACK"
    )

]

profile = defaultdict(lambda: {})