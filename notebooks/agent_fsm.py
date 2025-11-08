
# agent_fsm.py — deterministic FSM module for demo
import json
from datetime import datetime

class AgentFSM:
    def __init__(self, config=None):
        self.config = config or {
            "prob_threshold_investigate": 0.7,
            "prob_threshold_report": 0.85,
            "prob_threshold_contain": 0.9,
            "persistence_window": 2,
            "containment_duration": 3
        }
        self.state = "Monitoring"
        self.memory = []
        self.containment_timer = 0
        self.trace = []

    def _log(self, alert, action, reason):
        entry = {
            "time": datetime.now().isoformat(),
            "state": self.state,
            "packet_idx": int(alert.get("packet_idx", -1)),
            "prob": float(alert.get("packet_base_prob", alert.get("prob",0.0))),
            "action": action,
            "reason": reason
        }
        self.trace.append(entry)
        return entry

    def transition(self, new_state, reason):
        prev = self.state
        self.state = new_state
        return f"{prev} -> {new_state} ({reason})"

    def handle_alert(self, alert):
        prob = float(alert.get("packet_base_prob", alert.get("prob",0.0)))
        self.memory.append({"prob": prob, "packet_idx": alert.get("packet_idx")})
        self.memory = self.memory[-self.config["persistence_window"]:]
        if self.state == "Monitoring":
            if prob >= self.config["prob_threshold_investigate"]:
                msg = self.transition("Investigating", "High prob")
                return self._log(alert, "investigate", msg)
            else:
                return self._log(alert, "monitor", "below threshold")
        elif self.state == "Investigating":
            if all(m["prob"] > self.config["prob_threshold_report"] for m in self.memory):
                msg = self.transition("Reporting", "persistent")
                return self._log(alert, "report", msg)
            if prob < 0.5:
                msg = self.transition("Monitoring", "normalized")
                return self._log(alert, "monitor", msg)
            return self._log(alert, "investigate", "continue")
        elif self.state == "Reporting":
            if all(m["prob"] > self.config["prob_threshold_contain"] for m in self.memory):
                msg = self.transition("Containment", "critical")
                self.containment_timer = self.config["containment_duration"]
                return self._log(alert, "contain", msg)
            if prob < 0.6:
                msg = self.transition("Monitoring", "false alarm")
                return self._log(alert, "monitor", msg)
            return self._log(alert, "report", "persistence")
        elif self.state == "Containment":
            self.containment_timer -= 1
            if self.containment_timer <= 0:
                msg = self.transition("Monitoring", "release")
                return self._log(alert, "release", msg)
            return self._log(alert, "contain", "ongoing")

    def save_trace(self, path):
        with open(path, "w") as f:
            json.dump(self.trace, f, indent=2)
