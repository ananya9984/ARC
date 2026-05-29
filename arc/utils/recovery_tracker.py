class RecoveryEventTracker:
    def __init__(self):
        self.events = [] 

    def log_event(self, step, event):
            self.events.append({
                "step": step,
                "event": event
            })

    def get_events(self):
                return self.events