# look through all collected windows events that have been sorted by Crticial events
# analyze to make decisions


class SecurityIncident:
    # Class Attributes

    def __init__(self, description, severity):
        self.description = description
        self.windowsEvents = []  # Windows Events to look out for
        self.severity = severity