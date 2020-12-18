def details_dictionary(description):
    return {
        "Possible Account Brute Force": "A possible account brute force has been detected. Check logs for event ID "
                                        "4624 to determine if user successfully logged in or 4740 if they were locked "
                                        "out. ",
        "Firewall - Rule Added": "New Firewall rules have been added. Normal users should not be making Firewall "
                                 "changes. View supporting events if other firewall changes have been made. ",
        "Firewall - Rule Deleted": "Firewall rules have been deleted. Normal users should not be making Firewall "
                                 "changes. View supporting events if other firewall changes have been made. ",
        "Firewall - Rule Changed": "New Firewall rules have been added. Normal users should not be making Firewall "
                                 "changes. View supporting events if other firewall changes have been made. ",
        "Firewall - Group Policy Failure": "Failure to load Firewall Group Policy. View supporting events if other "
                                           "firewall changes have been made. ",
        "Event Log Cleared": "The event log has been cleared. This should never be done under normal circumstances. "
                             "Look for supporting events of unusual usage of account management privileges. ",
        "Audit Log Cleared": "The audit log has been cleared. This should never be done under normal circumstances. "
                             "Look for supporting events of unusual usage of account management privileges. ",
        "Privilege Escalation": "Privilege escalation has taken place. Investigate changes made to privileged and "
                                "security groups immediately as a new user has been added or security group policies "
                                "have been changed.",
        "External Media Detected": "External media has been detected on the system. Check for supporting events "
                                   "related to application changes, Windows service changes, unexpected errors, "
                                   "and crashes. ",
        "A Windows Update Failed or Crashed": "A windows update failed or crashed during installation. Investigate "
                                              "the cause as this can have malicious reasons. ",
        "A New Windows Service has Been Installed": "A new Windows Service has been installed. If this is not "
                                                    "expected, investigate immediately. ",
        "Malware Detected": "Malware has been detected on the system by Windows Defender. Investigate supporting "
                            "events immediately. "
    }.get(description, "NULL")


class SecurityIncident:

    def __init__(self, description, windows_events, supporting_events, severity):
        self.description = description
        self.windows_events = windows_events  # Windows Events to look out for
        self.supporting_events = supporting_events  # Windows Events that may exist, optional
        self.severity = severity  # 1-5, 5 being the highest
        self.details = details_dictionary(description)

    def __str__(self):
        return f'{self.description}'

    def matching_event_id(self, event_id):
        if event_id in self.windows_events:
            return True
        else:
            return False

    def matching_supporting_event_id(self, event_id):
        if event_id in self.supporting_events:
            return True
        else:
            return False


class DetectedIncident:

    def __init__(self, incident, initial_event):
        self.incident = incident
        self.count = 1
        self.first_occurrence = initial_event.time_written
        self.last_occurrence = initial_event.time_written
        self.associated_events = [initial_event]
        self.supporting_events = []

    def __str__(self):
        return f'{self.incident}'

    def add_event(self, event):
        self.associated_events.append(event)
        self.count += 1
        self.first_occurrence = event.time_written

    def add_supporting_event(self, event):
        self.supporting_events.append(event.windows_event)

    def get_supporting_events(self):
        events = ""
        for event in self.supporting_events:
            events += event.name + "\n"
        return events

    def get_severity_score(self):
        score = self.incident.severity
        for supporting in self.supporting_events:
            score += 1
        return score


def analyze_event_collection(event_collection):
    incidents_detected = dict()

    # Load possible incidents
    incidents = [accountBruteForceAttempt, newFirewallRule, firewallRuleChange, firewallFailedToLoadGroupPolicy,
                 eventLogCleared, auditLogCleared, privilegeEscalation, externalMediaDetection, windowsUpdateFailure]

    for incident in incidents:
        for event in event_collection.collection:
            if incident.matching_event_id(event.event_id):
                if incident not in incidents_detected:
                    incidents_detected[incident] = DetectedIncident(incident, event)
                else:
                    incidents_detected[incident].add_event(event)

    # Get supporting events
    for incident in incidents_detected:
        for event in event_collection.collection:
            if incidents_detected[incident].incident.matching_supporting_event_id(event.event_id):
                if event.windows_event not in incidents_detected[incident].supporting_events:
                    incidents_detected[incident].add_supporting_event(event)

    return incidents_detected


accountBruteForceAttempt = SecurityIncident("Possible Account Brute Force", [4625], [4624, 4740], 0)
accountLockout = SecurityIncident("Account Lock Out", [4740], [4625], 2)
successfulLogin = SecurityIncident("Successful Login", [4624, 4648], [4625, 4728, 4732, 4756, 4735], 0)
newFirewallRule = SecurityIncident("Firewall - Rule Added", [2004], [2005, 2006, 2033, 2009], 5)
firewallRuleChange = SecurityIncident("Firewall - Rule Change", [2005], [2004, 2006, 2033, 2009], 5)
firewallRuleDeleted = SecurityIncident("Firewall - Rule Deleted", [2006, 2033], [2004, 2006, 2033, 2009], 5)
firewallFailedToLoadGroupPolicy = SecurityIncident("Firewall - Group Policy Failure", [2009], [2005, 2006, 2033],
                                                   4)
eventLogCleared = SecurityIncident("Event Log Cleared", [104], [1102, 4728, 4732, 4756, 4735], 5)
auditLogCleared = SecurityIncident("Audit Log Cleared", [1102], [104, 4728, 4732, 4756, 4735], 5)
privilegeEscalation = SecurityIncident("Privilege Escalation", [4728, 4732, 4756, 4735], [4624, 1006, 7045], 3)
externalMediaDetection = SecurityIncident("External Media Detected", [43, 400, 410], [1006, 5008, 903, 904, 7045, 1022, 1033], 1)
windowsUpdateFailure = SecurityIncident("A Windows Update Failed or Crashed", [20, 24, 25, 31, 34, 35], [], 2)
newWindowsService = SecurityIncident("A New Windows Service has Been Installed", [7045], [7022, 7023, 7024, 7026, 7032, 7034, 4728, 4732, 4756], 2)
applicationChanges = SecurityIncident("An Application has been Installed, Changed, or Removed", [903, 904, 905, 906, 907, 908], [7045, 1005, 4728, 4732, 4756, 4624], 1)
groupPolicyError = SecurityIncident("Machines with Domain Group Policy Has Errored", [1125, 1127, 1129], [], 4)
malwareDetected = SecurityIncident("Malware Detected", [1006], [1005, 1008, 2001, 3002, 43, 400, 410], 5)
windowsDefenderFailures = SecurityIncident("Windows Defender Scan and/or Update Failures", [1005, 1008, 2001, 3002], [1006, 2004, 43, 400, 410, 4728, 4732, 4756], 4)
passTheHashDetected = SecurityIncident("Pass the Hash Attack Detected", [4624], [4728, 4732, 4756, 4735, 2004, 2005, 2006], 5)
blueScreenOfDeath = SecurityIncident("Blue Screen of Death", [1001], [7022, 7023, 7024, 7026, 7031, 903, 904, 7045, 1006, 1005, 1008], 4)