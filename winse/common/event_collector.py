import enum
# collect events from the windows system
# determine irrelevant or unwanted events
# init to my windows event object

class WindowsEvent:
    # Class Attributes

    def __init__(self, name, ID, level, type, description):
        self.name = name
        self.ID = ID
        self.level = level
        self.description = description
        self.type = type


class LogLevel(enum.Enum):
    Error = "Error"
    Informational = "Informational"
    Warning = "Warning"


class LogType(enum.Enum):
    Application = "Application"
    System = "System"
    Network = "Network"
    Security = "Security"


# Class for storing all collected logs
class LogCollection:
    # Array for storing WindowsEvent objects
    collectedEvents = []

    def __init__(self):
        pass


# Init Windows Event objects
applicationCrashAppError = WindowsEvent("Application Crash", 1000, LogLevel.Error, LogType.Application, "Application Error")
applicationCrashAppHang = WindowsEvent("Application Hang", 1002, LogLevel.Error, LogType.Application, "Application Hang")
applicationCrashBlueScreenOfDeath = WindowsEvent("Application Crash - Blue Screen of Death", 1001, LogLevel.Error, LogType.System, "")
windowsServiceFailOrCrash = WindowsEvent("Windows Service Fail or Crash", [7022, 7023], LogLevel.Error, LogType.System, "")


class FirewallRuleAdd(WindowsEvent):
    pass


class FirewallRuleChange(WindowsEvent):
    pass


class FirewallRulesDeleted(WindowsEvent):
    pass


class FirewallFailedToLoadGroupPolicy(WindowsEvent):
    pass


class EventLogWasCleared(WindowsEvent):
    pass


class AuditLogWasCleared(WindowsEvent):
    pass


class NewWindowsService(WindowsEvent):
    pass


class NewApplicationInstallation(WindowsEvent):
    pass


class RemovedApplication(WindowsEvent):
    pass


class AccountLockout(WindowsEvent):
    pass


class UserAddedToPrivilegedGroup(WindowsEvent):
    pass


class SecurityEnabledGroupModification(WindowsEvent):
    pass


class SuccessfulUserLogin(WindowsEvent):
    pass


class FailedUserLogin(WindowsEvent):
    pass


class AccountLoginWithExplicitCredentials(WindowsEvent):
    pass





