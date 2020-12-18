import enum
import win32evtlog
import win32con
import win32evtlogutil
import traceback
import time
import sys
import datetime


class EventCollection:
    log_types = ["System", "Application"]  # Security

    def __init__(self, time_window_hours):
        self.logs = []
        self.collection = []
        self.time_window_hours = time_window_hours
        for log_type in self.log_types:
            collect_events(self, log_type, time_window_hours)  # Collect events

        self.collection = categorize_events(self.logs)  # Categorize events


class WindowsEvent:

    def __init__(self, name, event_id, level, log_type):
        self.name = name
        self.event_id = event_id
        self.level = level
        self.log_type = log_type

    def __str__(self):
        return f'{self.name}'


class LogLevel(enum.Enum):
    Error = "Error"
    Informational = "Informational"
    Warning = "Warning"


class LogType(enum.Enum):
    Application = "Application"
    System = "System"
    Network = "Network"
    Security = "Security"


class LoggedEvent:

    def __init__(self, windows_event, event_id, source, msg, time_written):
        self.windows_event = windows_event
        self.event_id = event_id
        self.source = source
        self.msg = msg
        self.time_written = time_written


def collect_events(collection, log_type, time_window_hours):
    begin_sec = time.time()
    begin_time = time.strftime('%H:%M:%S  ', time.localtime(begin_sec))

    seconds_per_hour = 60 * 60
    how_many_seconds_back_to_search = seconds_per_hour * time_window_hours
    gathered_events = []

    try:
        log_handle = win32evtlog.OpenEventLog('localhost', log_type)
        total = win32evtlog.GetNumberOfEventLogRecords(log_handle)
        print("Scanning through {} events on {} in {}".format(total, 'localhost', log_type))
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        event_count = 0
        events = 1
        while events:
            events = win32evtlog.ReadEventLog(log_handle, flags, 0)
            seconds = begin_sec
            for event in events:
                the_time = event.TimeGenerated.Format()
                seconds = date2sec(the_time)
                comparison = begin_sec - how_many_seconds_back_to_search
                if seconds < comparison: break
                if event.EventType == win32con.EVENTLOG_ERROR_TYPE or event.EventType == win32con.EVENTLOG_INFORMATION_TYPE or event.EventType == win32con.EVENTLOG_WARNING_TYPE:  # looks to only get Error logs, may change to by ID
                    event_count += 1
                    collection.logs.append(event)  # Add event
            if seconds < comparison: break  # get out of while loop

        win32evtlog.CloseEventLog(log_handle)
    except:
        try:
            print(traceback.print_exc(sys.exc_info()))
        except:
            print('Exception while printing traceback')


def date2sec(evt_date):
    '''
    This function converts dates with format
    'Thu Jul 13 08:22:34 2017' to seconds since 1970.
    '''
    dt = datetime.datetime.strptime(evt_date, "%a %b %d %H:%M:%S %Y")
    return dt.timestamp()


# Init Windows Event objects
applicationCrashAppError = WindowsEvent("Application Crash", 1000, LogLevel.Error, LogType.Application)
applicationCrashAppHang = WindowsEvent("Application Hang", 1002, LogLevel.Error, LogType.Application)
applicationCrashBlueScreenOfDeath = WindowsEvent("Application Crash - Blue Screen of Death", 1001, LogLevel.Error,
                                                 LogType.System)
windowsServiceFailOrCrash = WindowsEvent("Windows Service Fail or Crash", [7022, 7023], LogLevel.Error, LogType.System)
windowsUpdateFailed = WindowsEvent("Windows Update Failed or Crashed", [20, 24, 25, 31, 34, 35], LogLevel.Error,
                                   LogType.System)
firewallRuleAdd = WindowsEvent("New Firewall Rule Added", 2004, LogLevel.Informational, LogType.Security)
firewallRuleChanged = WindowsEvent("Firewall Rule Changed", 2005, LogLevel.Informational, LogType.Security)
firewallRuleDeleted = WindowsEvent("Firewall Rule Deleted", [2006, 2033], LogLevel.Informational, LogType.Security)
firewallFailedToLoadGroupPolicy = WindowsEvent("Failed to load Group Firewall Policy", [2006, 2033], LogLevel.Error,
                                               LogType.Security)
eventLogCleared = WindowsEvent("Event Log was Cleared", 104, LogLevel.Informational, LogType.System)
auditLogCleared = WindowsEvent("Audit Log was Cleared", 1102, LogLevel.Informational, LogType.Security)
newWindowsService = WindowsEvent("New Windows Service", 7045, LogLevel.Informational, LogType.System)
newMSIFileInstalled = WindowsEvent("New MSI File Installed", [1022, 1033], LogLevel.Informational, LogType.Application)
newApplicationInstallation = WindowsEvent("New Application Installed", [903, 904], LogLevel.Informational,
                                          LogType.Application)
updatedApplication = WindowsEvent("An Application Has Been Updated", [905, 906], LogLevel.Informational,
                                  LogType.Application)
removedApplication = WindowsEvent("An Application Has Been Removed", [907, 908], LogLevel.Informational,
                                  LogType.Application)
accountLockout = WindowsEvent("An Account Has Been Locked Out", 4740, LogLevel.Informational, LogType.Security)
userAddedToPrivilegedGroup = WindowsEvent("A User Has Been Added to Privileged Group", [4728, 4732, 4756],
                                          LogLevel.Informational, LogType.Security)
securityGroupModification = WindowsEvent("A Security Enabled Group Modification Has Been Made", 4735,
                                         LogLevel.Informational, LogType.Security)
successfulUserLogin = WindowsEvent("A User Has Successfully Logged In", 4624, LogLevel.Informational, LogType.Security)
failedUserLogin = WindowsEvent("A Failed User Login Attempt Has Been Made", 4625, LogLevel.Informational,
                               LogType.Security)
loginWithExplicitCredentials = WindowsEvent("A Login Has Been Made With Explicit Credentials", 4648,
                                            LogLevel.Informational, LogType.Security)
groupPolicyApplicationFailed = WindowsEvent("Group Policy Application Failed due to Connectivity", 1129, LogLevel.Error,
                                            LogType.System)
newExternalDevice = WindowsEvent("New External Device Detected", [43, 400, 410], LogLevel.Informational, LogType.System)
scanFailed = WindowsEvent("Windows Defender Scan Failed", [1005], LogLevel.Error, LogType.System)
detectedMalware = WindowsEvent("Windows Defender Detected Malware", [1006], LogLevel.Warning, LogType.Security)
actionOnMalwareFailed = WindowsEvent("Action on Malware Failed", [1008], LogLevel.Error, LogType.Security)
failedToUpdateSignatures = WindowsEvent("Failed to Update Signatures", [2001], LogLevel.Error, LogType.Security)
signatureRevert = WindowsEvent("Reverting to Last Known Good Set of Signatures", [2004], LogLevel.Error, LogType.Security)
protectionFailed = WindowsEvent("Real Time Protection Failed", [3002], LogLevel.Error, LogType.Security)
passTheHashDetected = WindowsEvent("Pass the Hash Attack Detected", [4624], LogLevel.Informational, LogType.Security)


def event_dictionary(event_id):
    event_objects = {
        1000: applicationCrashAppError,
        1002: applicationCrashAppHang,
        1001: applicationCrashBlueScreenOfDeath,
        7022: windowsServiceFailOrCrash,
        2023: windowsServiceFailOrCrash,
        7024: windowsServiceFailOrCrash,
        7026: windowsServiceFailOrCrash,
        7031: windowsServiceFailOrCrash,
        7032: windowsServiceFailOrCrash,
        7034: windowsServiceFailOrCrash,
        20: windowsUpdateFailed,
        24: windowsUpdateFailed,
        25: windowsUpdateFailed,
        31: windowsUpdateFailed,
        34: windowsUpdateFailed,
        35: windowsUpdateFailed,
        2004: firewallRuleAdd,
        2005: firewallRuleChanged,
        2006: firewallRuleDeleted,
        2009: firewallFailedToLoadGroupPolicy,
        104: eventLogCleared,
        1102: auditLogCleared,
        7045: newWindowsService,
        1022: newMSIFileInstalled,
        1023: newMSIFileInstalled,
        903: newApplicationInstallation,
        904: newApplicationInstallation,
        905: updatedApplication,
        906: updatedApplication,
        907: removedApplication,
        908: removedApplication,
        4740: accountLockout,
        4728: userAddedToPrivilegedGroup,
        4732: userAddedToPrivilegedGroup,
        4756: userAddedToPrivilegedGroup,
        4735: securityGroupModification,
        4624: successfulUserLogin,
        4625: failedUserLogin,
        4648: loginWithExplicitCredentials,
        1129: groupPolicyApplicationFailed,
        43: newExternalDevice,
        400: newExternalDevice,
        410: newExternalDevice,
        1005: scanFailed,
        1006: detectedMalware,
        1008: actionOnMalwareFailed,
        2001: failedToUpdateSignatures,
        2004: signatureRevert,
        3002: protectionFailed,
        4624: passTheHashDetected
    }
    return event_objects.get(event_id, "NULL")


def categorize_events(gathered_events):
    categorized_events = []

    for event in gathered_events:
        windows_event = event_dictionary(event.EventID)

        if windows_event != "NULL":
            if windows_event.log_type == LogType.System:
                msg = str(win32evtlogutil.SafeFormatMessage(event, "System"))
            if windows_event.log_type == LogType.Application:
                msg = str(win32evtlogutil.SafeFormatMessage(event, "Application"))
            if windows_event.log_type == LogType.Security:
                msg = str(win32evtlogutil.SafeFormatMessage(event, "Security"))
            msg = msg.replace('<', '&lt;')
            msg = msg.replace('>', '&gt;')
            if msg == "" or msg == None:
                for s in event.StringInserts:
                    msg += "x {}<br/>".format(s)

            categorized_events.append(
                LoggedEvent(windows_event, event.EventID, event.SourceName, msg, event.TimeWritten))
    return categorized_events
