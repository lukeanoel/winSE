$evt = new-object System.Diagnostics.EventLog("Application")
$evt.Source = "MyEvent2"
$infoevent = [System.Diagnostics.EventLogEntryType]::Information
$evt.WriteEntry("Failed Login Event",$infoevent,4625)

$evt = new-object System.Diagnostics.EventLog("Application")
$evt.Source = "MyEvent2"
$infoevent = [System.Diagnostics.EventLogEntryType]::Information
$evt.WriteEntry("Success Login Event",$infoevent,4624)

$evt = new-object System.Diagnostics.EventLog("Application")
$evt.Source = "MyEvent"
$infoevent = [System.Diagnostics.EventLogEntryType]::Information
$evt.WriteEntry("Windows Service Change Event",$infoevent,7045)

$evt = new-object System.Diagnostics.EventLog("Application")
$evt.Source = "MyEvent2"
$infoevent = [System.Diagnostics.EventLogEntryType]::Information
$evt.WriteEntry("Privileged User Added Event",$infoevent,4728)

$evt = new-object System.Diagnostics.EventLog("Application")
$evt.Source = "MyEvent2"
$infoevent = [System.Diagnostics.EventLogEntryType]::Error
$evt.WriteEntry("App Install Event",$infoevent,903)

$evt = new-object System.Diagnostics.EventLog("Application")
$evt.Source = "MyEvent2"
$infoevent = [System.Diagnostics.EventLogEntryType]::Information
$evt.WriteEntry("Firewall Delete Event",$infoevent,2006)

$evt = new-object System.Diagnostics.EventLog("Application")
$evt.Source = "MyEvent2"
$infoevent = [System.Diagnostics.EventLogEntryType]::Information
$evt.WriteEntry("Audt Log Cleared Event",$infoevent,1102)

$evt = new-object System.Diagnostics.EventLog("Application")
$evt.Source = "MyEvent2"
$infoevent = [System.Diagnostics.EventLogEntryType]::Error
$evt.WriteEntry("Event Log Cleared Event",$infoevent,104)