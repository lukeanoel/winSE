# winSE

Even within a single computer system, there are a big number of security related events in a period of time. Popular pentesting tools such as port scanning and vulnerability scanning focus on low-level events, such as ports that are open and software versions. Due to the volume of these low level events, pentesting tools do not provide human friendly security assessment. They often do not answer the following questions: "How likely has this computer been compromised?", "If already compromised, for how long?".

winSE's Goal:
To fill the above gaps. In this project I investigat heuristic rules to sijngle out security critical events from a large number of security events on a Windows system to make high-level orrelations among them and present human-freidnly security conclusions.

This tool collects all Application, System, and Security events on a windows system during a window of time (default: 24 hours). After collection, these low-level events are categorgized into higher level security incidents that can draw conclusions as to what actually occured on the system. These security incidents are then assigned scores based on severity and are associated with other related supporting events that can help paint an even more clear picture. This is all displayed via a generated HTML page in a human-friendly digestable format.

Total Score (Based of 24 hours)	Breach Likelihood
>= 30	Extremely Likely (95+%)
22	Highly Likely (70%)
15	Moderately Likely (50%)
10	Unlikely (30%)
5	Not Likely (5%)
<5	No Identifiable Risk


Event Name	Assoc. Event IDs	Log Level	Log Type
Application Crash	1000	Error	Application
Application Crash - Blue Screen of Death	1002	Error	System
Application Hang	1001	Error	Application
Windows Service Fail or Crash	7022, 7023	Error	System
Windows Update Failed or Crashed	20, 24, 25, 31, 34, 35	Error	System
New Firewall Rule Added	2004	Information	Security
New Firewall Rule Changed	2005	Information	Security
New Firewall Rule Changed	2006, 2033		Security
Failed to Load Group Firewall Policy	2006, 2033	Error	Security
Event Log Cleared	104	Information	System
Audit Log Cleared	1102	Information	Security
New Windows Service	7045	Information	Security
New MSI File Installed
	1022, 1033	Information	Application
New Application Installed
	903, 904	Information	Security
An Application Has Been Updated
	905, 906	Information	Security
An Application Has Been Removed
	907, 908	Information	Security
An Account Has Been Locked Out
	907, 908	Information	Security
A User Has Been Added to Privileged Group
	4728, 4732, 4756	Information	Security
A Security Enabled Group Modification Has Been Made
	4735	Information	Security
A User Has Successfully Logged In
	4624	Information	Security
A Failed User Login Attempt Has Been Made
	4625	Information	Security
A Login Has Been Made With Explicit Credentials
	4648	Information	Security
Group Policy Application Failed due to Connectivity
	1129	Error	System
New External Device Detected
	43, 400, 410		System
Windows Defender Scan Failed	1005	Information	System
Windows Defender Detected Malware
	1006	Warning	Security
Action on Malware Failed
	1008	Error	Security
Failed to Update Signatures
	2001	Error	Security
Reverting to Last Known Good Set of Signatures
	2004	Error	Security
Real Time Protection Failed
	3002	Error	Security
Pass the Hash Attack Detected
	4624	Error	Security
