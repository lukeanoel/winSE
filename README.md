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
