#!/usr/bin/env python
from winse.common import event_collector, event_analyzer
import subprocess, sys
import locale

log_types = ["System, Application"]
servers = ["localhost"]
time_window_hours = 500
ps_script_path = "C:\\Users\\lukea\\PycharmProjects\\winSE\\winse\\tests\\populate_logs.ps1"
testing = True


def calc_total_severity_score(incidents_detected):
    total_severity_score = 0

    for incident in incidents_detected:
        total_severity_score += incidents_detected[incident].get_severity_score()

    return total_severity_score


def run():
    # Create logs
    if testing:
        p = subprocess.Popen(["powershell.exe",
                              ps_script_path],
                             stdout=sys.stdout)
        p.communicate()
    # Collect
    event_collection = event_collector.EventCollection(time_window_hours)
    # Analyze
    incidents_detected = event_analyzer.analyze_event_collection(event_collection)
    total_severity_score = calc_total_severity_score(incidents_detected)
    if total_severity_score >= 30:
        breach_likelihood = "Extremely Likely (95+%)"
    if total_severity_score < 30 and total_severity_score >= 22:
        breach_likelihood = "Highly Likely (70%)"
    if total_severity_score < 22 and total_severity_score >= 15:
        breach_likelihood = "Moderately Likely (50%)"
    if total_severity_score < 15 and total_severity_score >= 10:
        breach_likelihood = "Unlikely (30%)"
    if total_severity_score < 10 and total_severity_score >= 5:
        breach_likelihood = "Not Likely (5%)"
    if total_severity_score < 5:
        breach_likelihood = "No Identifiable Risk"

    # Output
    with open("output.html", "w") as out:
        locale.setlocale(locale.LC_ALL, 'english-us')

        out.write("""
            <style>
                body {{ Arial Black, "Helvetica Neue", Helvetica, sans-serif; }}
                table, th, td {{
                    border: 1px solid black;
                }}
                table {{ border-spacing: 8px; }}
                th, td {{
                    border: none;
                }}
                th {{
                  background-color: green;
                  color: white;
                }}
                td {{ vertical-align: text-top; }}
                .event-time {{ font-size: 9px; }}
                .event-type {{ font-size: 9px; }}
                .event-ID {{ front-size; 9px; }}
                .error-count {{ text-align: right; }}
    
            </style>
            WinSE has analyzed the Windows Event logs on {} over the last {} hours. Below is the analysis of events along with Likelihood of breach.<br/>
        """.format(servers, time_window_hours))

        out.write("""
            <table>
            <tr>
                <th>Server</th>
                <th>Likelihood of Breach</th>
                <th>Total Severity Score</th>
            </tr>
        """)

        out.write("""
            <tr>
                <td>{}</td>
                <td>{}</td>
                <td class="error-count">{}</td>
            </tr>
        """.format('localhost', breach_likelihood, total_severity_score))

        out.write("""
            <table>
            <tr>
                <th>Incident</th>
                <th>First Occurrence</th>
                <th>Last Occurrence</th>
                <th>Details</th>
                <th>Detected Supporting Events</th>
                <th>Severity</th>
                <th>Incident Count</th>
            </tr>
        """)

        # out.write('<tr><th colspan=3>{}</th></tr>'.format('localhost'))
        for incident in incidents_detected:
            inc = incidents_detected[incident]
            out.write("""
            					<tr>
            						<td>{}</td>
            						<td>{}</td>
            						<td>{}</td>
            						<td>{}</td>
            						<td>{}</td>
            						<td>{}</td>
            						<td>{}</td>
            					</tr>\n""".format(inc,
                                                  inc.first_occurrence,
                                                  inc.last_occurrence,
                                                  inc.incident.details,
                                                  inc.get_supporting_events(),
                                                  inc.get_severity_score(),
                                                  inc.count
                                                  ))

        out.write("""
            		</table>
            	""")

    print("Wrote output to {}".format("output.html"))
