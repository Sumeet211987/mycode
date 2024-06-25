import requests
from datetime import datetime

# Function to fetch issues from Burp API
def fetch_issues():
    burp_api_url = "http://localhost:1337"  # Replace with your actual Burp API URL
    url = f"{burp_api_url}/v0.1/knowledge_base/issue_definitions"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to fetch issues: {response.status_code}")
        return []

# Function to process the fetched issues
def process_issues(issues):
    severity_confidence_counts = {
        'High': {'Certain': 0, 'Firm': 0, 'Tentative': 0},
        'Medium': {'Certain': 0, 'Firm': 0, 'Tentative': 0},
        'Low': {'Certain': 0, 'Firm': 0, 'Tentative': 0},
        'Information': {'Certain': 0, 'Firm': 0, 'Tentative': 0},
        'False Positive': {'Certain': 0, 'Firm': 0, 'Tentative': 0}
    }
    detailed_issues = []

    for issue in issues:
        severity = issue.get('severity', 'Information')
        confidence = issue.get('confidence', 'Tentative')
        severity_confidence_counts[severity][confidence] += 1
        detailed_issues.append({
            'id': len(detailed_issues) + 1,
            'name': issue.get('name', 'N/A'),
            'severity': severity,
            'confidence': confidence,
            'description': issue.get('description', 'No description available.'),
            'remediation': issue.get('remediation', 'No remediation available.'),
            'references': issue.get('description', 'No description available.'),
            'vulnerability': issue.get('vulnerability_classifications', 'No remediation available.')
        })

    return severity_confidence_counts, detailed_issues

# Function to create the HTML report
def create_html_report(filename, severity_confidence_counts, detailed_issues):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    toc_items = ""
    detailed_items = ""

    for issue in detailed_issues:
        toc_items += f'<p class="TOCH0"><a href="#{issue["id"]}">{issue["id"]}.&nbsp;{issue["name"]}</a></p>\n'
        detailed_items += f"""
        <span class="BODH0" id="{issue['id']}"><h3 id="{issue['id']}">{issue['id']}. {issue['name']}</h3></span>
        <h2>Summary</h2> 
        <table cellpadding="0" cellspacing="0" class="summary_table">
    <tr>
    <td rowspan="4" class="icon" valign="top" align="center"><div class='scan_issue_medium_certain_rpt'></div></td>
    <td>Severity:&nbsp;&nbsp;</td>
    <td><b>{issue['severity']}</b></td>
    </tr>
    <tr>
    <td>Confidence:&nbsp;&nbsp;</td>
    <td><b>{issue['confidence']}</b></td>
    </tr>
    </table>
        <div class="issue">
            <h3 id="{issue['id']}">{issue['id']}. {issue['name']}</h3>
            <p><strong>Issue detail:</strong></p>
            <p>{issue['description']}</p>
            <p><strong>Issue remediation:</strong></p>
            <p>{issue['remediation']}</p>
             <p><strong>References:</strong></p>
            <p>{issue['references']}</p>
            <p><strong>Vulnerability classifications:</strong></p>
            <p>{issue['vulnerability']}</p>
        </div>"""

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Vulnerability Report</title>
        <link rel="stylesheet" type="text/css" href="style.css">
    </head>
    <body>
    <div id="container">
<div class="title"><img src="burpsuit_logo_image.png" width="184" height="58"><h1>Burp Scanner Report</h1></div>
        <h1>Summary</h1>
        <span class="TEXT">The table below shows the numbers of issues identified in different categories. Issues are classified according to severity as High, Medium, Low, Information, or False Positive. This reflects the likely impact of each issue for a typical organization. Issues are also classified according to confidence as Certain, Firm, or Tentative. This reflects the inherent reliability of the technique that was used to identify the issue.</span><br><br>
        <table cellpadding="0" cellspacing="0" class="overview_table">
            <tr>
                <td width="70">&nbsp;</td>
                <td width="100">&nbsp;</td>
                <td colspan="4" height="40" align="center" class="label">Confidence</td>
            </tr>
            <tr>
                <td width="70">&nbsp;</td>
                <td width="90">&nbsp;</td>
                <td width="82" height="30" class="info">Certain</td>
                <td width="82" height="30" class="info">Firm</td>
                <td width="82" height="30" class="info">Tentative</td>
                <td width="82" height="30" class="info_end">Total</td>
            </tr>
            <tr>
                <td class="label" rowspan="5" valign="middle">Severity</td>"""

    for severity, counts in severity_confidence_counts.items():
        total = counts['Certain'] + counts['Firm'] + counts['Tentative']
        severity_class = severity.lower().replace(" ", "_")
        html_content += f"""
            
                <td class="info" height="30">{severity}</td>
                <td class="colour_holder"><span class="colour_block {severity_class}_certain">{counts['Certain']}</span></td>
                <td class="colour_holder"><span class="colour_block {severity_class}_firm">{counts['Firm']}</span></td>
                <td class="colour_holder"><span class="colour_block {severity_class}_tentative">{counts['Tentative']}</span></td>
                <td class="colour_holder_end"><span class="colour_block row_total">{total}</span></td>
            </tr>"""
    
    html_content += """
    </table>
    <span class="TEXT">The chart below shows the aggregated numbers of issues identified in each category. Solid colored bars represent issues with a confidence level of Certain, and the bars fade as the confidence level falls.</span><br><br>
    <table cellpadding="0" cellspacing="0" class="overview_table">
        <tr>
            <td width="70">&nbsp;</td>
            <td width="100">&nbsp;</td>
            <td colspan="9" height="40" align="center" class="label">Number of issues</td>
        </tr>
        <tr>
            <td width="70">&nbsp;</td>
            <td width="90">&nbsp;</td>
            <td width="83"><span class="grad_mark">0</span></td>
            <td width="83"><span class="grad_mark">2</span></td>
            <td width="83"><span class="grad_mark">4</span></td>
            <td width="83"><span class="grad_mark">6</span></td>
            <td width="83"><span class="grad_mark">8</span></td>
            <td width="83"><span class="grad_mark">10</span></td>
            <td width="83"><span class="grad_mark">12</span></td>
            <td width="83"><span class="grad_mark">14</span></td>
        </tr>
"""

# Define the severities to be included
    included_severities = ["High", "Medium", "Low"]
    
    image_data = {
    "High": ["data:image/png;base64,R0lGODlhAQABAPAAAPMqTAAAACH/C1hNUCBEYXRhWE1QPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4gPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgNi4wLWMwMDMgNzkuMTY0NTI3LCAyMDIwLzEwLzE1LTE3OjQ4OjMyICAgICAgICAiPiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPiA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtbG5zOnhtcE1NPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvbW0vIiB4bWxuczpzdFJlZj0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL3NUeXBlL1Jlc291cmNlUmVmIyIgeG1wOkNyZWF0b3JUb29sPSJBZG9iZSBQaG90b3Nob3AgMjIuMSAoTWFjaW50b3NoKSIgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDo2MUE2RjA3OTMzQzAxMUVCQkZDMEJFODVBQTNBQzcwMCIgeG1wTU06RG9jdW1lbnRJRD0ieG1wLmRpZDo2MUE2RjA3QTMzQzAxMUVCQkZDMEJFODVBQTNBQzcwMCI+IDx4bXBNTTpEZXJpdmVkRnJvbSBzdFJlZjppbnN0YW5jZUlEPSJ4bXAuaWlkOjYxQTZGMDc3MzNDMDExRUJCRkMwQkU4NUFBM0FDNzAwIiBzdFJlZjpkb2N1bWVudElEPSJ4bXAuZGlkOjYxQTZGMDc4MzNDMDExRUJCRkMwQkU4NUFBM0FDNzAwIi8+IDwvcmRmOkRlc2NyaXB0aW9uPiA8L3JkZjpSREY+IDwveDp4bXBtZXRhPiA8P3hwYWNrZXQgZW5kPSJyIj8+Af/+/fz7+vn49/b19PPy8fDv7u3s6+rp6Ofm5eTj4uHg397d3Nva2djX1tXU09LR0M/OzczLysnIx8bFxMPCwcC/vr28u7q5uLe2tbSzsrGwr66trKuqqainpqWko6KhoJ+enZybmpmYl5aVlJOSkZCPjo2Mi4qJiIeGhYSDgoGAf359fHt6eXh3dnV0c3JxcG9ubWxramloZ2ZlZGNiYWBfXl1cW1pZWFdWVVRTUlFQT05NTEtKSUhHRkVEQ0JBQD8+PTw7Ojk4NzY1NDMyMTAvLi0sKyopKCcmJSQjIiEgHx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQAALAAAAAABAAEAQAICRAEAOw==", "data:image/png;base64,R0lGODlhAQABAIAAAPmXpwAAACH/C1hNUCBEYXRhWE1QPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4gPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgNi4wLWMwMDMgNzkuMTY0NTI3LCAyMDIwLzEwLzE1LTE3OjQ4OjMyICAgICAgICAiPiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPiA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtbG5zOnhtcE1NPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvbW0vIiB4bWxuczpzdFJlZj0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL3NUeXBlL1Jlc291cmNlUmVmIyIgeG1wOkNyZWF0b3JUb29sPSJBZG9iZSBQaG90b3Nob3AgMjIuMSAoTWFjaW50b3NoKSIgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDo0OTM5RkM5NzMzQzExMUVCQkZDMEJFODVBQTNBQzcwMCIgeG1wTU06RG9jdW1lbnRJRD0ieG1wLmRpZDo0OTM5RkM5ODMzQzExMUVCQkZDMEJFODVBQTNBQzcwMCI+IDx4bXBNTTpEZXJpdmVkRnJvbSBzdFJlZjppbnN0YW5jZUlEPSJ4bXAuaWlkOjQ5MzlGQzk1MzNDMTExRUJCRkMwQkU4NUFBM0FDNzAwIiBzdFJlZjpkb2N1bWVudElEPSJ4bXAuZGlkOjQ5MzlGQzk2MzNDMTExRUJCRkMwQkU4NUFBM0FDNzAwIi8+IDwvcmRmOkRlc2NyaXB0aW9uPiA8L3JkZjpSREY+IDwveDp4bXBtZXRhPiA8P3hwYWNrZXQgZW5kPSJyIj8+Af/+/fz7+vn49/b19PPy8fDv7u3s6+rp6Ofm5eTj4uHg397d3Nva2djX1tXU09LR0M/OzczLysnIx8bFxMPCwcC/vr28u7q5uLe2tbSzsrGwr66trKuqqainpqWko6KhoJ+enZybmpmYl5aVlJOSkZCPjo2Mi4qJiIeGhYSDgoGAf359fHt6eXh3dnV0c3JxcG9ubWxramloZ2ZlZGNiYWBfXl1cW1pZWFdWVVRTUlFQT05NTEtKSUhHRkVEQ0JBQD8+PTw7Ojk4NzY1NDMyMTAvLi0sKyopKCcmJSQjIiEgHx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQAAIfkEAAAAAAAsAAAAAAEAAQAAAgJEAQA7", "data:image/png;base64,R0lGODlhAQABAIAAAP3a3wAAACH/C1hNUCBEYXRhWE1QPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4gPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgNi4wLWMwMDMgNzkuMTY0NTI3LCAyMDIwLzEwLzE1LTE3OjQ4OjMyICAgICAgICAiPiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPiA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtbG5zOnhtcE1NPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvbW0vIiB4bWxuczpzdFJlZj0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL3NUeXBlL1Jlc291cmNlUmVmIyIgeG1wOkNyZWF0b3JUb29sPSJBZG9iZSBQaG90b3Nob3AgMjIuMSAoTWFjaW50b3NoKSIgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDo0OTM5RkM5QjMzQzExMUVCQkZDMEJFODVBQTNBQzcwMCIgeG1wTU06RG9jdW1lbnRJRD0ieG1wLmRpZDo0OTM5RkM5QzMzQzExMUVCQkZDMEJFODVBQTNBQzcwMCI+IDx4bXBNTTpEZXJpdmVkRnJvbSBzdFJlZjppbnN0YW5jZUlEPSJ4bXAuaWlkOjQ5MzlGQzk5MzNDMTExRUJCRkMwQkU4NUFBM0FDNzAwIiBzdFJlZjpkb2N1bWVudElEPSJ4bXAuZGlkOjQ5MzlGQzlBMzNDMTExRUJCRkMwQkU4NUFBM0FDNzAwIi8+IDwvcmRmOkRlc2NyaXB0aW9uPiA8L3JkZjpSREY+IDwveDp4bXBtZXRhPiA8P3hwYWNrZXQgZW5kPSJyIj8+Af/+/fz7+vn49/b19PPy8fDv7u3s6+rp6Ofm5eTj4uHg397d3Nva2djX1tXU09LR0M/OzczLysnIx8bFxMPCwcC/vr28u7q5uLe2tbSzsrGwr66trKuqqainpqWko6KhoJ+enZybmpmYl5aVlJOSkZCPjo2Mi4qJiIeGhYSDgoGAf359fHt6eXh3dnV0c3JxcG9ubWxramloZ2ZlZGNiYWBfXl1cW1pZWFdWVVRTUlFQT05NTEtKSUhHRkVEQ0JBQD8+PTw7Ojk4NzY1NDMyMTAvLi0sKyopKCcmJSQjIiEgHx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQAAIfkEAAAAAAAsAAAAAAEAAQAAAgJEAQA7"],
    "Medium": ["data:image/png;base64,R0lGODlhAQABAPAAAP9mMwAAACH/C1hNUCBEYXRhWE1QPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4gPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgNi4wLWMwMDMgNzkuMTY0NTI3LCAyMDIwLzEwLzE1LTE3OjQ4OjMyICAgICAgICAiPiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPiA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtbG5zOnhtcE1NPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvbW0vIiB4bWxuczpzdFJlZj0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL3NUeXBlL1Jlc291cmNlUmVmIyIgeG1wOkNyZWF0b3JUb29sPSJBZG9iZSBQaG90b3Nob3AgMjIuMSAoTWFjaW50b3NoKSIgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDo5NkRGMzMxMDMzQzAxMUVCQkZDMEJFODVBQTNBQzcwMCIgeG1wTU06RG9jdW1lbnRJRD0ieG1wLmRpZDo5NkRGMzMxMTMzQzAxMUVCQkZDMEJFODVBQTNBQzcwMCI+IDx4bXBNTTpEZXJpdmVkRnJvbSBzdFJlZjppbnN0YW5jZUlEPSJ4bXAuaWlkOjk2REYzMzBFMzNDMDExRUJCRkMwQkU4NUFBM0FDNzAwIiBzdFJlZjpkb2N1bWVudElEPSJ4bXAuZGlkOjk2REYzMzBGMzNDMDExRUJCRkMwQkU4NUFBM0FDNzAwIi8+IDwvcmRmOkRlc2NyaXB0aW9uPiA8L3JkZjpSREY+IDwveDp4bXBtZXRhPiA8P3hwYWNrZXQgZW5kPSJyIj8+Af/+/fz7+vn49/b19PPy8fDv7u3s6+rp6Ofm5eTj4uHg397d3Nva2djX1tXU09LR0M/OzczLysnIx8bFxMPCwcC/vr28u7q5uLe2tbSzsrGwr66trKuqqainpqWko6KhoJ+enZybmpmYl5aVlJOSkZCPjo2Mi4qJiIeGhYSDgoGAf359fHt6eXh3dnV0c3JxcG9ubWxramloZ2ZlZGNiYWBfXl1cW1pZWFdWVVRTUlFQT05NTEtKSUhHRkVEQ0JBQD8+PTw7Ojk4NzY1NDMyMTAvLi0sKyopKCcmJSQjIiEgHx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQAALAAAAAABAAEAQAICRAEAOw==", "data:image/png;base64,R0lGODlhAQABAPAAAP+ymQAAACH/C1hNUCBEYXRhWE1QPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4gPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgNi4wLWMwMDMgNzkuMTY0NTI3LCAyMDIwLzEwLzE1LTE3OjQ4OjMyICAgICAgICAiPiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPiA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtbG5zOnhtcE1NPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvbW0vIiB4bWxuczpzdFJlZj0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL3NUeXBlL1Jlc291cmNlUmVmIyIgeG1wOkNyZWF0b3JUb29sPSJBZG9iZSBQaG90b3Nob3AgMjIuMSAoTWFjaW50b3NoKSIgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDo5NkRGMzMwQzMzQzAxMUVCQkZDMEJFODVBQTNBQzcwMCIgeG1wTU06RG9jdW1lbnRJRD0ieG1wLmRpZDo5NkRGMzMwRDMzQzAxMUVCQkZDMEJFODVBQTNBQzcwMCI+IDx4bXBNTTpEZXJpdmVkRnJvbSBzdFJlZjppbnN0YW5jZUlEPSJ4bXAuaWlkOjYxQTZGMDdGMzNDMDExRUJCRkMwQkU4NUFBM0FDNzAwIiBzdFJlZjpkb2N1bWVudElEPSJ4bXAuZGlkOjYxQTZGMDgwMzNDMDExRUJCRkMwQkU4NUFBM0FDNzAwIi8+IDwvcmRmOkRlc2NyaXB0aW9uPiA8L3JkZjpSREY+IDwveDp4bXBtZXRhPiA8P3hwYWNrZXQgZW5kPSJyIj8+Af/+/fz7+vn49/b19PPy8fDv7u3s6+rp6Ofm5eTj4uHg397d3Nva2djX1tXU09LR0M/OzczLysnIx8bFxMPCwcC/vr28u7q5uLe2tbSzsrGwr66trKuqqainpqWko6KhoJ+enZybmpmYl5aVlJOSkZCPjo2Mi4qJiIeGhYSDgoGAf359fHt6eXh3dnV0c3JxcG9ubWxramloZ2ZlZGNiYWBfXl1cW1pZWFdWVVRTUlFQT05NTEtKSUhHRkVEQ0JBQD8+PTw7Ojk4NzY1NDMyMTAvLi0sKyopKCcmJSQjIiEgHx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQAALAAAAAABAAEAAAICRAEAOw==", "data:image/png;base64,R0lGODlhAQABAPAAAP/ZzAAAACH/C1hNUCBEYXRhWE1QPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4gPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgNi4wLWMwMDMgNzkuMTY0NTI3LCAyMDIwLzEwLzE1LTE3OjQ4OjMyICAgICAgICAiPiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPiA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtbG5zOnhtcE1NPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvbW0vIiB4bWxuczpzdFJlZj0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL3NUeXBlL1Jlc291cmNlUmVmIyIgeG1wOkNyZWF0b3JUb29sPSJBZG9iZSBQaG90b3Nob3AgMjIuMSAoTWFjaW50b3NoKSIgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDo2MUE2RjA3RDMzQzAxMUVCQkZDMEJFODVBQTNBQzcwMCIgeG1wTU06RG9jdW1lbnRJRD0ieG1wLmRpZDo2MUE2RjA3RTMzQzAxMUVCQkZDMEJFODVBQTNBQzcwMCI+IDx4bXBNTTpEZXJpdmVkRnJvbSBzdFJlZjppbnN0YW5jZUlEPSJ4bXAuaWlkOjYxQTZGMDdCMzNDMDExRUJCRkMwQkU4NUFBM0FDNzAwIiBzdFJlZjpkb2N1bWVudElEPSJ4bXAuZGlkOjYxQTZGMDdDMzNDMDExRUJCRkMwQkU4NUFBM0FDNzAwIi8+IDwvcmRmOkRlc2NyaXB0aW9uPiA8L3JkZjpSREY+IDwveDp4bXBtZXRhPiA8P3hwYWNrZXQgZW5kPSJyIj8+Af/+/fz7+vn49/b19PPy8fDv7u3s6+rp6Ofm5eTj4uHg397d3Nva2djX1tXU09LR0M/OzczLysnIx8bFxMPCwcC/vr28u7q5uLe2tbSzsrGwr66trKuqqainpqWko6KhoJ+enZybmpmYl5aVlJOSkZCPjo2Mi4qJiIeGhYSDgoGAf359fHt6eXh3dnV0c3JxcG9ubWxramloZ2ZlZGNiYWBfXl1cW1pZWFdWVVRTUlFQT05NTEtKSUhHRkVEQ0JBQD8+PTw7Ojk4NzY1NDMyMTAvLi0sKyopKCcmJSQjIiEgHx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQAALAAAAAABAAEAQAICRAEAOw=="],
    "Low": ["data:image/png;base64,R0lGODlhAQABAPAAAACU/wAAACH/C1hNUCBEYXRhWE1QPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4gPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgNi4wLWMwMDMgNzkuMTY0NTI3LCAyMDIwLzEwLzE1LTE3OjQ4OjMyICAgICAgICAiPiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPiA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtbG5zOnhtcE1NPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvbW0vIiB4bWxuczpzdFJlZj0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL3NUeXBlL1Jlc291cmNlUmVmIyIgeG1wOkNyZWF0b3JUb29sPSJBZG9iZSBQaG90b3Nob3AgMjIuMSAoTWFjaW50b3NoKSIgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDpERDdCQTNGNTMzQzAxMUVCQkZDMEJFODVBQTNBQzcwMCIgeG1wTU06RG9jdW1lbnRJRD0ieG1wLmRpZDpERDdCQTNGNjMzQzAxMUVCQkZDMEJFODVBQTNBQzcwMCI+IDx4bXBNTTpEZXJpdmVkRnJvbSBzdFJlZjppbnN0YW5jZUlEPSJ4bXAuaWlkOjk2REYzMzE2MzNDMDExRUJCRkMwQkU4NUFBM0FDNzAwIiBzdFJlZjpkb2N1bWVudElEPSJ4bXAuZGlkOkREN0JBM0Y0MzNDMDExRUJCRkMwQkU4NUFBM0FDNzAwIi8+IDwvcmRmOkRlc2NyaXB0aW9uPiA8L3JkZjpSREY+IDwveDp4bXBtZXRhPiA8P3hwYWNrZXQgZW5kPSJyIj8+Af/+/fz7+vn49/b19PPy8fDv7u3s6+rp6Ofm5eTj4uHg397d3Nva2djX1tXU09LR0M/OzczLysnIx8bFxMPCwcC/vr28u7q5uLe2tbSzsrGwr66trKuqqainpqWko6KhoJ+enZybmpmYl5aVlJOSkZCPjo2Mi4qJiIeGhYSDgoGAf359fHt6eXh3dnV0c3JxcG9ubWxramloZ2ZlZGNiYWBfXl1cW1pZWFdWVVRTUlFQT05NTEtKSUhHRkVEQ0JBQD8+PTw7Ojk4NzY1NDMyMTAvLi0sKyopKCcmJSQjIiEgHx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQAALAAAAAABAAEAQAICRAEAOw==", "data:image/png;base64,R0lGODlhAQABAPAAAH/J/wAAACH/C1hNUCBEYXRhWE1QPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4gPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgNi4wLWMwMDMgNzkuMTY0NTI3LCAyMDIwLzEwLzE1LTE3OjQ4OjMyICAgICAgICAiPiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPiA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtbG5zOnhtcE1NPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvbW0vIiB4bWxuczpzdFJlZj0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL3NUeXBlL1Jlc291cmNlUmVmIyIgeG1wOkNyZWF0b3JUb29sPSJBZG9iZSBQaG90b3Nob3AgMjIuMSAoTWFjaW50b3NoKSIgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDo5NkRGMzMxNDMzQzAxMUVCQkZDMEJFODVBQTNBQzcwMCIgeG1wTU06RG9jdW1lbnRJRD0ieG1wLmRpZDo5NkRGMzMxNTMzQzAxMUVCQkZDMEJFODVBQTNBQzcwMCI+IDx4bXBNTTpEZXJpdmVkRnJvbSBzdFJlZjppbnN0YW5jZUlEPSJ4bXAuaWlkOjk2REYzMzEyMzNDMDExRUJCRkMwQkU4NUFBM0FDNzAwIiBzdFJlZjpkb2N1bWVudElEPSJ4bXAuZGlkOjk2REYzMzEzMzNDMDExRUJCRkMwQkU4NUFBM0FDNzAwIi8+IDwvcmRmOkRlc2NyaXB0aW9uPiA8L3JkZjpSREY+IDwveDp4bXBtZXRhPiA8P3hwYWNrZXQgZW5kPSJyIj8+Af/+/fz7+vn49/b19PPy8fDv7u3s6+rp6Ofm5eTj4uHg397d3Nva2djX1tXU09LR0M/OzczLysnIx8bFxMPCwcC/vr28u7q5uLe2tbSzsrGwr66trKuqqainpqWko6KhoJ+enZybmpmYl5aVlJOSkZCPjo2Mi4qJiIeGhYSDgoGAf359fHt6eXh3dnV0c3JxcG9ubWxramloZ2ZlZGNiYWBfXl1cW1pZWFdWVVRTUlFQT05NTEtKSUhHRkVEQ0JBQD8+PTw7Ojk4NzY1NDMyMTAvLi0sKyopKCcmJSQjIiEgHx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQAALAAAAAABAAEAQAICRAEAOw==", "data:image/png;base64,R0lGODlhAQABAPABAL/k/wAAACH/C05FVFNDQVBFMi4wAwEAAAAh+QQFAAABACwAAAAAAQABAAACAkQBADs="]
}

    for severity in included_severities:
        counts = severity_confidence_counts.get(severity, {'Certain': 0, 'Firm': 0, 'Tentative': 0})
        certain_width = counts['Certain'] * 10  # Adjust the multiplier for better scaling
        firm_width = counts['Firm'] * 10  # Adjust the multiplier for better scaling
        tentative_width = counts['Tentative'] * 10  # Adjust the multiplier for better scaling
        bar_class = severity.lower().replace(" ", "-")
        images = image_data[severity]  # Get the list of images for the current severity
        html_content += f"""
        <tr>
            <td class="label">{severity}</td>
            <td colspan="8" height="30">
                 <table cellpadding="0" cellspacing="0">
                <tr>
                    <td><img class="bar {bar_class}" src="{images[0]}" width="{certain_width}" height="16" style="background-color: #007bff;"></td>
                    <td><img class="bar {bar_class}" src="{images[1]}" width="{firm_width}" height="16" style="background-color: #7bbfff;"></td>
                    <td><img class="bar {bar_class}" src="{images[2]}" width="{tentative_width}" height="16" style="background-color: #b3d9ff;"></td>
                </tr>
                <tr>
                    <td><img class="bar {bar_class}" src="{images[0]}" width="{certain_width}" height="16" style="background-color: #007bff;"></td>
                    <td><img class="bar {bar_class}" src="{images[1]}" width="{firm_width}" height="16" style="background-color: #7bbfff;"></td>
                    <td><img class="bar {bar_class}" src="{images[2]}" width="{tentative_width}" height="16" style="background-color: #b3d9ff;"></td>
                </tr>
                <tr>
                    <td><img class="bar {bar_class}" src="{images[0]}" width="{certain_width}" height="16" style="background-color: #007bff;"></td>
                    <td><img class="bar {bar_class}" src="{images[1]}" width="{firm_width}" height="16" style="background-color: #7bbfff;"></td>
                    <td><img class="bar {bar_class}" src="{images[2]}" width="{tentative_width}" height="16" style="background-color: #b3d9ff;"></td>
                </tr>
            </table>
            </td>
        </tr>
        """
        
    html_content += """
        </table>
        <div class="rule"></div>
        <h1>Contents</h1>""" + toc_items + """
        <br>
        """ + detailed_items + """
    </body>
    </html>
    """

    with open(filename, 'w') as file:
        file.write(html_content)

# Main function to fetch issues and create the report
def main():
    issues = fetch_issues()
    severity_confidence_counts, detailed_issues = process_issues(issues)
    create_html_report("vulnerability_report.html", severity_confidence_counts, detailed_issues)

if __name__ == "__main__":
    main()
