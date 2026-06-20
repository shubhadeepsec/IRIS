from typing import Dict, Any

def html_export(data: Dict[str, Any], filepath: str) -> None:
    """Export data to a styled HTML report."""
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IRIS Intelligence Report</title>
    <style>
        body {{
            background-color: #0a0e27;
            color: #ffffff;
            font-family: 'Courier New', Courier, monospace;
            padding: 20px;
        }}
        h1, h2, h3 {{
            color: #00d9ff;
        }}
        .container {{
            max-width: 800px;
            margin: 0 auto;
            border: 1px solid #00d9ff;
            padding: 20px;
            box-shadow: 0 0 10px #00d9ff;
        }}
        .key {{
            color: #00ff88;
            font-weight: bold;
        }}
        .value {{
            color: #ffffff;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        th, td {{
            border: 1px solid #00d9ff;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background-color: #00d9ff;
            color: #0a0e27;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>⚡ IRIS Intelligence Report</h1>
        <p><strong>Target:</strong> {data.get("Target") or data.get("Domain") or data.get("Email") or "Unknown"}</p>
        <hr style="border-color: #00d9ff;">
        
        <h2>Summary</h2>
        <table>
            <tr><th>Attribute</th><th>Value</th></tr>
"""
    for key, value in data.items():
        if key == "_raw": continue
        html_content += f"            <tr><td class='key'>{key}</td><td class='value'>{value}</td></tr>\n"

    html_content += """        </table>
    </div>
</body>
</html>"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_content)
