import csv
from typing import Dict, Any

def csv_export(data: Dict[str, Any], filepath: str) -> None:
    """Export data to a CSV file."""
    # Filter out raw data for CSV
    clean_data = {k: v for k, v in data.items() if k != "_raw"}
    
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Attribute", "Value"])
        for key, value in clean_data.items():
            writer.writerow([key, str(value)])
