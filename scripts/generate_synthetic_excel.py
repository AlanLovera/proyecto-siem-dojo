"""Generate an explicitly synthetic XLSX without reading any source dataset."""
import argparse
from datetime import datetime, timedelta
from io import BytesIO
from pathlib import Path

from openpyxl import Workbook
from dojo.ingestion import REQUIRED_COLUMNS


def synthetic_rows():
    """Invented events, documentation IPs and invented laboratory accounts."""
    rows = []
    def add(seconds, event_id, **changes):
        record = dict(Log_ID=f"SYNTH-{len(rows)+1:04d}",
                      Timestamp=(datetime(2030, 1, 1) + timedelta(seconds=seconds)).strftime("%Y-%m-%d %H:%M:%S"),
                      Hostname="SYNTH-HOST-01", Event_ID=event_id, User="SYNTHETIC_LAB\\user-01",
                      Source_IP="192.0.2.10", Destination="192.0.2.20", Log_Source="Security",
                      Event_Description="SYNTHETIC: invented educational test event",
                      Process_CommandLine=None, Result="Success", Severity="Informational")
        record.update(changes)
        rows.append([record[k] for k in REQUIRED_COLUMNS])
    for i in range(6):
        add(i*10, 4625, User=f"SYNTHETIC_LAB\\user-{i%3+1:02d}", Result="Failure")
    add(70, 4624)
    add(80, 4688, Process_CommandLine="powershell.exe -enc SYNTHETIC_NOT_BASE64")
    add(90, 4688, Process_CommandLine="cmd.exe /c whoami")
    add(100, 4698, Process_CommandLine="SYNTHETIC scheduled task description")
    add(110, "HTTP_ACCESS", User="-", Log_Source="IIS", Process_CommandLine="/synthetic?cmd=whoami", Result="200")
    add(120, 4688, User="IIS APPPOOL\\SyntheticPool", Process_CommandLine="cmd.exe /c whoami")
    return rows


def workbook_bytes():
    book = Workbook()
    book.properties.creator = "DOJO SIEM Analyzer"
    book.properties.lastModifiedBy = "DOJO SIEM Analyzer"
    sheet = book.active
    sheet.title = "Synthetic Logs"
    sheet.append(list(REQUIRED_COLUMNS))
    for row in synthetic_rows():
        sheet.append(row)
    stream = BytesIO()
    book.save(stream)
    book.close()
    return stream.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="New local .xlsx path; existing files are never overwritten")
    args = parser.parse_args()
    if args.output.suffix.lower() != ".xlsx":
        parser.error("Output must have the .xlsx extension")
    with args.output.open("xb") as output:
        output.write(workbook_bytes())
    print("Created 12 invented synthetic events; sheet: Synthetic Logs")


if __name__ == "__main__":
    main()
