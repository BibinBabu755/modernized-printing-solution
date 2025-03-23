import win32evtlog
import win32evtlogutil
import win32con
import json
import time

# Event IDs for Print Jobs
PRINT_JOB_STARTED = 307
PRINT_JOB_COMPLETED = 308

def fetch_print_events():
    """
    Fetches Windows Event Logs related to print jobs.
    Looks for print job start (ID 307) and print job completion (ID 308).
    """
    server = "localhost"  # Local machine
    log_type = "Microsoft-Windows-PrintService/Operational"

    # Open the event log
    hand = win32evtlog.OpenEventLog(server, log_type)

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    total = win32evtlog.GetNumberOfEventLogRecords(hand)

    print(f"Total Print Events: {total}")

    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if not events:
            break

        for event in events:
            if event.EventID in [PRINT_JOB_STARTED, PRINT_JOB_COMPLETED]:
                event_data = parse_event(event)
                print(json.dumps(event_data, indent=2))  # Print formatted JSON

    win32evtlog.CloseEventLog(hand)

def parse_event(event):
    """
    Parses an event log entry to extract relevant print job information.
    """
    event_data = {
        "EventID": event.EventID,
        "TimeGenerated": event.TimeGenerated.Format(),
        "SourceName": event.SourceName,
        "ComputerName": event.ComputerName,
        "Message": win32evtlogutil.SafeFormatMessage(event, "Microsoft-Windows-PrintService/Operational"),
    }

    if event.EventID == PRINT_JOB_STARTED:
        event_data["Status"] = "Print Job Started"
    elif event.EventID == PRINT_JOB_COMPLETED:
        event_data["Status"] = "Print Job Completed"

    return event_data

if __name__ == "__main__":
    fetch_print_events()
