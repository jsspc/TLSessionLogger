### TLSessionLogger
Tool developed to observe TLS session resumptions

### Required libraries

- Scapy: https://scapy.net/
- Tkinter
- signal
- subprocess
- threading
- dumpcap (is downloaded along with Wireshark): https://www.wireshark.org/docs/man-pages/dumpcap.html

### How to launch the interface

- Go to the directories with all python files and call 'python interface.py'
- Click on an interface in the list to select it.
- Optionnal: Define pcap and csv name; add description to the csv file by using the "Add txt to log" field; log session reusmption events in csv by tcking the "Log to CSV" box.
- Start the capture
- Open the browser, start browsing; logs of session resumption events will appear in the logging frame.
- Stop the capture before closing the program.

### Default name and folders

- The default name of the capture file is capture.pcap
- The default name of the output file (CSV file containg the logs) is output.csv
- The default folder is the current working directory (same as interface.py)

