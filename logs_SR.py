import logging
from threading import Thread, Event
from tkinter.scrolledtext import ScrolledText
import tkinter as tk
import queue
import datetime
import time
import global_var

logger = logging.getLogger(__name__)


"""
In charge of handling queue of logs and displaying in interface
"""

class QueueHandler(logging.Handler):
    """Class to send logging records to a queue

    It can be used from different threads
    """

    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record):
        self.log_queue.put(record)


class Clock(Thread):
    """Class to display the time every seconds
    Every 5 seconds, the time is displayed using the logging.ERROR level
    to show that different colors are associated to the log levels
    """

    def __init__(self):
        super().__init__()
        self._stop_event = Event()

    def run(self):
        logger.debug('Clock started')
        previous = -1
        while not self._stop_event.is_set():
            now = datetime.datetime.now()
            if previous != now.second:
                previous = now.second
                if now.second % 5 == 0:
                    level = logging.ERROR
                else:
                    level = logging.INFO
                logger.log(level, now)
            time.sleep(0.2)

    def stop(self):
        self._stop_event.set()

class ConsoleUi:
    """Poll messages from a logging queue and display them in a scrolled text widget"""
    def __init__(self, frame):
        self.frame = frame
        # Create a ScrolledText wdiget
        self.scrolled_text = ScrolledText(frame, state='disabled', height=12)
        self.scrolled_text.grid(row=0, column=0)
        self.scrolled_text.configure(font='TkFixedFont')
        self.scrolled_text.tag_config('INFO', foreground='orange')
        self.scrolled_text.tag_config('CRITICAL', foreground='gray')
        self.scrolled_text.tag_config('WARNING', foreground='orange')
        self.scrolled_text.tag_config('ERROR', foreground='red')
        self.log_queue = queue.Queue()
        self.queue_handler = QueueHandler(self.log_queue)
        # formatter = logging.Formatter('%(asctime)s: %(message)s')
        # self.queue_handler.setFormatter(formatter)
        logger.addHandler(self.queue_handler)
        # Start polling messages from the queue
        self.frame.after(5, self.poll_log_queue)

        self.var1 = tk.IntVar()
        self.log_into_csv = tk.Checkbutton(frame, text='Log in CSV', variable=self.var1, onvalue=1, offvalue=0, command=self.log_to_output)
        self.log_into_csv.grid(row=5, column=0, columnspan=2)

    def display(self, record):
        msg = self.queue_handler.format(record)
        self.scrolled_text.configure(state='normal')
        self.scrolled_text.insert(tk.END, msg + '\n', record.levelname)
        self.scrolled_text.configure(state='disabled')
        # Autoscroll to the bottom
        self.scrolled_text.yview(tk.END)

    def poll_log_queue(self):
        # Check every 5ms if there is a new message in the queue to display
        while True:
            try:
                record = self.log_queue.get(block=False)
            except queue.Empty:
                break
            else:
                self.display(record)
        self.frame.after(5, self.poll_log_queue)

    def log_to_output(self):

        if self.var1.get() == 1:
            global_var.save_in_log = True
        else:
            global_var.save_in_log = False
        print(global_var.save_in_log)





