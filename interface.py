from tkinter import *
from tkinter import filedialog
import tkinter.ttk as ttk
import signal
from os import getcwd, path
import global_var
from datetime import datetime

from capturing_process import Capture
from utils import list_interfaces
from storing_process import add_to_csv


fenetre = Tk()

# Logging into scrolledtext widget - example
# https://github.com/beenje/tkinter-logging-text-widget/blob/master/main.py


from logs_SR import ConsoleUi

class Interface(Frame):

    # ===========================================================================
    # =================== Main Frame ============================================
    # ===========================================================================

    def __init__(self, fenetre, **kwargs):

        """
        Defining main interface frame
        :param fenetre:
        :param kwargs:
        """

        # Creating main frame
        Frame.__init__(self, fenetre, **kwargs)
        fenetre.title("TLS Session Resumptions - Logs")
        fenetre.config(background='#596061', padx=20, pady=20)
        self.frame = fenetre
        self.grid()

        # Variables of interface
        self.ongoing_capture = False

        # Get the network interfaces
        self.capture_interfaces = list_interfaces()
        global_var.init()

        # Define chosen interface as the one used by dumpcap by default (first of list)
        self.interface_chosen = self.capture_interfaces[0][0]

        # Create the listbox with interfaces available
        self.listbox_capture_interfaces = Listbox(fenetre, selectmode='single')
        self.listbox_capture_interfaces.bind("<<ListboxSelect>>", self.def_new_interface)

        # List of interfaces
        self.listbox_capture_interfaces.grid(row=0, column=0, columnspan=2, rowspan = 5)

        for elmt in self.capture_interfaces:
            self.listbox_capture_interfaces.insert(END, elmt[1])

        # Label to display which interface has been chosen
        self.selected_interface = self.capture_interfaces[0][1]
        self.selected_interface_label = Label(fenetre, text=self.selected_interface)
        self.selected_interface_label.grid(row=6, column=0, columnspan=2)

        # Create capture instance for interface
        self.capture_process = Capture(self.interface_chosen)

        # Start and stop buttons
        self.button_start_capture = Button(fenetre, text='Start capture', command=self.start_capture_signal)
        self.button_start_capture.config(background='#3ca3bc', foreground='#ffffff', padx=5, pady=5)
        self.button_start_capture.grid(row=7, column=0)

        self.button_stop_capture = Button(fenetre, text='Stop capture', command=self.stop_capture_signal)
        self.button_stop_capture.config(background='#3ca3bc', foreground='#ffffff', padx=5, pady=5)
        self.button_stop_capture.grid(row=7, column=1)

        # Path of saved files
        self.filepath_label = Label(fenetre, text="PCAP filepath", width=10)
        self.filepath_label.grid(row=0, column=2, columnspan=2)

        self.button_browse_filepath = Button(fenetre, text='Browse', command=self.def_new_filepath)  # TODO: change
        self.button_browse_filepath.config(background='#3ca3bc', foreground='#ffffff')
        self.button_browse_filepath.grid(row=1, column=2, columnspan=2)

        # Name of pcap file
        self.filename_label = Label(fenetre, text="PCAP filename", width=15)
        self.filename_label.grid(row=2, column=2, columnspan=2)

        self.text_file_name = StringVar()
        self.filename_entry = Entry(fenetre, textvariable=self.text_file_name, width=20)
        self.filename_entry.grid(row=3, column=2)

        self.button_def_filename = Button(fenetre, text='OK', command=self.def_new_filename)  # TODO: change
        self.button_def_filename.config(background='#3ca3bc', foreground='#ffffff', padx=3, pady=3)
        self.button_def_filename.grid(row=3, column=3)

        # Name of csv (log) file
        self.out_filename_label = Label(fenetre, text="Output filename", width=20)
        self.out_filename_label.grid(row=4, column=2)

        self.out_text_file_name = StringVar()
        self.out_filename_entry = Entry(fenetre, textvariable=self.out_text_file_name, width=20)
        self.out_filename_entry.grid(row=5, column=2)

        self.button_def_out_filename = Button(fenetre, text='OK', command=self.def_output_filename)  # TODO: change
        self.button_def_out_filename.config(background='#3ca3bc', foreground='#ffffff', padx=3, pady=3)
        self.button_def_out_filename.grid(row=5, column=3)

        # Manually add line to csv (log) file
        self.out_filename_label = Label(fenetre, text="Add txt to log", width=15)
        self.out_filename_label.grid(row=6, column=2)

        self.out_log_line = StringVar()
        self.out_log_line_entry = Entry(fenetre, textvariable=self.out_log_line, width=20)
        self.out_log_line_entry.grid(row=7, column=2)

        self.button_def_out_filename = Button(fenetre, text='OK', command=self.log_setup)  # TODO: change
        self.button_def_out_filename.config(background='#3ca3bc', foreground='#ffffff', padx=3, pady=3)
        self.button_def_out_filename.grid(row=7, column=3)

        # Logs displayed to user
        console_frame = ttk.Labelframe(fenetre, text="Session Resumption Logs")
        console_frame.columnconfigure(0, weight=1)
        console_frame.rowconfigure(0, weight=1)
        console_frame.grid(row=0, column=5, rowspan=7)

        self.console = ConsoleUi(console_frame)

        # Clear logs button
        self.button_clear_logs = Button(console_frame, text='Clear logs', command=self.clear_logs)
        self.button_clear_logs.config(background='#3ca3bc', foreground='#ffffff', padx=3, pady=3)
        self.button_clear_logs.grid(row=7, column=3)

        # End of window
        fenetre.protocol('WM_DELETE_WINDOW', self.quit)
        fenetre.bind('<Control-q>', self.quit)
        signal.signal(signal.SIGINT, self.quit)

    def quit(self, *args):
        """
        On closing interface
        :param args:
        :return:
        """
        # self.clock.stop()
        self.frame.destroy()

    def start_capture_signal(self):
        """
        Click on start button: sends start signal to Capture process
        :return:
        """
        if self.ongoing_capture:
            print("Stop current capture first")
        else:
            self.ongoing_capture = True
            self.capture_process.start_capture()

    def stop_capture_signal(self):
        """
        Click on Stop button: sends stop signal to Capture process
        :return:
        """
        if not self.ongoing_capture:
            print("No capture ongoing")
        else:
            self.capture_process.stop_capture()
            self.ongoing_capture = False

    def def_new_interface(self, event):
        """
        On click in Listbox, will trigger event to change capture interface
        :param event: click on listbox
        :return:
        """
        if not self.ongoing_capture:
            index = event.widget.curselection()
            self.interface_chosen = self.capture_interfaces[index[0]][1]

            self.selected_interface_label.destroy()
            self.selected_interface_label = Label(fenetre, text=self.interface_chosen)
            self.selected_interface_label.grid(row=6, column=0, columnspan=2)

            self.capture_process.change_interface(self.capture_interfaces[index[0]][0])
        else:
            print("Stop capture and select valid interface")

    def def_new_filepath(self):
        """
        Define new folder for pcap file
        :return:
        """
        if not self.ongoing_capture:
            path = filedialog.askdirectory(parent=self.frame, initialdir=getcwd(), title='Select the folder')
            self.capture_process.change_filepath(path)
            print(self.capture_process.full_path)
        else:
            print("Stop capture first")

    def def_new_filename(self):
        """
        Define new name for pcap file
        :return:
        """
        if not self.ongoing_capture:
            name = self.text_file_name.get()
            self.capture_process.change_filename(name)
            print(self.capture_process.full_path)
        else:
            print("Stop capture first")

    def clear_logs(self):
        """
        Clear logs in log window
        :return:
        """
        self.console.scrolled_text.configure(state='normal')
        self.console.scrolled_text.delete('0.0', END)
        self.console.scrolled_text.update()
        self.console.scrolled_text.configure(state='disabled')

    def clear_logs_file(self):
        """
        if existing file for csv logs: empties it first
        :return:
        """
        if not self.ongoing_capture:
            filepath = global_var.filepath
            filename = global_var.output_file_name
            full_path = path.normpath(filepath + '\\output\\' + filename +'.csv')
            f = open(full_path, 'w+')
            f.write('')
            f.close()
        else:
            print("Stop capture first")

    def log_setup(self):
        """
        Defines CSV log file to default (./output/name_csv.csv)
        :return:
        """
        filepath = global_var.filepath
        filename = global_var.output_file_name
        full_path = path.normpath(filepath + '\\' + filename + '.csv')
        log_to_add = self.out_log_line.get()
        add_to_csv(full_path, [str(datetime.now()), log_to_add])

    def def_output_filename(self):
        """
        Defines name od csv (log) file
        :return:
        """
        if not self.ongoing_capture:
            global_var.output_file_name = self.out_text_file_name.get()
            print(global_var.filepath+'\\'+global_var.output_file_name+'.csv')
        else:
            print("Stop capture first")






interface = Interface(fenetre)
interface.mainloop()

