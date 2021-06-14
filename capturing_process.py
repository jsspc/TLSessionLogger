import subprocess
from threading import Thread
from os import getcwd, path
import pcap_reader as reader
import global_var


class Capture:

    def __init__(self, interface, filepath = None, filename = None):
        """
        :param interface: name of interface to capture from (string)
        :param filepath: path of pcap capture file (string)
        :param filename: path of pcap capture file (string)
        """
        global_var.init_global_capture()
        self.capture_status = False
        if filepath is None:
            self.filepath = getcwd()
        else:
            self.filepath = filepath
        if filename is None:
            self.filename = 'capture.pcap'
        else:
            self.filename = filename

        self.full_path = path.normpath(self.filepath+'\\'+self.filename)
        self.interface = interface

        self.reading_process = reader.Reader()
        self.lines_for_log = []

    def start_capture(self):
        """
        starts thread for capture (p1: capture packets; p2: read packets)
        :return:
        """
        self.p1 = Thread(target=self.capture_process_loop)
        self.p1.start()
        self.p2  = Thread(target=self.read_packets)
        self.p2.start()

    def capture_process_loop(self):
        """
        Allows to loop capture while stop is not clicked
        :return:
        """
        self.capture_status = True
        print(self.interface, self.filepath)
        # capture filter does not seem to support TLS filtering, taking it all
        command = ['dumpcap', '-i', self.interface, '-w', self.full_path, '-P']
        process = subprocess.Popen(command, stdout=None, stderr=None, shell=False)
        while self.capture_status:
            # while the stop button is not pressed, we loop here
            pass
        process.kill()
        print("Capture stopped")

    def read_packets(self):
        """
        Starts reading process
        :return:
        """
        print("Reading packets")
        self.reading_process.reading_loop = True
        self.reading_process.get_parsed_packets(self.full_path)

    def stop_capture(self):
        print("Stopping capture...")
        self.capture_status = False
        print("Stopping reading...")
        self.reading_process.stop_reading()

    def change_filepath(self, filepath):
        self.filepath = filepath
        self.full_path = path.normpath(self.filepath + '\\' + self.filename)

    def change_filename(self, filename):
        self.filename = filename + '.pcap'
        self.full_path = path.normpath(self.filepath + '\\' + self.filename)

    def change_interface(self, interface):
        self.interface = interface


