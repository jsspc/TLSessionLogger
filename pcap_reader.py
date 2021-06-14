import os
import time
from scapy.all import PcapReader, load_layer
import pcap_parser as parser
import storing_process as storer
from os import path
import global_var

i = 0

int_to_process = {1: "SID", 2:"STK", 3:"PSK"}

class Reader:
    def __init__(self):
        load_layer('tls')
        self.reading_loop = True

    def get_parsed_packets(self, pcapfile_path):

        try:
            pcap_object = self.create_pcap_reader(pcapfile_path)
        except Exception as e:
            print(e, "Sleep 5 seconds to wait for file creation")
            time.sleep(5)  # leaves some time for file to be created by capture process
            pcap_object = self.create_pcap_reader(pcapfile_path)

        pckts = self.read_live_data(pcap_object)
        filepath = global_var.filepath
        filename = global_var.output_file_name
        full_path = path.normpath(filepath + '\\' + filename + '.csv')

        for i, pck in enumerate(pckts):
            extracted_data = parser.parse_packet(pck, i)
            # parser returns dictionary with relevant entries when a TLS Handshake is parsed
            for new_line in extracted_data:
                if new_line != None:
                    if global_var.save_in_log:
                        token = new_line['token']
                        storer.add_to_csv(full_path, [str(new_line['ip']), new_line['source'], int_to_process[new_line['resumption_type']], str(new_line['entry']), str(len(token)), token])
                    # yield {'ip', 'port', 'resumption_type', 'token', 'created', 'lifespan','tls_vp','source','entry'}
                    # new entry of TLS handshake that could be resumption or new token

    def create_pcap_reader(self, pcapfile_path):
        """
        Creates and returns PcapReader Scapy object
        :param pcapfile_path:
        :return:
        """
        return PcapReader(pcapfile_path)

    def read_live_data(self, pcapfile):
        """
        :param pcapfile: PcapReader object to read
        :return: parsed packet to pcap format (one by one)
        """
        while self.reading_loop:
            # Looping process, won't stop before "Stop capture" is pressed
            try:
                pck = pcapfile.read_packet()
                yield pck
            except EOFError:
                time.sleep(0.01)
                continue

    def looping_read_process(self, pckts):
        """

        :param pckts: list of pcap packets ready to be parsed (will increase as new packets are captured and stored in PCAP file)
        :return: yields dictionnary of relevant informations:
        {'ip', 'port', 'resumption_type', 'token', 'created', 'lifespan', 'tls_vp', 'entry_c', 'entry_s'}
        """

        for pck_nb, pck in enumerate(pckts):
            extracted_data = parser.parse_packet(pck, pck_nb)
            # parser returns dictionary with relevant entries when a TLS Handshake is parsed
            for new_line in extracted_data:
                if new_line != None:
                    # new entry of TLS handshake that could be resumption or new token
                    yield new_line

    def stop_reading(self):
        self.reading_loop = False