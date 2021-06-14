from os import getcwd

"""
Defines global variables used throughout the program
"""

def init():
    global save_in_log
    save_in_log = False

    global output_file_name
    output_file_name = 'output'


def init_global_capture():
    global filepath
    filepath = getcwd()
