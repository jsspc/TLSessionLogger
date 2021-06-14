import logging
from storing_process import add_to_csv
from logs_SR import logger
from os import path
import global_var

def alert_user(res_type, *args):
    if res_type == 1:
        print("Client - SID - "+args[3]+" - " +args[0][:5] + "..." + args[0][-5:])
        logger.log(logging.ERROR, "Client - SID - "+args[3]+" - " +args[0][:5] + "..." + args[0][-5:])
    if res_type == 2:
        print("Client - STK - "+args[3]+" - " +args[0][:5] + "..." + args[0][-5:])
        logger.log(logging.ERROR, "Client - STK - "+args[3]+" - " +args[0][:5] + "..." + args[0][-5:])
    if res_type == 3:
        print("Server - SID - "+" - " +args[0][:5] + "..." + args[0][-5:])
        logger.log(logging.WARNING, "Server - SID - " +args[0][:5] + "..." + args[0][-5:])
    if res_type == 4:
        print("Server - STK - "+args[0][:5] + "..." + args[0][-5:])
        logger.log(logging.WARNING, "Server - STK - "+args[0][:5] + "..." + args[0][-5:])
    if res_type == 5:
        print("Client - PSK - "+args[3]+" - " +args[0][:5] + "..." + args[0][-5:])
        logger.log(logging.ERROR, "Client - PSK - "+args[3]+" - " +args[0][:5] + "..." + args[0][-5:])
    if res_type == 6:
        print("Client - SID - "+args[0])
        logger.log(logging.CRITICAL, "Client - NEW - "+args[0]+" - " +args[1][:5] + "..." + args[1][-5:])