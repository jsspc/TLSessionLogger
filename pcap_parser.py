from datetime import datetime
from utils import find_version, find_server_name
from notif_process import alert_user

def parse_packet(pck, pck_nb):
    """
    parses a packet
    :param pck: packet (Scapy)
    :param pck_nb: number of packet in pcap file
    :return:
    """
    try:
        var_tls = pck['TLS']
        # if this works, then we are working with a tls packet; else, try fails, and we break out of function
        if var_tls.type == 22:
            # Handshake message
            # there might be several handshake messages types in that packet (server hello,change cipher, etc)
            # we are ony interested in ClientHello (resumption?) [1] ServerHello [2] and NewSessionTicket [4]
            for tls_msg in var_tls.msg:
                # for each message, check the type
                msg_type = tls_msg.msgtype
                if msg_type == 1:
                    res = False
                    # ClientHello - Clients are the ones starting the resumption (non empty SessionID, ticket extension)
                    tls_version = find_version(tls_msg)
                    servername = find_server_name(tls_msg)
                    if tls_msg.sidlen != 0 and tls_version == 2 :
                        # we check TLS version:
                        # ClientHello and not empty SessionID and tls 1.2: resumption
                        sessionid = tls_msg.sid.hex()
                        serverip = pck["IP"].dst
                        serverport = pck["TCP"].dport
                        res_type = 1
                        lifetime = None
                        client_entry = datetime.now()
                        alert_user(1, sessionid, 'cm', serverip, servername)
                        res = True
                        try:
                            # ip, port, type, value, created, lifetime, usage_client_entry, usage_server_entry
                            yield {'ip': serverip, 'port': serverport, 'resumption_type': res_type,
                                   'token': sessionid, 'created': None, 'lifespan': lifetime,
                                   'tls_vp': tls_version, 'entry': client_entry, 'source': 'c'}
                        except Exception as e:
                            print("Issue", e)
                            continue

                    # we check to see if there is a Session Ticket extension
                    for extension in tls_msg.ext:
                        if extension.type == 35:
                            # Session Ticket extension here
                            if extension.len != 0:
                                # non empty ticket: resumption from Client
                                ticket = extension.ticket.hex()
                                serverip = pck["IP"].dst
                                serverport = pck["TCP"].dport
                                res_type = 2  # Ticket resumption
                                # lifetime = extension.lifetime # no lifetime field in Scapy
                                client_entry = datetime.now()
                                # we have the right info, send to DB
                                alert_user(2, ticket, 'cm', serverip, servername)
                                res = True
                                try:
                                    # ip, port, type, value, created, lifetime, usage_client_entry, usage_server_entry
                                    yield {'ip': serverip, 'port': serverport, 'resumption_type': res_type,
                                           'token': ticket, 'created': None, 'lifespan': None,
                                           'tls_vp': tls_version, 'entry': client_entry, 'source': 'c'}

                                except Exception as e:
                                    print("Issue", e)
                                    continue
                            break  # no need to continue the extension loop, we found it already

                    # we check to see if it is a PSK resumption
                    for extension in tls_msg.ext:
                        if extension.type == 41:
                            ids = extension.identities
                            psk_key = ids[0].identity[0].key_name.hex()
                            psk_iv = ids[0].identity[0].iv.hex()
                            psk_encstatelen = hex(ids[0].identity[0].encstatelen)
                            psk_encstate = ids[0].identity[0].encstate.hex()
                            psk_mac = ids[0].identity[0].mac
                            if psk_mac == None:
                                psk_mac = ''
                            else:
                                psk_mac = psk_mac.hex()
                            psk_key = str(psk_key) + str(psk_iv) + str(psk_encstatelen)[2:] + str(psk_encstate) + str(psk_mac)
                            serverip = pck["IP"].dst
                            serverport = pck["TCP"].dport
                            alert_user(5, psk_key, 'cm', serverip, servername)
                            res = True
                            lifetime = extension.identities[0].obfuscated_ticket_age
                            client_entry = datetime.now()
                            try:
                                # ip, port, type, value, created, lifetime, usage_client_entry, usage_server_entry
                                yield {'ip': serverip, 'port': serverport, 'resumption_type': 3,
                                       'token': psk_key, 'created': None, 'lifespan': lifetime,
                                       'tls_vp': tls_version, 'source': 'c', 'entry': client_entry}
                            except Exception as e:
                                print("Issue", e)
                                continue
                            break
                    if not res:
                        # This will display all the non-resumption ClientHello; needed to see TLS SessionID resumption from TLSv1.3 defualt clients
                        if tls_msg.sidlen != 0:
                            # This might be a resumption or an echo depending on the answer from ServerHello, so we log it as gray
                            sessionid = tls_msg.sid.hex()
                            alert_user(6, servername, sessionid)

                elif msg_type == 2:
                    # ServerHello message

                    tls_version = find_version(tls_msg)
                    # ServerHello has no server_name field

                    # ServerHello - Servers are the ones setting the SessionID or confirming incoming NewSessionTicket msg
                    if tls_msg.sidlen != 0 and tls_version == 2:
                        # SessionID not empty: sets new value (new handshake or failed resumption), or confirms resumption
                        sessionid = tls_msg.sid.hex()
                        # get the data we need to fill DB
                        serverip = pck["IP"].src
                        serverport = pck["TCP"].sport
                        # new_usage = datetime.now()
                        server_entry = datetime.now()
                        alert_user(3, sessionid)
                        try:
                            # ip, port, type, value, created, lifetime, tls_version, usage_client_entry, usage_server_entry
                            yield {'ip': serverip, 'port': serverport, 'resumption_type': 1,
                                   'token': sessionid, 'created': None, 'lifespan': None,
                                   'tls_vp': tls_version, 'source': 's', 'entry': server_entry}
                        except Exception as e:
                            print("Issue", e)
                            continue

                    # TLS 1.3 resumption: nothing to observe, server will just send encrypted NewSessionTicket later on

                elif msg_type == 4:
                    # NewSessionTicket message: here we consider it is necessarily TLS1.2
                    tls_version = 2
                    ticket = tls_msg.ticket.hex()
                    serverip = pck["IP"].src
                    serverport = pck["TCP"].sport
                    server_entry = datetime.now()  # we consider this is a pretty accurate time as parsing is done live
                    alert_user(4, ticket, 'sm', serverip)
                    try:
                        # ip, port, type, value, tls_version, created, lifetime, usage_client_entry, usage_server_entry
                        yield {'ip': serverip, 'port': serverport, 'resumption_type': 2,
                               'token': ticket, 'created': None, 'lifespan': None,
                               'tls_vp': tls_version, 'source': 's', 'entry': server_entry}
                    except Exception as e:
                        print("Issue", e)
                        continue


    except Exception as e:
        # the packet has no "TLS" entry, we just pass it
        pass


