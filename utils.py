import subprocess

def find_version(tls_msg):
    has_tls13ext = False
    has_tlsv13 = False
    for extensio in tls_msg.ext:
        if extensio.type == 45:
            has_tls13ext = True
        if extensio.type == 43:
            #  lists the accepted extensions
            try:
                list_ext = extensio.versions
                if 772 in list_ext:
                    has_tlsv13 = True
                # Did not find TLS 1.3 so must be TLS 1.2
                break  # found the right extension, break loop
            except Exception as e:
                # we found the right extension but error occurs: extension.versions is not an entry, only one version supported
                extension_single = extensio.version
                if extension_single == 772:
                    return 3
                elif extension_single == 771:
                    return 2
    if has_tls13ext or has_tlsv13:
        return 3
    return 2

def find_server_name(tls_msg):
    for ext in tls_msg.ext:
        if ext.type == 0:
        # server name extension
            try:
                list_names = ext.servernames
                return list_names[0].servername.decode('utf-8')
            except Exception as e:
                print("ERROR", e, list_names[0].servername)
                return "unknown server name"
    return "unknown server name"




def execute_command(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output, error = process.communicate()
    return output, error


def list_interfaces():
    output, error = execute_command(['dumpcap', '-D'])
    output = output.decode('utf-8')
    output = output.split('\r\n')
    new = [0 for k in range(len(output)-1)]
    for i, elmt in enumerate(output[:len(output)-1]):

        new[i] = elmt.split('(')
        new[i][0] = str(new[i][0].split(' ')[1])
        new[i][1] = new[i][1][:len(new[i][1])-1]

    return new

