
def add_to_csv(csvpath, list_line):
    # list_line = [ip, port, tls_version, type_res, token, created, lifetime]
    newline = list_line[0]
    for elmt in list_line[1:]:
        newline += ',' + elmt
    newline+='\n'
    f = open(csvpath, 'a+')
    f.write(newline)
    f.close()



