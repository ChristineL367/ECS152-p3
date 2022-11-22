import sys

def combine(f1, f2, f_type, file_read):
    f1o = open(f1, "r"); f2o = open(f2, "r")
    data = ""

    f1r = f1o.readline(); f2r = f2o.readline()

    while f1r != '' and f2r != '':
        x1 = f1r.split("| "); x2 = f2r.split("| ")
        

        if float(x1[-1]) >= float(x2[-1]):
            data += f2r
            f2r = f2o.readline()
        else:
            data += f1r
            f1r = f1o.readline()
    
    if f1r == '':
        while f2r != '':
            data += f2r
            f2r = f2o.readline()
    else: 
        while f1r != '':
            data += f1r
            f1r = f1o.readline()
    
    log_file = f_type + "_log_" + file_read + ".txt"
    with open (log_file, 'w') as f:
        f.write(data)

    f1o.close(); f2o.close()


if __name__ == '__main__':
    f1 = sys.argv[1]
    f2 = sys.argv[2]
    f_type = sys.argv[3]
    
    if len(sys.argv) > 1:
        file_read = sys.argv[4]
    else:
        file_read = ''

    combine(f1, f2, f_type, file_read)