import sys

def combine(f1, f2, f_type):
    f1_num = sum(1 for line in open(f1)); f2_num = sum(1 for line in open(f2))
    f1o = open(f1_num, "r"); f2o = open(f2_num, "r")
    data = ""

    f1r = f1o.readline(); f2r = f2o.readline()

    while f1r != '' or f2r != '':
        x1 = f1r.split("| "); x2 = f2r.split("| ")

        if int(x1[-1]) >= int(x2[-1]):
            data += f2r; data += "\n"
            f2r = f2o.readline()
        else:
            data += f1r; data += "\n"
            f1r = f1o.readline()
    
    if f1r == '':
        while f2r != '':
            data += f2r; data += "\n"
            f2r = f2o.readline()
    else: 
        while f1r != '':
            data += f1r; data += "\n"
            f1r = f1o.readline()
    
    log_file = f_type + "_log.txt"
    with open (log_file, 'w') as f:
        f.write(data)

    f1o.close()
    f2o.close()



if __name__ == '__main__':
    f1 = sys.argv[2]
    f2 = sys.argv[3]
    f_type = sys.argv[4]

    combine(f1, f2, f_type)