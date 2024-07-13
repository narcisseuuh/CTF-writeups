from pwn import *

def read_seccomptemplate(name):
    with open(name, mode='rb') as f:
        return f.read()

def parse_c_source(name):
    source = ''
    with open(name, mode='r') as f:
        source = f.read()
    source = source.split(';\n')[:-1]
    values = [int(elem, 16) for elem in source]
    return values

def int_to_bytes(i):
    return int.to_bytes(i, byteorder='little')

def extract_table(values):
    table = []
    for i in range(0, len(values), 4):
        curr_payload = int_to_bytes(values[i])[:1]
        curr_payload += b'\x00'
        curr_payload += int_to_bytes(values[i + 1])[:1]
        curr_payload += int_to_bytes(values[i + 2])[:1]
        curr_payload += p32(values[i + 3])
        table.append(curr_payload)
    return table

def write_new_seccomp(values):
    payload = b''
    for elem in values: 
        payload += elem
    with open('seccomp.bpf', 'wb') as f: 
        f.write(payload)

def main():
    """
    Piece of code I wrote to extract the seccomp policies of a file in bpf format.
    """
    tmp = read_seccomptemplate('template.bpf')
    print(tmp)
    values = parse_c_source('seccomp.txt')

    print([hex(elem) for elem in values])

    seccomp_table = extract_table(values)

    write_new_seccomp(seccomp_table)
    print(read_seccomptemplate('seccomp.bpf'))

if __name__ == '__main__':
    main()
