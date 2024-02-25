import random
import socket
import struct
import sys


def create_dns_query(hostName):
    print("Preparing DNS query..")
    # Generate a random 16 bit number (2 Bytes)
    id = random.randint(0, 0xFFFF)

    # We set flags to 0000000100000000.
    # First bit is 0 => Query
    # 8th bit is 1 => RecursionDesired is needed

    # int(a, b)
    # a is a number in string format.
    # b represents type of number a (bin, dec, hex)

    #to_bytes(a, byte_order)
    # a represents number of bytes of output
    # byte_order represents order (big-endian, small-endian)

    flags = int("0000000100000000", 2).to_bytes(2, byteorder='big')

    QDCOUNT = 1
    ANCOUNT = 0
    NSCOUNT = 0
    ARCOUNT = 0

    # We use struct here as it provides various functions for packing and unpacking
    # of variable length data in binary format.

    # >H2sHHHH represents Header Format
    # > represents big-endian order (Most Significant Bit first)
    # H represents unsigned short of 2 Bytes (id)
    # 2s represents a string of 2 Bytes (flags)
    # H represents unsigned short of 2 Bytes (QDCOUNT)
    # H represents unsigned short of 2 Bytes (ANCOUNT)
    # H represents unsigned short of 2 Bytes (NSCOUNT)
    # H represents unsigned short of 2 Bytes (ARCOUNT)

    header = struct.pack(">H2sHHHH", id, flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)

    # Body should be in Bytes format
    request_body = b""

    for label in hostName.split("."):
        # Here B represents unsigned character of 1 Byte
        request_body += struct.pack("B", len(label))
        request_body += label.encode()

    # QNAME: Terminates with the zero length octet
    request_body += int("0", 2).to_bytes(1, byteorder='big')

    # QTYPE: Set to 1 because we are only interested in A type records
    request_body += struct.pack(">H", 1)

    # QCLASS: Set to 1 (Internet)
    request_body += struct.pack(">H", 1)

    return header + request_body


def send_dns_query(dns_request):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
        # Setting timeout to 5 seconds
        udp_socket.settimeout(5)
        # Sending DNS Query
        print(f"Sending DNS query...")
        for retry in range(1, 4):
            try:
                udp_socket.sendto(dns_request, ("8.8.8.8", 53))
                dns_response, _ = udp_socket.recvfrom(1024)
                print(f"DNS response received (attempt {retry} of 3)")
                return dns_response

            except socket.timeout as e:
                if retry < 3:
                    print(f"Request failed (attempt {retry} of 3). Retrying again ...")
                else:
                    print("All 3 attempts failed.")
                    print(e)
                    break
            except Exception as e:
                print(e)
    return None


def parse_headers(dns_response, next_byte_num):
    headers = {}
    # parsing ID (2 Bytes)
    id_bytes = dns_response[next_byte_num:next_byte_num + 2]
    id = bytes_to_hex(id_bytes)
    headers['header.ID'] = id
    next_byte_num += 2

    # parsing flags ( 2 Bytes)
    flags = dns_response[next_byte_num:next_byte_num + 2]
    flags = "".join((str(bin(byte)))[2:] for byte in flags)
    next_byte_num += 2

    headers['header.QR'] = int(flags[0], 2)
    headers['header.OPCODE'] = int(flags[1:5], 2)
    headers['header.AA'] = int(flags[5], 2)
    headers['header.TC'] = int(flags[6], 2)
    headers['header.RD'] = int(flags[7], 2)
    headers['header.RA'] = int(flags[8], 2)
    headers['header.Z'] = int(flags[9:12], 2)
    headers['header.RCODE'] = int(flags[12:], 2)

    # parsing COUNTS ( 4 of 2 Bytes)
    headers['header.QDCOUNT'] = sum(i for i in dns_response[next_byte_num:next_byte_num + 2])
    next_byte_num += 2
    headers['header.ANCOUNT'] = sum(i for i in dns_response[next_byte_num:next_byte_num + 2])
    next_byte_num += 2
    headers['header.NSCOUNT'] = sum(i for i in dns_response[next_byte_num:next_byte_num + 2])
    next_byte_num += 2
    headers['header.ARCOUNT'] = sum(i for i in dns_response[next_byte_num:next_byte_num + 2])
    next_byte_num += 2

    return headers, next_byte_num


def parse_question(dns_response, next_byte_num, qnum):
    question = {}
    # parsing QNAME
    QNAME, next_byte_num = get_question_name_from_bytes(dns_response, start_byte=next_byte_num)
    question['question' + qnum + '.QNAME'] = QNAME
    # Increment of byte number done in the function

    # parsing QTYPE
    QTYPE = bytes_to_hex(dns_response[next_byte_num:next_byte_num+2])
    question['question' + qnum + '.QTYPE'] = QTYPE
    next_byte_num += 2

    # parsing QCLASS
    QCLASS = bytes_to_hex(dns_response[next_byte_num:next_byte_num+2])
    question['question' + qnum + '.QCLASS'] = QCLASS
    next_byte_num += 2

    return question, next_byte_num


def parse_RR(dns_response, next_byte_num, RR_Type):
    RR = {}
    # parse RR NAME
    NAME, next_byte_num = get_RR_name_from_bytes(dns_response, start_byte=next_byte_num)
    RR[RR_Type+'.NAME'] = NAME
    # Increment of byte number done in the function

    # parse RR TYPE
    TYPE = bytes_to_hex(dns_response[next_byte_num:next_byte_num+2])
    RR[RR_Type+'.TYPE'] = TYPE
    next_byte_num += 2

    # parse RR CLASS
    CLASS = bytes_to_hex(dns_response[next_byte_num:next_byte_num+2])
    RR[RR_Type+'.CLASS'] = CLASS
    next_byte_num += 2

    # parse RR TTL
    TTL = bytes_to_hex(dns_response[next_byte_num:next_byte_num+4])
    RR[RR_Type+'.TTL'] = TTL
    next_byte_num += 4

    # parse RR RDLENGTH
    RDLENGTH = bytes_to_hex(dns_response[next_byte_num:next_byte_num+2])
    RR[RR_Type+'.RDLENGTH'] = RDLENGTH
    next_byte_num += 2

    # parse RR RDATA
    RDATA = ""
    for i in range(4):
        RDATA += str(dns_response[next_byte_num]) + "."
        next_byte_num += 1
    RDATA = RDATA[:-1]
    RR[RR_Type+'.RDATA'] = RDATA

    return RR, next_byte_num


def parse_dns_query(dns_response):
    print("Processing DNS response..")
    human_readable_response = {}
    headers, next_byte_num = parse_headers(dns_response, next_byte_num=0)
    human_readable_response.update(headers)

    # parse all Questions
    for i in range(1, headers['header.QDCOUNT'] + 1):
        question, next_byte_num = parse_question(dns_response, next_byte_num, str(i))
        human_readable_response.update(question)

    # parse all Answer Resource Records
    for i in range(1, headers['header.ANCOUNT'] + 1):
        answer, next_byte_num = parse_RR(dns_response, next_byte_num, 'answer' + str(i))
        human_readable_response.update(answer)

    # parse all Authority Resource Records
    for i in range(1, headers['header.NSCOUNT'] + 1):
        authority, next_byte_num = parse_RR(dns_response, next_byte_num, 'authority' + str(i))
        human_readable_response.update(authority)

    # parse all Additional Resource Records
    for i in range(1, headers['header.ARCOUNT'] + 1):
        additional, next_byte_num = parse_RR(dns_response, next_byte_num, 'additional' + str(i))
        human_readable_response.update(additional)

    return human_readable_response


def get_RR_name_from_bytes(dns_response, start_byte):
    # get length of the label
    length_of_label = dns_response[start_byte]
    name = ''
    # AND operation with 0xc0(11000000) checks if the first two bits of the length of label are set.
    # If they are set, then DNS compression has been done and pointer to the actual name is
    # represented by next 14 bits.
    if length_of_label & 0xc0 == 0xc0:
        # > represents Big-endian order
        # H represents unsigned short of 2 Bytes (length and pointer)
        # AND operation with 0x3FFF(0011111111111111) masks (set bits to 0) the length of label
        # and gives us the next 14 bits.
        pointer_byte = struct.unpack('>H', dns_response[start_byte:start_byte + 2])[0] & 0x3FFF
        name, _ = get_question_name_from_bytes(dns_response, pointer_byte)
    return name, start_byte + 2


def get_question_name_from_bytes(dns_response, start_byte):
    name = ""
    # parse till we reach an empty octet
    while dns_response[start_byte] != 0:
        # get length of the label
        length_of_label = dns_response[start_byte]
        start_byte += 1
        # parse label
        for i in range(length_of_label):
            name += chr(dns_response[start_byte])
            start_byte += 1
        name += "."

    return name[:-1], start_byte + 1


def bytes_to_hex(bytes):
    count = 0
    for index, i in enumerate(reversed(bytes)):
        count += i * 16 ** (2 * index)
    return count


def print_response(response):
    for key, value in response.items():
        print(f'{key:20s} = {"":3s} {value}')
    print("-" * 100)
    print("\n\n")


if len(sys.argv) < 2:
    print("Provide Input in this format: python my-dns-client.py <hostname>")
    sys.exit(1)


# Extract the hostName from the command-line arguments
hostName = sys.argv[1]
print(f'Received a request to get IP Address for {hostName}')

dns_request = create_dns_query(hostName)
print("Contacting DNS server..")
dns_response = send_dns_query(dns_request)
human_readable_response = parse_dns_query(dns_response)
print("-" * 100)
print_response(human_readable_response)
