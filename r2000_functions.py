import time
import json
import requests
import array as arr
import math
import numpy as np

# define function to create_file
def save_ip(sensor_ip_address, pc_ip_address):
    file = open('network.dat', 'w')
    file.write(str(sensor_ip_address) + '\n' + str(pc_ip_address) + '\n')
    file.close()
    print('network setup:' + '\n' + 'sensor_ip_address:'+ sensor_ip_address + '\n' + 'pc_ip_address:' + pc_ip_address + '\n')

def send_request(url):
    try:
        r = requests.get(url, timeout=3)
        print(r.text)
    except:
        print ('error: no connection')
        return

def request_handle(url):
    try:
        r = requests.get(url, timeout=3)
        data = r.json()
        handle =data['handle']
        file = open('handle.dat', 'w')
        file.write(handle)
        file.close()
        print(r.text)
    except:
        print ('error: no connection')
        return

def read_ip():
    file = open('network.dat', 'r')
    content = file.read().splitlines()
    file.close()
    # print('network setup:' + '\n' + 'sensor_ip_address:'+ content[0] + '\n' + 'pc_ip_address:' + content[1] + '\n')
    return (content)

def check_ip():
    print('network setup:' + '\n' + 'sensor_ip_address:'+ read_ip()[0] + '\n' + 'pc_ip_address:' + read_ip()[1] + '\n')

def read_handle():
    file = open('Handle.dat', 'r')
    content = file.read()
    file.close()
    return (content)

def twos_complement_to_decimal(binary_str):
    n = len(binary_str)
    
    # Check if the number is negative
    if binary_str[0] == '1':
        # Invert all bits
        inverted_bits = ''.join('1' if bit == '0' else '0' for bit in binary_str)
        # Convert inverted binary to decimal and add 1
        decimal = int(inverted_bits, 2) + 1
        # Make it negative
        decimal = -decimal
    else:
        # Convert directly to decimal
        decimal = int(binary_str, 2)

    return decimal

import socket

def socket_connect(pc_ip_address):

    HOST = pc_ip_address
    PORT = 6464

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    s.bind((HOST, PORT))
    print('server start at: %s:%s' % (HOST, PORT))
        
    MAGIC_BYTES = b'\x5c\xa2'
    buffer = b''
    
    try: 
        while True:  
                data, adder = s.recvfrom(65536)
                print('recvfrom ' + str(adder))
                data_interpret(data)
                # buffer += data
                                
                # while True:
                #     start_index = buffer.find(MAGIC_BYTES)
                #     if start_index != -1:
                #         end_index = buffer.find(MAGIC_BYTES, start_index + len(MAGIC_BYTES))
                #         if end_index != -1:
                #             packet_data = buffer[start_index:(end_index + 1)]
                #             data_interpret(packet_data)
                #             # print (str(packet_data))
                #             buffer = buffer[end_index:]
                #         else:
                #             break
                #     else:
                #         break

    except KeyboardInterrupt:           
            s.close()
            print ('socket closed')

def data_interpret (packet_data):
    magic = hex(packet_data[1]) +','+ hex(packet_data[0])  #unit16
    packet_type = chr(packet_data[2]) + chr(packet_data[3]) #unit16
    packet_size = packet_data[7]*(256**3)+packet_data[6]*(256**2)+packet_data[5]*256+packet_data[4] #unit32
    header_size = packet_data[9]*256+packet_data[8] #unit16
    scan_number = packet_data[11]*256+packet_data[10] #unit16
    packet_number = packet_data[13] * 256 + packet_data[12] #unit16

    timestamp_raw = (packet_data[21]*(256**7)+packet_data[20]*(256**6)+packet_data[19]*(256**5)+packet_data[18]*(256**4)+packet_data[17]*(256**3)+packet_data[16]*(256**2)+packet_data[15]*256+packet_data[14]) #ntp64
    # timestamp_sync = (packet_data[29]*(256**7)+packet_data[28]*(256**6)+packet_data[27]*(256**5)+packet_data[26]*(256**4)+packet_data[25]*(256**3)+packet_data[24]*(256**2)+packet_data[23]*256+packet_data[22]) #ntp64
                                
    status_flags = packet_data[33]*(256**3)+packet_data[32]*(256**2)+packet_data[31]*256+packet_data[30] #unit32
    scan_frequency =  (packet_data[37] * (256**3)+packet_data[36] * (256**2)+ packet_data[35] * (256) + packet_data[34])/1000 #unit32
    num_points_scan = packet_data[39] * 256 + packet_data[38] #unit16
    num_points_packet = packet_data[41] * 256 + packet_data[40] #unit16
    first_index = packet_data[43] * 256 + packet_data[42]
    first_angle = (twos_complement_to_decimal(bin(packet_data[47]*(256**3)+packet_data[46]*(256**2)+packet_data[45]*256+packet_data[44])[2:].zfill(32))/10000)
    angular_increment = ((packet_data[51]*(256**3)+packet_data[50]*(256**2)+packet_data[49]*256+packet_data[48])/10000)
    
    iq_input = bin(packet_data[55]*(256**3)+packet_data[54]*(256**2)+packet_data[53]*256+packet_data[52])[2:].zfill(32)
    iq_overload = bin(packet_data[59]*(256**3)+packet_data[58]*(256**2)+packet_data[57]*256+packet_data[56])[2:].zfill(32)
    iq_timestamp_raw = (packet_data[66]*(256**7)+packet_data[65]*(256**6)+packet_data[64]*(256**5)+packet_data[63]*(256**4)+packet_data[62]*(256**3)+packet_data[61]*(256**2)+packet_data[60]*256+packet_data[59])
    iq_timestamp_sync = (packet_data[74]*(256**7)+packet_data[73]*(256**6)+packet_data[72]*(256**5)+packet_data[71]*(256**4)+packet_data[70]*(256**3)+packet_data[69]*(256**2)+packet_data[68]*256+packet_data[67])

    header_padding = packet_data[75]
    # scan_point_data_bin = []
    # scan_point_data = []
    distance_array = []
    amplitude_array = []
    
    for i in range(header_size,packet_size,4):
        # scan_point_data_bin.append([packet_data[i+3], packet_data[i+2], packet_data[i+1], packet_data[i]])
        # scan_point_data.append([hex(packet_data[i+3]), hex(packet_data[i+2]), hex(packet_data[i+1]), hex(packet_data[i])])
        distance_array.append(((packet_data[i+3]*(256**3)+packet_data[i+2]*(256**2)+packet_data[i+1]*256+packet_data[i])& 1048575))
        amplitude_array.append((((packet_data[i+3]*(256**3)+packet_data[i+2]*(256**2)+packet_data[i+1]*256+packet_data[i]))>>20))
    
    
    
    print('magic:' + magic)
    print('packet_type:' + packet_type)
    print('packet_size:' + str(packet_size)) 
    print('header_size:' + str(header_size)) 
    print('scan_number:' + str(scan_number)) 
    print('packet_number:' + str(packet_number)) 
    
    print('timestamp_raw:' + str(timestamp_raw))
    print('status_flags:' + str(status_flags))
    print('scan_frequency:' + str(scan_frequency))
    print('num_points_scan:' + str(num_points_scan))
    print('num_points_packet:' + str(num_points_packet))
    print('first_index:' + str(first_index))
    print('first_angle:' + str(first_angle))
    print('angular_increment:' + str(angular_increment))
    print('iq_input:' + str(iq_input))
    print('iq_overload:' + str(iq_overload))
    print('iq_timestamp_raw:' + str(iq_timestamp_raw))
    print('iq_timestamp_sync:' + str(iq_timestamp_sync))
    print('header_padding:' + str(header_padding))

    print('distance:' + str(distance_array))
    # print(len(distance_array))
    print('amplitude:' + str(amplitude_array))
    # print(len(amplitude_array))
    # if (min(distance_array) < 400):
    #     time.sleep(5)
    #     print ('obstacal detected')
    #     print('min. distance:' + str(min(distance_array)))
    # mean_left = np.mean(distance_array[0:50])
    # mean_right = np.mean(distance_array[51:100])
    # if mean_left < mean_right:
    #     print ('TURN LEFT')
    # elif mean_left > mean_right:
    #     print ('TURN RIGHT')


# http commands
def http_commands (command):
    url = 'http://'+ read_ip()[0] + '/cmd/' + command
    return url

print('current network setup:' + '\n' + 'sensor_ip_address:'+ read_ip()[0] + '\n' + 'pc_ip_address:' + read_ip()[1] + '\n')


    
