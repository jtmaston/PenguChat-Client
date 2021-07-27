# Contains the different network components ( called daemons cause they run in the background )


import os
import time
from base64 import b64decode, b64encode
from os import makedirs
from os.path import basename
from pickle import dumps as p_dumps
from pickle import loads as p_loads
from socket import socket
from sys import platform

import pyaudio
from Crypto.Cipher import AES
from appdirs import user_data_dir

from DBHandler import get_common_key, save_message

data_directory = user_data_dir("PenguChat")

server_address = 'localhost'  # REMEMBER, FOR DEMO CHANGE TO LOCALHOST | note: I have bad memory. At home, the server
# runs remotely ( to simulate real life use ).  Someone else needs to run it on localhost.


def receiver_daemon(packet, queue):  # handles receiving data from the server
    chunk_size = 2 ** 29  # a nice compromise i've found for speed and ram usage. About 500ish megs can be
    sock = socket()  # can be read per transfer. Realistically, that's never achieved but yk... it's fast

    global server_address
    sock.connect((server_address, packet['port']))  # when receiving, the client connects to the server on a separate
    # socket to the one text is transmitted through.

    cipher = AES.new(get_common_key(packet['destination'], packet['sender']), AES.MODE_SIV)
    encrypted_filename = p_loads(b64decode(packet['filename']))
    filename = cipher.decrypt_and_verify(encrypted_filename[0], encrypted_filename[1]).decode()
    packet['display_name'] = filename  # this bit ↑ decrypts the filename to know how to save it to disk

    if not os.path.exists(f"{data_directory}/files/{packet['destination']}"):
        makedirs(f"{data_directory}/files/{packet['destination']}")

    if os.path.isfile(f"{data_directory}/files/{packet['destination']}/{filename}"):
        filename = filename[0: filename.find('.')] + "(1)" + filename[filename.find('.'):]
        number = int(filename[(filename.find('(') + 1): filename.find(')')])
        while os.path.isfile(f"{data_directory}/files/{packet['destination']}/{filename}"):
            number += 1
            filename = filename[0: filename.find('(') + 1] + str(number) + filename[filename.rfind(')'):]

    # all this ↑ convoluted part does is make sure no naming conflicts appear on disk. Files are stored incrementally,
    # using the tried and tested file(number).extension naming scheme. The database memorizes both display name and
    # the actual name on disk

    file = open(f"{data_directory}/files/{packet['destination']}/{filename}", "wb+")
    # start = time.time()
    chunk = sock.recv(chunk_size)
    blob = b""
    while chunk:
        blob += chunk
        chunk = sock.recv(chunk_size)
    # end = time.time()
    # print(f"Transfer rate is {floor(len(blob) / 1000000 / (end - start + 0.01) * 8)} mbps")
    # ↑ used this a lot during testing. kinda accurate? eyeballing it and ifstat seems to make it ok-ish.
    # your mileage may vary.

    # print("File recv'd. Starting decryption.")
    cipher = AES.new(get_common_key(packet['destination'], packet['sender']), AES.MODE_SIV)
    blob = b64decode(blob)
    blob.strip('\r\n'.encode())
    blob = p_loads(blob)
    blob = p_loads(cipher.decrypt_and_verify(blob[0], blob[1]))
    file.write(blob['file_blob'])

    # this ↑ bit decrypts the file. Since we're running on another thread, this doesn't hinder the main program loop
    # ( except maybe on pc's with few cores? My E8135 2.66GHz beast runs it fine.

    # print("Decryption done.")

    packet['content'] = packet['display_name']
    packet['isfile'] = True
    packet['filename'] = f"{data_directory}/files/{packet['destination']}/{filename}"

    # ↑ basically , memorize both display name ( 'test.zip' ) and path ( "C:\Users\Foo\Bar\test.zip" )

    save_message(packet, packet['destination'], f"{data_directory}/files/{packet['destination']}/{filename}")

    file.close()
    sock.close()
    queue.put(packet)


def sender_daemon(file_path, queue, destination, username, sock, packet):  # this sends data. Very similar to above
    # print("Started sender Daemon.")              # and a direct port of the code I used on the server. Recycling!
    file = open(file_path, 'rb')
    data = file.read()

    filename = basename(file.name)
    cipher = AES.new(get_common_key(destination, username), AES.MODE_SIV)
    data = p_dumps({'filename': filename, 'file_blob': data})
    blob = p_dumps(cipher.encrypt_and_digest(data)) + '\r\n'.encode()
    blob = b64encode(blob)

    # print("Encryption done. Listening.")
    # print(sock.getsockname())
    # ↑ uhh, these are debug prints. Keeping 'em for when something breaks.

    client_socket, addr = sock.accept()

    # print(f"Started connection with {addr}")
    client_socket.sendall(blob)
    # sendall seems to be magical. on windows, it's not even blocking. Can't measure its speed. I tried and got
    # about 14000mbps.
    #print(client_socket.getpeername())
    #print(client_socket.recv(20))
    print("done")
    client_socket.close()
    sock.close()

    packet['display_name'] = filename

    if not os.path.exists(f"{data_directory}/files/{packet['sender']}"):
        makedirs(f"{data_directory}/files/{packet['sender']}")

    if os.path.isfile(f"{data_directory}/files/{packet['sender']}/{filename}"):
        filename = filename[0: filename.find('.')] + "(1)" + filename[filename.find('.'):]
        number = int(filename[(filename.find('(') + 1): filename.find(')')])
        while os.path.isfile(f"{data_directory}/files/{packet['sender']}/{filename}"):
            number += 1
            filename = filename[0: filename.find('(') + 1] + str(number) + filename[filename.rfind(')'):]

    # same as above.

    if platform.startswith("win"):
        cmd = "copy " + \
              f'"{file_path} "'.replace('/', '\\') + \
              f' "{data_directory}/files/{packet["sender"]}/{filename}"'.replace('/', '\\')

    else:
        cmd = 'cp ' + \
              f'"{file_path}" ' + \
              f'" {data_directory}/files/{packet["sender"]}/{filename}"'

    # this copies the file to a cache location ( the user_data_dir ). Since the original file can be deleted, the user
    # might still want to get it at a later date. This *feels* sketchy, but leaving the transfer up to the OS seems
    # smarter than anything I could do.
    os.system(cmd)

    packet['content'] = packet['display_name']
    packet['isfile'] = True
    packet['filename'] = filename
    save_message(packet, packet['sender'], filename=f'{data_directory}/files/{packet["sender"]}/{filename}')
    queue.put(packet)
    return


def voip_listener_daemon(sock, application):  # Used with VoIP. This is a stub. Accepts an incoming stream of raw
    sock.listen(1)  # audio ( haven't figured out codecs yet ), and plays it back. As of
    sock.setblocking(False)  # now, it's unused.

    # print(sock.getsockname())
    while application.calling and application.running:
        try:
            client_socket, addr = sock.accept()
        except BlockingIOError:
            pass
        else:
            application.sound_manager.stop()
            audio_manager = pyaudio.PyAudio()
            call_stream = audio_manager.open(format=pyaudio.paInt16,  # 16 bit integer, 10.2khz audio, mono
                                             channels=1,
                                             rate=10240,
                                             output=True)
            while application.calling:
                try:
                    data = client_socket.recv(1024)
                except BlockingIOError:
                    pass
                else:
                    call_stream.write(data)  # as the packets are read, they're played back
                    client_socket.send('ACK'.encode())  # and an acknowledgement packet is sent.

            client_socket.close()
            sock.close()
            call_stream.close()
            audio_manager.terminate()
            return
    return

# def voip_speaker_daemon():  # yeah.
# sock = socket()
