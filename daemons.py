import time
from base64 import b64decode, b64encode
from math import floor
from os import makedirs
from os.path import basename
from socket import socket

import pyaudio
from Crypto.Cipher import AES
from appdirs import user_data_dir

from DBHandler import get_common_key, save_message

from pickle import loads as p_loads
from pickle import dumps as p_dumps

data_directory = user_data_dir("PenguChat")

server_address = 'localhost'


def receiver_daemon(packet):
    chunk_size = 2 ** 29
    sock = socket()

    global server_address
    sock.connect((server_address, packet['port']))

    cipher = AES.new(get_common_key(packet['destination'], packet['sender']), AES.MODE_SIV)
    encrypted_filename = p_loads(b64decode(packet['filename']))
    filename = cipher.decrypt_and_verify(encrypted_filename[0], encrypted_filename[1]).decode()

    try:
        file = open(f"{data_directory}/files/{filename}", "wb+")
    except FileNotFoundError:
        makedirs(f"{data_directory}/files")
        file = open(f"{data_directory}/files/{filename}", "wb+")
    start = time.time()
    chunk = sock.recv(chunk_size)
    blob = b""
    while chunk:
        blob += chunk
        chunk = sock.recv(chunk_size)
    end = time.time()
    print(f"Transfer rate is {floor(len(blob) / 1000000 / (end - start + 0.01) * 8)} mbps")

    print("File recv'd. Starting decryption.")
    cipher = AES.new(get_common_key(packet['destination'], packet['sender']), AES.MODE_SIV)
    blob = b64decode(blob)
    blob.strip('\r\n'.encode())
    blob = p_loads(blob)
    blob = p_loads(cipher.decrypt_and_verify(blob[0], blob[1]))
    file.write(blob['file_blob'])
    print("Decryption done.")

    save_message(packet, packet['destination'], filename)

    file.close()
    sock.close()


def sender_daemon(file_name, file_size, destination, username, sock):
    print("Started sender Daemon.")
    file = open(file_name, 'rb')
    data = file.read()
    filename = basename(file.name)
    cipher = AES.new(get_common_key(destination, username), AES.MODE_SIV)
    data = p_dumps({'filename': filename, 'file_blob': data})
    blob = p_dumps(cipher.encrypt_and_digest(data)) + '\r\n'.encode()
    blob = b64encode(blob)

    print("Encryption done. Listening.")
    # sock.setblocking(False)

    print(sock.getsockname())

    client_socket, addr = sock.accept()

    print(f"Started connection with {addr}")
    client_socket.sendall(blob)
    client_socket.close()
    sock.close()
    return


def voip_listener_daemon(sock, application):
    sock.listen(1)
    sock.setblocking(False)

    print(sock.getsockname())
    while application.calling and application.running:
        try:
            client_socket, addr = sock.accept()
        except BlockingIOError:
            pass
        else:
            application.sound_manager.stop()
            audio_manager = pyaudio.PyAudio()
            call_stream = audio_manager.open(format=pyaudio.paInt16,
                                             channels=1,
                                             rate=10240,
                                             output=True)
            while application.calling:
                try:
                    data = client_socket.recv(1024)
                except BlockingIOError:
                    pass
                else:
                    call_stream.write(data)
                    client_socket.send('ACK'.encode())

            client_socket.close()
            sock.close()
            call_stream.close()
            audio_manager.terminate()
            return
    return


def voip_speaker_daemon():
    sock = socket()
