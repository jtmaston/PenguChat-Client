from kivy.config import Config
from kivy.utils import get_color_from_hex

Config.set('graphics', 'width', '500')
Config.set('graphics', 'height', '750')

import os
from platform import platform

OS = platform()
if OS[0:OS.find('-')] == 'Windows':  # use DirectX for Windows, prevents some issues when using RDP
    os.environ["KIVY_GL_BACKEND"] = "angle_sdl2"  # ( and is generally better for Win )
import time
from math import floor
from os.path import basename
from socket import socket, AF_INET, SOCK_STREAM
from tkinter import filedialog, Tk

import threading

from kivy.uix.screenmanager import FadeTransition
from kivymd.uix.banner import MDBanner

import kivy.clock
import pyaudio
from appdirs import user_data_dir
from kivy.core.audio import SoundLoader
from twisted.logger import globalLogPublisher, LogLevel

data_directory = user_data_dir("PenguChat")

tkWindow = Tk()  # create a tkinter window, this is used for the native file dialogs
tkWindow.withdraw()  # hide it for now
# init must be done here, to ensure tkinter gets loaded b4 everything else

from pickle import dumps as p_dumps
from base64 import b64encode
from json import dumps, loads
from sys import modules
from kivymd.app import MDApp
from kivy.clock import Clock
from kivy.support import install_twisted_reactor
from kivy.uix.popup import Popup
from kivy.uix.textinput import TextInput
from pyDH import DiffieHellman
from DBHandler import *

Clock.max_iteration = 20
if 'twisted.internet.reactor' in modules:
    del modules['twisted.internet.reactor']
install_twisted_reactor()  # integrate twisted with kivy

from twisted.internet import reactor
from twisted.internet.protocol import Protocol, connectionDone
from twisted.internet.protocol import ClientFactory as Factory
from twisted.python.log import startLogging
from sys import stdout

startLogging(stdout)

from UIElements import *


def analyze(event):
    if event.get("log_level") == LogLevel.critical:
        print("Stopping for: ", event)


running = True
server_address = 'localhost'


class FauxMessage:
    def __init__(self):
        self.isfile = None
        self.message_data = None
        self.sender = None


class PenguChatApp(MDApp):  # this is the main KV app
    _popup: Popup

    def __init__(self):  # set the window params, as well as init some parameters
        super(PenguChatApp, self).__init__()

        Config.set('graphics', 'width', f'{500}')
        Config.set('graphics', 'height', f'{750}')
        self.calling = False
        self.file_socket = socket()
        self.window_size = (
            int(8 / 10 * tkWindow.winfo_screenwidth()),
            int(8 / 10 * tkWindow.winfo_screenheight())
        )
        self.chatroom_pos = (
            int((tkWindow.winfo_screenwidth() - self.window_size[0]) / 2),
            int((tkWindow.winfo_screenheight() - self.window_size[1]) / 2)
        )

        self.username = None
        self.destination = None
        self.__private = None
        self.factory = None
        self.__server_key = None
        self.sidebar_refs = dict()
        self.conversation_refs = []
        self.friend_refs = []
        self.pwd = None
        self.incoming = {}
        self.running = True
        self.sound_manager = None
        self.sidebar_tab = 'F'

    def stop(self, *args):
        global running
        running = False
        print("asking to stop")
        return True

    """App loading section"""

    @staticmethod
    def hide_tk(*args, **kwargs):
        tkWindow.withdraw()

    def build(self):
        super(PenguChatApp, self).build()
        self.root.current = 'loading_screen'  # move to the loading screen
        self.factory = ClientFactory()
        # self.root.ids.conversation.bind(minimum_height=self.root.ids.conversation.setter('height'))
        self.root.ids.requests_button.tab = 'F'
        self.icon = 'Assets/circle-cropped.png'
        global server_address
        # reactor.connectTCP("berrybox.local", 8123, self.factory)  # connect to the server
        # reactor.connectTCP("192.168.137.138", 8123, self.factory)  # connect to the server
        reactor.connectTCP(server_address, 8123, self.factory)  # connect to the server

        self.theme_cls.colors = dict(self.theme_cls.colors, **colors_hex)

    """Server handshake, establish E2E tunnel for password exchange"""

    def secure(self):
        self.__private = DiffieHellman()  # private key is generated
        public = self.__private.gen_public_key()  # public key is derived from it
        command_packet = {
            'command': 'secure',
            'key': public
        }
        self.factory.client.transport.write((dumps(command_packet) + '\r\n').encode())  # send
        # print(f" <- {dumps(command_packet).encode()}")

    """Methods that send data to server"""

    def send_login_data(self):
        pwd = self.root.ids.loginPass.text.strip()  # get username and password from the UI element
        self.username = self.root.ids.loginUsr.text.strip()
        try:  # this block is necessary to make sure that an E2E tunnel exists to the server
            cipher = AES.new(str(self.__server_key).encode(), AES.MODE_SIV)
        except AttributeError:  # if not, connection should be reset in order to get one
            self.factory.client.transport.loseConnection()
            self.fail_connection()
            return False
        encrypted, tag = cipher.encrypt_and_digest(pwd.encode())  # this generates a digest file from the pass
        login_packet = {
            'command': 'login',
            'password': b64encode(encrypted).decode(),
            'tag': b64encode(tag).decode(),
            'sender': self.username,
            'isfile': False
        }
        self.root.current = 'loading_screen'
        self.root.transition = FadeTransition()
        self.factory.client.transport.write((dumps(login_packet) + '\r\n').encode())  # finally, send it
        # print(f" <- {dumps(login_packet).encode()}")

    def send_sign_up_data(self):  # see above method, it's that but with extra steps
        pwd = self.root.ids.passwd.text.strip()
        pwd_r = self.root.ids.passwd_r.text.strip()
        self.username = self.root.ids.username.text.strip()

        self.pwd = pwd

        if pwd == pwd_r:
            cipher = AES.new(str(self.__server_key).encode(), AES.MODE_SIV)
            encrypted, tag = cipher.encrypt_and_digest(pwd.encode())
            signup_packet = {
                'command': 'signup',
                'password': b64encode(encrypted).decode(),
                'tag': b64encode(tag).decode(),
                'sender': self.username
            }
            self.root.current = 'loading_screen'
            self.factory.client.transport.write((dumps(signup_packet) + '\r\n').encode())
            # print(f" <- {dumps(signup_packet).encode()}")

    def logout(self):
        self.factory.client.transport.loseConnection()
        self.root.current = 'loading_screen'
        self.init_chat_room()  # called to clear the chat room, in anticipation of a new one being loaded

    def send_text(self):
        message_text = self.root.ids.message_content.text
        self.root.ids.message_content.text = ""  # clear the message box's contents
        cipher = AES.new(get_common_key(self.destination, self.username), AES.MODE_SIV)  # encryption part
        content = p_dumps(cipher.encrypt_and_digest(message_text.encode()))
        content = b64encode(content).decode()
        packet = {
            'sender': self.username,
            'destination': self.destination,
            'command': 'message',
            'content': content,
            'timestamp': datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
            'isfile': False,
        }
        save_message(packet, self.username)
        f = FauxMessage()
        f.isfile = packet['isfile']
        f.message_data = packet['content']
        f.sender = packet['sender']

        self.add_bubble_to_conversation(f, self.destination)
        self.factory.client.transport.write((dumps(packet) + '\r\n').encode())
        # print(f" <- {dumps(packet).encode()}")

    @staticmethod
    def sender_daemon(file, file_size, destination, username, sock):
        print("Started sender Daemon.")
        data = file.read()
        filename = basename(file.name)
        cipher = AES.new(get_common_key(destination, username), AES.MODE_SIV)
        data = p_dumps({'filename': filename, 'file_blob': data})
        blob = p_dumps(cipher.encrypt_and_digest(data)) + '\r\n'.encode()
        blob = b64encode(blob)

        global running
        print("Encryption done. Listening.")
        sock.listen()
        sock.setblocking(False)

        print(sock.getsockname())
        while running:
            try:
                client_socket, addr = sock.accept()
            except BlockingIOError:
                pass
            else:
                print(f"Started connection with {addr}")
                start = time.time()
                # with open(f'{data_directory}/cache/{local_filename}', 'rb') as f:
                #    client_socket.sendfile(f, 0)
                client_socket.sendall(blob)
                client_socket.close()
                sock.close()
                end = time.time()
                print("Connection done.")
                print(f"Transfer rate is {floor(file_size / 1000000 / (end - start + 0.01) * 8)} mbps")
                return
        return

    def send_file(self):
        file = filedialog.askopenfile(mode="rb")
        tkWindow.update()
        self.hide_tk()

        if file:
            # Get file size, to make sure we *can* load it to RAM
            file.seek(0, os.SEEK_END)
            file_size = file.tell()
            file.seek(0, 0)

            # Encrypt the file, alongside its name. Then store with a random identifier
            filename = basename(file.name)

            cipher = AES.new(get_common_key(self.destination, self.username), AES.MODE_SIV)
            out_filename = p_dumps(cipher.encrypt_and_digest(filename.encode())) + '\r\n'.encode()
            out_filename = b64encode(out_filename).decode()

            sock = socket()
            sock.bind(("0.0.0.0", 0))
            threading.Thread(target=self.sender_daemon,
                             args=(file, file_size, self.destination, self.username, sock)).start()

            packet = {  # metadata
                'sender': self.username,
                'destination': self.destination,
                'command': 'prepare_for_file',
                'timestamp': datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
                'file_size': file_size,
                'filename': out_filename,
                'port': sock.getsockname()[1]
            }

            self.factory.client.transport.write((dumps(packet) + '\r\n').encode())

    @staticmethod
    def receiver_daemon(packet):
        chunk_size = 8 * 1024
        sock = socket()

        global server_address

        print(server_address, packet['port'])
        sock.connect((server_address, packet['port']))
        cipher = AES.new(get_common_key(packet['destination'], packet['sender']), AES.MODE_SIV)

        packet['filename'] = packet['filename'].replace("[SLASH]", '/')
        packet['filename'] = packet['filename'].replace("[BACKSLASH]", '\\')

        encrypted_filename = p_loads(b64decode(packet['filename']))
        filename = cipher.decrypt_and_verify(encrypted_filename[0], encrypted_filename[1]).decode()

        try:
            file = open(f"{data_directory}/files/{filename}", "wb+")
        except FileNotFoundError:
            makedirs(f"{data_directory}/files")
            file = open(f"{data_directory}/files/{filename}", "wb+")

        chunk = sock.recv(chunk_size)
        while chunk:
            # print(chunk)
            file.write(chunk)
            chunk = sock.recv(chunk_size)

        file.close()
        sock.close()

    def ingest_file(self, buffer):

        cipher = AES.new(get_common_key(self.username, self.incoming['sender']), AES.MODE_SIV)
        encrypted_filename = p_loads(b64decode(self.incoming['filename']))

        self.incoming['isfile'] = True
        self.incoming['sender'] = self.incoming['sender']  # TODO: ?
        self.incoming['content'] = buffer.strip(b'\r\n')
        self.incoming['timestamp'] = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        filename = cipher.decrypt_and_verify(encrypted_filename[0], encrypted_filename[1]).decode()

        save_message(self.incoming, self.username, filename)
        f = FauxMessage()
        f.isfile = self.incoming['isfile']
        f.message_data = self.incoming['content']
        f.sender = self.incoming['sender']
        f.destination = self.username
        f.timestamp = self.incoming['timestamp']

        application.add_bubble_to_conversation(f, self.incoming['sender'])
        # print("ingest complete")

    """Helper methods"""

    def secure_server(self, command):  # part of the initial E2E
        self.__server_key = self.__private.gen_shared_key(command['content'])
        self.root.current = 'login'

    def login_ok(self):  # called when login succeeds, changes to the chatroom screen
        for screen in self.root.screens:  # clean any errors that may have appeared. This is ugly. Too bad!
            if screen.name == 'login':
                try:
                    screen.has_error
                except AttributeError:
                    pass
                else:
                    if screen.has_error:
                        screen.has_error = False
                        screen.children[0].remove_widget(screen.children[0].children[
                                                             len(screen.children[0].children) - 1])

        self.root.current = 'chat_room'

    def signup_ok(self):  # ditto above, only for signup
        for screen in self.root.screens:
            if screen.name == 'signup':  # same ugliness
                try:
                    screen.has_error
                except AttributeError:
                    pass
                else:
                    if screen.has_error:
                        screen.has_error = False
                        screen.children[0].remove_widget(screen.children[0].children[
                                                             len(screen.children[0].children) - 1])
                screen.has_error = False

        pwd = self.pwd.strip()  # after the server verifies that the user was correctly registered, also log
        # him in.
        try:
            cipher = AES.new(str(self.__server_key).encode(), AES.MODE_SIV)
        except AttributeError:
            self.factory.client.transport.loseConnection()
            self.fail_connection()
            return False
        encrypted, tag = cipher.encrypt_and_digest(pwd.encode())
        login_packet = {
            'command': 'login',
            'password': b64encode(encrypted).decode(),
            'tag': b64encode(tag).decode(),
            'sender': self.username.strip(),
            'isfile': False
        }
        self.root.current = 'loading_screen'
        Clock.usleep(50000)  # give the client time to catch up and the server to log the user in
        self.factory.client.transport.write((dumps(login_packet) + '\r\n').encode())
        # print(f" <- {dumps(login_packet).encode()}")

    def got_friend_key(self, command):  # called when a common key is established with a partner, after the req.
        add_common_key(command['friend'],
                       self.__private.gen_shared_key(command['content']),
                       self.username)

    def username_taken(self):  # called to change the screen to an errored state
        for screen in self.root.screens:
            if screen.name == 'signup':
                try:
                    screen.has_error
                except AttributeError:
                    screen.has_error = False
                finally:
                    if not screen.has_error:
                        error = ColoredLabel(color='red')
                        error.size_hint_y = 0.2

                        error.text = "Username is taken, sorry!"
                        screen.children[0].add_widget(error, len(screen.children[0].children))
                        screen.has_error = True

        self.root.current = 'signup'

    def login_failed(self):  # called when the signup process fails.
        for screen in self.root.screens:
            if screen.name == 'login':
                try:
                    screen.has_error
                except AttributeError:
                    screen.has_error = False
                finally:
                    if not screen.has_error:
                        error = MDBanner()
                        # error.size_hint_y = 0.2
                        error.text = "Username or password incorrect."
                        screen.children[0].add_widget(error, len(screen.children[0].children))
                        screen.has_error = True

        self.root.current = 'login'

    def new_chat(self):  # called when sending a chat request

        def send_chat_request(text_object):  # save the private key to be used later
            packet = {
                'sender': self.username,
                'command': 'friend_request',
                'content': self.__private.gen_public_key(),
                'destination': text_box.text,
                'timestamp': datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
                'isfile': False
            }
            self.factory.client.transport.write((dumps(packet) + '\r\n').encode())
            # print(f" <- {dumps(packet).encode()}")
            add_private_key(text_box.text, self.__private.get_private_key(), self.username)
            popup.dismiss()

        container = BackgroundContainer(orientation='vertical', padding=10, spacing=10)

        popup = Popup(title='Send friend request',
                      content=container,
                      size_hint=(None, None),
                      size=(400, 300))

        text_box = TextInput(write_tab=False, multiline=False, size_hint_y=0.6)
        button_box = BoxLayout(orientation='horizontal', size_hint_y=0.4, padding=10, spacing=10)

        text_box.bind(on_text_validate=send_chat_request)
        button_send = MenuButton(text="Send!", on_press=send_chat_request)
        button_cancel = MenuButton(text="Cancel", on_press=popup.dismiss)

        container.add_widget(text_box)
        button_box.add_widget(button_send)
        button_box.add_widget(button_cancel)
        container.add_widget(button_box)

        popup.open()

    def accept_request(self, button_object):  # called when accepting the request
        friend = button_object.parent.parent.username  # Must move up two boxes, first parent is ver box second is hor
        friend_key = int(get_key_for_request(self.username, friend).decode())
        common_key = self.__private.gen_shared_key(friend_key)
        add_common_key(friend, common_key, self.username)  # add the common key to the database
        self.root.ids.sidebar.remove_widget(button_object.parent)  # remove the request entry in the sidebar
        delete_request(friend)  # also delete the request from the db
        packet = {
            'sender': self.username,
            'command': 'friend_accept',
            'content': self.__private.gen_public_key(),
            'destination': friend,
            'timestamp': datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
            'isfile': False
        }
        start_message = {  # ths is a blank, ignored packed designed to allow an empty chat room to be displayed
            'sender': packet['destination'],
            'destination': packet['sender'],
            'command': 'message',
            'content': chr(224),
            'timestamp': datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
            'isfile': False
        }
        save_message(start_message, self.username)  # save it
        del self.sidebar_refs[friend]
        self.set_sidebar_to_friend_list()
        self.factory.client.transport.write((dumps(packet) + '\r\n').encode())  # send the acknowledgement
        # print(f" <- {dumps(packet).encode()}")

    def accept_request_reply(self, packet):  # called when the peer has accepted the chat request
        private = DiffieHellman()
        private._DiffieHellman__a = get_private_key(packet['sender'], self.username)
        common = private.gen_shared_key(int(packet['content']))  # Maybe Done: Sometimes getting errors. Why?
        add_common_key(packet['sender'], common, self.username)
        delete_private_key(packet['sender'], self.username)
        start_message = {
            'sender': packet['sender'],
            'destination': self.username,
            'command': 'message',
            'content': chr(224),
            'timestamp': datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
            'isfile': False
        }
        save_message(start_message, self.username)
        self.set_sidebar_to_friend_list()

    def deny_request(self, button_object):  # called when denying the request
        self.root.ids.sidebar.remove_widget(button_object)
        del self.sidebar_refs[button_object.parent.parent.username]
        delete_request(button_object.parent.parent.username)
        self.set_sidebar_to_request_list()

    """Loading methods"""

    def set_sidebar_to_friend_list(self):  # set sidebar to the friends list
        self.root.ids.sidebar.clear_widgets()  # clear all items in the sidebar
        self.root.ids.conversation_button.color = get_color_from_hex("ff9f1e")
        self.root.ids.requests_button.color = get_color_from_hex("e4e5e9")
        self.root.ids.requests_button.font_name = 'Assets/Segoe UI'
        self.root.ids.conversation_button.font_name = 'Assets/Segoe UI Bold'
        self.root.ids.sidebar.rows = 0

        names = get_friends(self.username)  # call the database to see who the prev conversations were

        for i in names:  # create a new button for every friend
            a = ContactName()  # TODO: this part is ugly and sucks. Too bad!
            a.text = i
            a.font_name = 'Assets/Segoe UI'
            a.size_hint = (1, 1)
            a.font_size = '25dp'
            a.halign = 'center'
            a.valign = 'center'
            if i == self.destination:
                a.color = get_color_from_hex("ff9f1e")
            else:
                a.color = get_color_from_hex("5f6c74")

            a.bind(on_press=self.show_message_box)
            self.root.ids.sidebar.rows += 1
            self.root.ids.sidebar.add_widget(a)

            self.friend_refs.append(a)

    def set_sidebar_to_request_list(self):  # pretty much ditto set_sidebar_to_friend_list, see above

        self.root.ids.sidebar.clear_widgets()
        self.root.ids.sidebar.rows = 0
        self.root.ids.conversation_button.color = get_color_from_hex("e4e5e9")
        self.root.ids.requests_button.color = get_color_from_hex("ff9f1e")
        self.root.ids.conversation_button.font_name = 'Assets/Segoe UI'
        self.root.ids.requests_button.font_name = 'Assets/Segoe UI Bold'

        # requests = get_requests(self.username)  # fixed
        # for i in requests:
        #    e = SidebarElement(i)
        #    e.accept.bind(on_press=self.accept_request)
        #    e.decline.bind(on_press=self.deny_request)
        #    self.sidebar_refs[i] = e
        #    self.root.ids.sidebar.rows += 1
        #    self.root.ids.sidebar.add_widget(e.container)
        # self.root.ids.request_button.canvas.ask_update()

    def load_messages(self, partner):  # method to load all the messages
        if len(self.conversation_refs) > 0:  # clear the conversation
            # self.root.ids.conversation.clear_widgets()
            self.conversation_refs.clear()
            # self.root.ids.conversation.rows = 0

        messages = get_messages(partner, self.username)  # call the database to get the messages
        for i in messages:  # decrypt every message and then display it
            print(i)
            #self.add_bubble_to_conversation(i, partner)

    def add_bubble_to_conversation(self, message, partner):
        cipher = AES.new(get_common_key(partner, self.username), AES.MODE_SIV)
        if not message.isfile:
            encrypted = p_loads(b64decode(message.message_data))
            try:
                message.message_data = cipher.decrypt_and_verify(encrypted[0], encrypted[1]).decode()
            except ValueError:
                Logger.error(f"Application: MAC error on message id {message.id}")
                message.message_data = "[Message decryption failed. Most likely the key has changed]"
            finally:
                if message.sender == self.username:
                    e = ConversationElement(side='r', isfile=False, text=message.message_data)
                else:
                    e = ConversationElement(side='l', isfile=False, text=message.message_data)
        else:
            filename = get_filename(message.sender,
                                    message.destination,
                                    message.timestamp
                                    )
            truncated = {
                'sender': message.sender,
                'destination': message.destination,
                'timestamp': message.timestamp
            }
            if message.sender == self.username:
                e = ConversationElement(side='r', isfile=True, filename=filename, truncated=truncated)

            else:
                e = ConversationElement(side='l', isfile=True, filename=filename, truncated=truncated)

        # self.root.ids.conversation.rows += 1
        # self.root.ids.conversation.add_widget(e.line)
        self.conversation_refs.append(e)
        Clock.schedule_once(e.reload, 0.01)  # addresses the bug where the long messages do not display properly

    @staticmethod
    def voip_listener_daemon(sock):
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

    @staticmethod
    def voip_speaker_daemon():
        sock = socket()

    def call(self, already_in_call):
        self.root.current = 'calling'
        self.calling = True
        if not already_in_call:
            self.sound_manager = SoundLoader.load('Assets/dial_tone.wav')
            self.sound_manager.loop = True
            self.sound_manager.play()

        sock = socket(AF_INET, SOCK_STREAM)
        sock.bind(("0.0.0.0", 0))

        packet = {
            'sender': self.username,
            'command': 'call',
            'destination': self.destination,
            'timestamp': datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
            'isfile': False,
            'address': sock.getsockname()[0],
            'port': sock.getsockname()[1]
        }
        threading.Thread(target=application.voip_listener_daemon, args=(sock,)).start()
        self.factory.client.transport.write((dumps(packet) + '\r\n').encode())  # send the acknowledgement

    def end_call(self):
        try:
            self.sound_manager.stop()
        except AttributeError:
            pass

        self.calling = False
        self.root.current = 'chat_room'

    def fail_call(self):
        self.sound_manager.loop = False
        self.sound_manager.stop()
        self.calling = False
        self.sound_manager = SoundLoader.load("Assets/busy_trimmed.wav")
        self.sound_manager.play()
        self.root.current = 'call_failed'
        kivy.clock.ClockBase().usleep(2000000)
        self.root.current = 'chat_room'

    def accept_call(self):
        self.root.current = 'calling'
        self.call(already_in_call=True)

    def init_chat_room(self):  # called upon first entering the chatroom
        # self.hide_message_box()
        self.set_sidebar_to_friend_list()
        # self.root.ids.conversation.clear_widgets()

    """Widget methods"""

    def show_message_box(self, button_object):  # show the message box down TODO: text is blue. Why is text blue?
        self.destination = button_object.text

        # self.root.ids.message_box.foreground_color = (0, 0, 0)
        self.set_sidebar_to_friend_list()
        # if self.check_if_hidden(self.root.ids.message_box):
        #  self.show_widget(self.root.ids.message_box)
        self.load_messages(self.destination)

    def hide_message_box(self):  # hide the message box
        self.hide_widget(self.root.ids.message_box)

    def hide_widget(self, widget):  # helper method designed to hide widgets
        if not self.check_if_hidden(widget):
            wid = widget
            wid.saved_attrs = wid.height, wid.size_hint_y, wid.opacity, wid.disabled
            wid.height, wid.size_hint_y, wid.opacity, wid.disabled = 0, None, 0, True
            widget = wid
            if widget:
                pass

    def show_widget(self, widget):  # reverse of above
        wid = widget
        if self.check_if_hidden(widget):
            wid.height, wid.size_hint_y, wid.opacity, wid.disabled = wid.saved_attrs
            del wid.saved_attrs
            widget = wid
            if widget:
                pass

    """Static methods"""

    @staticmethod
    def check_if_hidden(widget):  # needed to check if widget was hidden
        try:
            widget.saved_attrs
        except AttributeError:
            return False
        else:
            return True

    def fail_connection(self):  # called when connection has failed
        for screen in self.root.screens:
            if screen.name == 'login':
                try:
                    screen.network_error
                except AttributeError:
                    error = ColoredLabel(color='red')
                    error.size_hint_y = 0.2
                    error.text = "Cannot connect!"
                    for i in screen.children[0].children:
                        i.disabled = True
                    screen.children[0].add_widget(error, len(screen.children[0].children))
                    screen.network_error = True
        self.root.current = 'login'

    def succeed_connection(self):  # called when connection succeeds, usually after a failed connection
        for screen in self.root.screens:
            if screen.name == 'login':
                try:
                    screen.network_error
                except AttributeError:
                    pass
                else:
                    if screen.network_error:
                        screen.network_error = False
                        screen.children[0].remove_widget(screen.children[0].children[
                                                             len(screen.children[0].children) - 1])
                        for i in screen.children[0].children:
                            i.disabled = False
        self.secure()
        self.root.current = 'login'


class Client(Protocol):  # defines the communications protocol
    def __init__(self):
        self.username = None
        self.destination = None
        self.buffer = b""

    def connectionMade(self):
        Logger.info("Established connection.")  # note: all queue mechanisms were removed once 1.3 rolled around
        application.succeed_connection()

    def dataReceived(self, data):  # called when a packet is received.
        print(f" -> {data}")  # uncomment this line to get the raw packet data
        data = data.decode().split('}')
        for packet in data:
            if packet:
                command = loads((packet + '}').encode())
                if command['command'] == 'secure':
                    application.secure_server(command)
                elif command['command'] == '200':
                    application.login_ok()
                elif command['command'] == '201':
                    application.signup_ok()
                elif command['command'] == 'friend_key':
                    application.got_friend_key(command)
                elif command['command'] == '406':
                    application.username_taken()
                elif command['command'] == '401':
                    application.login_failed()
                elif command['command'] == 'friend_request':
                    add_request(command)
                    application.root.ids.request_button.text = f"{len(get_requests(application.username))}\n"
                elif command['command'] == 'friend_accept':
                    application.accept_request_reply(command)
                elif command['command'] == 'message':
                    save_message(command, application.username)
                    f = FauxMessage()
                    f.isfile = command['isfile']
                    f.message_data = command['content']
                    f.sender = command['sender']
                    application.add_bubble_to_conversation(f, command['sender'])
                elif command['command'] == 'prepare_for_file':
                    threading.Thread(target=application.receiver_daemon, args=(command,)).start()
                elif command['command'] == 'call':
                    application.root.current = 'call_incoming'

                elif command['command'] == 'call_fail':
                    application.fail_call()

    def connectionLost(self, reason=connectionDone):  # called when the connection dies. RIP.
        Logger.info(reason.value)


class ClientFactory(Factory):  # handles connections and communications
    def __init__(self):
        self.client = None

    def buildProtocol(self, addr):
        c = Client()
        self.client = c
        return c

    def startedConnecting(self, connector):
        Logger.info('Application: Attempting to connect...')

    def clientConnectionFailed(self, connector, reason):
        Logger.error('Application: Connection failed!')
        application.fail_connection()
        connector.connect()

    def clientConnectionLost(self, connector, reason):
        Logger.info('Application: Disconnected.')
        connector.connect()


application = PenguChatApp()

if __name__ == '__main__':
    """ 
    THIS IS NECESSARY FOR PYINSTALLER BUILD ON WINDOWS. DO NOT UNCOMMENT UNLESS BUILDING.
    import os
    from kivy.resources import resource_add_path

     if hasattr(sys, '_MEIPASS'):
        resource_add_path(os.path.join(sys._MEIPASS))
     """

    globalLogPublisher.addObserver(analyze)
    application.run()
    ExceptionManager.add_handler(ExceptionWatchdog())
