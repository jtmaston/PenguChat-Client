from multiprocessing import Queue

if __name__ == '__main__':  # While this *may* be considered ugly, spawning multiprocessing processes with kivy
    # stuff included creates an additional window. This should address that.
    import multiprocessing
    from os import environ, SEEK_END
    from os.path import basename
    from platform import platform
    from sys import modules
    from sys import stdout
    from DBHandler import *

    OS = platform()
    if OS[0:OS.find('-')] == 'Windows':  # use DirectX for Windows, prevents some issues when using RDP
        environ["KIVY_GL_BACKEND"] = "angle_sdl2"  # ( and is generally better for Win )

    environ['KIVY_NO_ENV_CONFIG'] = '1'
    environ["KCFG_KIVY_LOG_LEVEL"] = "debug"
    environ["KCFG_KIVY_LOG_DIR"] = path + '/PenguChat/Logs'

    from kivy.config import Config  # must resize before importing window

    Config.set('graphics', 'width', f'{500}')
    Config.set('graphics', 'height', f'{750}')

    from kivy.core.window import Window as KVWindow
    from kivy.uix.screenmanager import FadeTransition
    from kivy.core.audio import SoundLoader
    from kivymd.app import MDApp
    from kivy.clock import Clock
    from kivy.support import install_twisted_reactor
    from UIElements import *

    Clock.max_iteration = 20
    if 'twisted.internet.reactor' in modules:
        del modules['twisted.internet.reactor']
    install_twisted_reactor()  # integrate twisted with kivy

    from tkinter import filedialog, Tk

    tkWindow = Tk()  # create a tkinter window, this is used for the native file dialogs
    tkWindow.withdraw()  # hide it for now

    from appdirs import user_data_dir

    data_directory = user_data_dir("PenguChat")

    from pickle import dumps as p_dumps
    from base64 import b64encode
    from json import dumps, loads
    from pyDH import DiffieHellman

    from twisted.internet import reactor
    from twisted.internet.protocol import Protocol, connectionDone
    from twisted.internet.protocol import ClientFactory as Factory
    from twisted.python.log import startLogging
    from socket import socket, AF_INET, SOCK_STREAM
    from daemons import sender_daemon, receiver_daemon, voip_listener_daemon, server_address

    startLogging(stdout)

    running = True


    class PenguChatApp(MDApp):  # this is the main KV app
        """App loading section"""

        def __init__(self, reloading=False):  # set the window params, as well as init some parameters
            if not reloading:  # When logging out, everything is reinitialized, except for the kivy stuff
                super(PenguChatApp, self).__init__()

            self.factory = None  # Governs the communications protocols
            self.calling = False  # This may be implemented in the future, for VoIP.

            self.window_size = (
                int(8 / 10 * tkWindow.winfo_screenwidth()),
                int(8 / 10 * tkWindow.winfo_screenheight())
            )
            self.chatroom_pos = (
                int((tkWindow.winfo_screenwidth() - self.window_size[0]) / 2),
                int((tkWindow.winfo_screenheight() - self.window_size[1]) / 2)
            )
            self.username = None  # Username of the client
            self.destination = None  # His conversation partner ( changes based on tab )
            self.__private = None  # His private key, used for Diffie-Hellman
            self.__server_key = None  # Common key for the E2E tunnel with the server
            self.sidebar_rows = dict()  # The buttons on the sidebar, mapped to their functions live here
            self.message_bubbles = []  # The message bubbles present in the chatroom
            self.contact_names = []  # Names of the contacts
            self.pwd = None  # Password used to login and / or signup. Del'd when server validates it
            self.sound_manager = None  # Used for VoIP, currently not implemented beyond a stub
            self.done_typing = False  # For the typing watchdog. Enables shift + enter in the message box
            self.daemons = []  # Holds the sender / receiver daemons
            self.wd_queue = Queue()  # Used to communicate with above daemons
            self.watchdog = Clock.schedule_interval(self.file_watchdog, 0.1)

        def build(self):
            super(PenguChatApp, self).build()
            self.root.current = 'loading_screen'  # move to the loading screen
            self.factory = ClientFactory()  # start accepting and making connections
            self.icon = 'Assets/logo-small.png'  # logo, for the top bar

            KVWindow.bind(on_key_down=self.check_for_shift_enter)  # start the keyboard checkers
            KVWindow.bind(on_key_up=self.clean_up_message_box)

            reactor.connectTCP(server_address, 8123, self.factory)  # connect to the server

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

        """Methods that send data"""

        def send_text(self):  # this method is used exclusively for text transmission
            if self.destination is None or self.destination == "":
                return
            message_text = self.root.ids.message_content.text
            self.root.ids.message_content.text = ""  # clear the message box's contents
            cipher = AES.new(get_common_key(self.destination, self.username), AES.MODE_SIV)  # get a cypher
            content = p_dumps(cipher.encrypt_and_digest(message_text.encode()))  # encrypt, then serialize
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
            f = FauxMessage()  # this is a quick hack to get message bubbles to display, without
            f.isfile = packet['isfile']  # reloading the whole messaging box. FauxMessage is a stub of the
            f.message_data = packet['content']  # database representation of messages.
            f.sender = packet['sender']

            self.add_bubble_to_conversation(f, self.destination)
            self.factory.client.transport.write((dumps(packet) + '\r\n').encode())
            self.root.ids.message_content.height = '40dp'
            # print(f" <- {dumps(packet).encode()}")

        def send_file(self):
            if self.destination is None or self.destination == "":
                return
            file = filedialog.askopenfile(mode="rb")  # the file sender. This opens a port, tells the server to
            tkWindow.update()  # connect to it,t hen serves a file to it.
            self.hide_tk()

            if file:
                # Get file size, to make sure we *can* load it to RAM | Note: though initially designed for, this
                file.seek(0, SEEK_END)  # mechanism was brutally implemented. Restricts file size to 1gb,
                file_size = file.tell()  # because after encryption 1gb files become ≈ 1.5-1.7gb in size
                file.seek(0, 0)
                if file_size > 1 * 10 ** 9:
                    return
                # Encrypt the file, alongside its name. Neither of them are accessible to the server, which handles
                # them by encrypted filename.
                filename = basename(file.name)

                cipher = AES.new(get_common_key(self.destination, self.username), AES.MODE_SIV)
                out_filename = p_dumps(cipher.encrypt_and_digest(filename.encode())) + '\r\n'.encode()
                out_filename = b64encode(out_filename).decode()
                file.close()
                sock = socket()
                sock.bind(("0.0.0.0", 0))  # open a socket on first available port
                sock.listen()

                packet = {  # metadata, gives the server info about where to connect and file stats
                    'sender': self.username,
                    'destination': self.destination,
                    'command': 'prepare_for_file',
                    'timestamp': datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
                    'file_size': file_size,
                    'filename': out_filename,
                    'port': sock.getsockname()[1]
                }

                # In order to run efficiently, the daemon runs on another thread ( if available ). Process is used
                # to avoid the all-mighty GIL from interfering.
                p = multiprocessing.Process(target=sender_daemon,
                                            args=(
                                                file.name, self.wd_queue, self.destination, self.username, sock,
                                                packet))
                self.daemons.append(p)
                p.start()

                self.factory.client.transport.write((dumps(packet) + '\r\n').encode())

        """Auth methods"""

        def send_login_data(self):

            if self.pwd is None or self.pwd == "":  # used when method called after signing up
                self.pwd = self.root.ids.loginPass.text.strip()  # get username and password from the UI element
            if self.username is None or self.username == "":
                self.username = self.root.ids.loginUsr.text.strip()
            try:  # this block is necessary to make sure that an E2E tunnel exists to the server
                cipher = AES.new(str(self.__server_key).encode(), AES.MODE_SIV)
            except AttributeError:  # if not, connection should be reset in order to get one
                self.factory.client.transport.loseConnection()
                self.fail_connection()
                return False
            encrypted, tag = cipher.encrypt_and_digest(self.pwd.encode())  # this generates a digest file from the pass
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
            # because of how twisted works, data sent to the server *has* to be serialized, thus b64 is used.

        def send_sign_up_data(self):  # see above method, it's that but with extra steps
            pwd = self.root.ids.passwd.text.strip()  # get the details from the UI element
            pwd_r = self.root.ids.passwd_r.text.strip()

            if pwd == pwd_r:  # check if passwords match
                self.username = self.root.ids.username.text.strip()
                self.pwd = pwd
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

        def new_chat(self):  # called when sending a chat request

            def send_chat_request(partner):  # save the private key to be used later
                packet = {
                    'sender': self.username,
                    'command': 'friend_request',
                    'content': self.__private.gen_public_key(),
                    'destination': partner,
                    'timestamp': datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
                    'isfile': False
                }
                self.factory.client.transport.write((dumps(packet) + '\r\n').encode())
                # print(f" <- {dumps(packet).encode()}")
                add_private_key(partner, self.__private.get_private_key(), self.username)
                popup.dismiss()

            popup = FriendPopup()  # this is the popup that allows the user to select his chat partner
            popup.callback = send_chat_request
            popup.open()

        def accept_request(self, button_object):  # called when accepting the request
            friend = button_object.parent.parent.username  # kivy is weird like this, and I couldn't find an easier way
            friend_key = int(get_key_for_request(self.username, friend).decode())
            common_key = self.__private.gen_shared_key(friend_key)
            packet = {
                'sender': self.username,
                'command': 'friend_accept',
                'content': self.__private.gen_public_key(),
                'destination': friend,
                'timestamp': datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
                'isfile': False
            }

            add_common_key(friend, common_key, self.username)  # add the common key to the database

            self.root.ids.sidebar.remove_widget(button_object.parent)  # remove the request entry in the sidebar
            delete_request(friend)  # also delete the request from the db

            del self.sidebar_rows[friend]
            self.set_sidebar_to_friend_list()
            self.factory.client.transport.write((dumps(packet) + '\r\n').encode())  # send the acknowledgement
            # print(f" <- {dumps(packet).encode()}")

        def logout(self):
            self.stop()
            self.factory.client.transport.loseConnection()
            self.root.current = 'loading_screen'
            self.factory.stopFactory()
            self.watchdog.cancel()
            # self.init_chat_room()  # called to clear the chat room, in anticipation of a new one being loaded
            self.__init__(reloading=True)
            self.build()

        def secure_server(self, command):  # part of the initial E2E, sets the common key with the server
            self.__server_key = self.__private.gen_shared_key(command['content'])
            self.root.current = 'login'

        def got_friend_key(self, command):  # called when a common key is established with a partner, after the req.
            add_common_key(command['friend'],
                           self.__private.gen_shared_key(command['content']),
                           self.username)

        def accept_request_reply(self, packet):  # called when the peer has accepted the chat request
            private = DiffieHellman()
            private._DiffieHellman__a = get_private_key(packet['sender'], self.username)
            common = private.gen_shared_key(int(packet['content']))
            add_common_key(packet['sender'], common, self.username)
            delete_private_key(packet['sender'], self.username)
            self.set_sidebar_to_friend_list()

        def deny_request(self, button_object):  # called when denying the request
            self.root.ids.sidebar.remove_widget(button_object)
            del self.sidebar_rows[button_object.parent.parent.username]
            delete_request(button_object.parent.parent.username)
            self.set_sidebar_to_request_list()

        """Helper methods"""

        def clean_up_message_box(self, *args):  # This cleans the message box of any \n's that remain
            key = args[2]
            if self.root.ids.message_content.focus and key == 40 and self.done_typing:  # if the message box is focused,
                self.root.ids.message_content.text = ""  # the enter key is released and
                self.done_typing = False  # user has finished typing

        def check_for_shift_enter(self, *args):  # This checks for shift+enter
            key = args[2]
            modifier_list = args[4]
            if self.root.ids.message_content.focus and key == 40 and not ('shift' in modifier_list):
                if self.root.ids.message_content.text.strip() != '':  # if the message box is focused, shift not
                    self.send_text()  # pressed and enter pressed
                    self.done_typing = True
                else:
                    self.root.ids.message_content.text = ""

        def stop(self, *args):  # called when stopping the app, this makes sure no daemons remain hanging
            global running
            print("asking to stop")
            for process in self.daemons:
                process.kill()

            return True

        def toggle_error(self, screen_name=None, error_text=None):  # experimental way of toggling errors on different
            for screen in self.root.screens:  # screens. *experimental*, and ugly. Too bad!
                if screen.name == screen_name:
                    try:
                        screen.has_error
                    except AttributeError:
                        if error_text is not None:
                            print('adding error')
                            screen.has_error = True
                            error = ColoredLabel(color='red')
                            error.size_hint_y = 0.2

                            error.text = error_text
                            screen.children[0].add_widget(error, len(screen.children[0].children))
                            screen.has_error = True
                    else:
                        if screen.has_error:
                            screen.has_error = False
                            screen.children[0].remove_widget(screen.children[0].children[
                                                                 len(screen.children[0].children) - 1])

        def file_watchdog(self, *args, **kwargs):  # watches to see if files have arrived or departed, to add
            while not self.wd_queue.empty():  # the corresponding bubbles to the conversation
                message = self.wd_queue.get()
                self.load_messages(message['destination'])

        def add_bubble_to_conversation(self, message, partner):  # add the message bubble
            cipher = AES.new(get_common_key(partner, self.username), AES.MODE_SIV)
            if not message.isfile:  # files and text are treated differently, because their bubbles are different.
                try:
                    encrypted = p_loads(b64decode(message.message_data))
                except EOFError:
                    Logger.error(f"Application: Message {message.id} is corrupted")  # handle some corruption.
                    message.message_data = "[Message appears corrupted.]"  # Thankfully haven't used this much
                else:
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
                filename = message.message_data.decode()
                truncated = {  # this holds the file metadata, used when rendering the file bubble
                    'sender': message.sender,
                    'destination': message.destination,
                    'timestamp': message.timestamp,
                    'file_path': message.filename
                }
                if message.sender == self.username:  # see UIElements for explanation of the magic below.
                    e = ConversationElement(side='r', isfile=True, filename=filename, truncated=truncated)
                else:
                    e = ConversationElement(side='l', isfile=True, filename=filename, truncated=truncated)

            self.root.ids.conversation.rows += 1
            self.root.ids.conversation.add_widget(e.line)
            self.message_bubbles.append(e)

            height = 0
            for child in self.root.ids.conversation_scroll.children[0].children:
                height += child.height

            if height > self.root.ids.conversation_scroll.height:  # if the box has overflown and data is outside the
                try:  # viewport, scroll down to see it.
                    self.root.ids.conversation_scroll.scroll_to(self.message_bubbles[-1].right)
                except IndexError:
                    pass

            Clock.schedule_once(e.reload, 0.1)  # addresses the bug where the long messages do not display properly

        """Loading methods"""

        def init_chat_room(self):  # called upon first entering the chatroom, to init it. Hide the message box until
            self.root.ids.message_content.hidden = True  # a conversation is started
            self.set_sidebar_to_request_list()  # shuffles the sidebar to get everything loaded in.
            self.set_sidebar_to_friend_list()
            self.root.ids.conversation.clear_widgets()

        def set_sidebar_to_friend_list(self):  # set sidebar to the friends list
            self.root.ids.requests_button.text = f"Requests [ {len(get_requests(self.username))} ]"  # dynamically gen
            self.root.ids.sidebar.clear_widgets()  # clear all items in the sidebar                 # sidebar text
            self.root.ids.conversation_button.color = get_color_from_hex("ff9f1e")  # this swaps colors, to indicate
            self.root.ids.requests_button.color = get_color_from_hex("e4e5e9")  # which tab is active
            self.root.ids.requests_button.font_name = 'Assets/Segoe UI'
            self.root.ids.conversation_button.font_name = 'Assets/Segoe UI Bold'
            self.root.ids.sidebar.rows = 0

            names = get_friends(self.username)  # call the database to see who the prev conversations were

            for i in names:  # create a new button for every friend
                a = ContactName()  # ~TODO: this part is ugly and sucks. Too bad!~
                a.text = i  # Could be done automagically, but for now manual is the way to go. We have too many
                a.font_name = 'Assets/Segoe UI'  # classes as is.
                a.size_hint = (1, 1)
                a.font_size = '25dp'
                a.halign = 'center'
                a.valign = 'center'
                if i == self.destination:
                    a.color = get_color_from_hex("ff9f1e")  # color of the message changes based on who's sending it
                else:
                    a.color = get_color_from_hex("5f6c74")

                a.bind(on_press=self.show_message_box)
                self.root.ids.sidebar.rows += 1
                self.root.ids.sidebar.add_widget(a)

                self.contact_names.append(a)

        def set_sidebar_to_request_list(self):  # pretty much ditto set_sidebar_to_friend_list, see above

            self.root.ids.sidebar.clear_widgets()
            self.root.ids.sidebar.rows = 0
            self.root.ids.conversation_button.color = get_color_from_hex("e4e5e9")
            self.root.ids.requests_button.color = get_color_from_hex("ff9f1e")
            self.root.ids.conversation_button.font_name = 'Assets/Segoe UI'
            self.root.ids.requests_button.font_name = 'Assets/Segoe UI Bold'

            requests = get_requests(self.username)  # fixed
            self.root.ids.requests_button.text = f"Requests [ {len(requests)} ]"
            for i in requests:
                e = SidebarElement(i)
                e.accept.bind(on_press=self.accept_request)
                e.decline.bind(on_press=self.deny_request)
                self.sidebar_rows[i] = e
                self.root.ids.sidebar.rows += 1
                self.root.ids.sidebar.add_widget(e.container)
                self.root.ids.requests_button.canvas.ask_update()

        def load_messages(self, partner):  # method to load all the messages
            if len(self.message_bubbles) > 0:  # clear the conversation
                self.root.ids.conversation.clear_widgets()
                self.root.ids.conversation.rows = 0
                self.message_bubbles.clear()
            self.root.ids.message_content.hidden = False
            self.root.ids.message_content.height = '40dp'
            self.root.ids.right_bar.width = '50dp'
            self.root.ids.ppclip.text_color = get_color_from_hex("1e1f1f")  # yes. the id's names are horrible. sry.
            self.root.ids.snd.text_color = get_color_from_hex("1e1f1f")

            messages = get_messages(partner, self.username)  # call the database to get the messages
            for i in messages:  # decrypt every message and then display it
                self.add_bubble_to_conversation(i, partner)

        """VoIP stuff"""

        def call(self, already_in_call):  # this is experimental stuff for VoIP. Too bad I couldn't finish
            self.root.current = 'calling'  # in time.
            self.calling = True
            if not already_in_call:
                self.sound_manager = SoundLoader.load('Assets/dial_tone.wav')  # play a dial tone
                self.sound_manager.loop = True
                self.sound_manager.play()

            sock = socket(AF_INET, SOCK_STREAM)  # and open a socket for the other client to connect to. Yes! It's P2P!
            sock.bind(("0.0.0.0", 0))  # maybe if I don't sleep I'll manage to get this running.

            packet = {  # server is used as a nameserver, to tell the clients how to connect to
                'sender': self.username,  # each other.
                'command': 'call',
                'destination': self.destination,
                'timestamp': datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
                'isfile': False,
                'address': sock.getsockname()[0],
                'port': sock.getsockname()[1]
            }
            p = multiprocessing.Process(target=voip_listener_daemon, args=(sock, self,))
            self.daemons.append(p)
            p.start()
            self.factory.client.transport.write((dumps(packet) + '\r\n').encode())  # send the acknowledgement

        def end_call(self):  # called when a call ends.
            try:
                self.sound_manager.stop()
            except AttributeError:
                pass

            self.calling = False
            self.root.current = 'chat_room'

        def fail_call(self):  # called when the person on the other end isn't connected.
            self.sound_manager.loop = False
            self.sound_manager.stop()
            self.calling = False
            self.sound_manager = SoundLoader.load("Assets/busy_trimmed.wav")
            self.sound_manager.play()
            self.root.current = 'call_failed'
            Clock.usleep(20000)  # wait for the busy tone to end.
            self.root.current = 'chat_room'

        def accept_call(self):  # stub
            self.root.current = 'calling'
            self.call(already_in_call=True)

        """Widget methods"""

        def show_message_box(self, button_object):  # called when selecting a contact from the sidebar,
            self.destination = button_object.text  # loads the data for it.
            self.set_sidebar_to_friend_list()
            self.load_messages(self.destination)

        """Static methods"""

        @staticmethod
        def hide_tk(*args, **kwargs):  # hides the tk window. tk is used to drive the file dialogs
            tkWindow.withdraw()

        """Errors"""

        def username_taken(self):  # called when the username requested has already been taken
            self.toggle_error('signup', 'Username is taken, sorry!')
            self.root.current = 'signup'

        def login_failed(self):  # called when username or password isn't right
            self.toggle_error(screen_name='login', error_text="Username or password incorrect!")
            self.username = ""
            self.pwd = ""
            self.root.current = 'login'

        def fail_connection(self):  # called when connection has failed
            self.toggle_error('login', 'Cannot connect!')
            self.root.current = 'login'

        def succeed_connection(self):  # called when connection succeeds, usually after a failed connection
            self.toggle_error('login')
            self.secure()
            self.root.current = 'login'

        def login_ok(self):  # called when login succeeds, changes to the chatroom screen
            self.pwd = None  # Forget the password, please
            self.root.current = 'chat_room'
            self.toggle_error('login')

        def signup_ok(self):  # ditto above, only for signup
            self.root.ids.username.error = False
            self.root.ids.passwd.error = False
            self.root.ids.passwd_r.error = False
            application.send_login_data()


    class Client(Protocol):  # defines the communications protocol
        def __init__(self):
            self.username = None
            self.destination = None

        def connectionMade(self):
            Logger.info("Established connection.")
            application.succeed_connection()

        def dataReceived(self, data):  # called when a packet is received.
            print(f" -> {data}")  # uncomment this line to get the raw packet data
            data = data.decode().split('}')  # because of how twisted works, packets come in one giant string, they must
            for packet in data:  # therefore be split for processing
                if packet:
                    command = loads((packet + '}').encode())  # ahh, pickle. passing unchecked input is usually
                    if command['command'] == 'secure':  # a bad idea. Too bad!
                        application.secure_server(command)
                    elif command['command'] == '200':  # sometimes the server speaks in HTML codes.
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
                        application.root.ids.requests_button.text = \
                            f"Requests [ {len(get_requests(application.username))} ]"
                    elif command['command'] == 'friend_accept':
                        application.accept_request_reply(command)
                    elif command['command'] == 'message':
                        save_message(command, application.username)
                        f = FauxMessage()  # our friend, FauxMessage strikes again
                        f.isfile = command['isfile']
                        f.message_data = command['content']
                        f.sender = command['sender']
                        application.add_bubble_to_conversation(f, command['sender'])
                    elif command['command'] == 'prepare_for_file':
                        p = multiprocessing.Process(target=receiver_daemon, args=(command, application.wd_queue,))
                        application.daemons.append(p)
                        p.start()
                    elif command['command'] == 'call':
                        application.root.current = 'call_incoming'
                    elif command['command'] == 'call_fail':
                        application.fail_call()
                    elif command['command'] == 'file_done':
                        print(f"Transfer rate is {command['speed']}")

        def connectionLost(self, reason=connectionDone):
            Logger.info(reason.value)


    class ClientFactory(Factory):  # is used to handle the protocols. Mostly useful when running multiple connections,
        def __init__(self):  # so a bit overkill, but the functionality is a welcome addition.
            self.client = None

        def buildProtocol(self, addr):  # these explain themselves. How nice. ↓
            c = Client()
            self.client = c
            return c

        def startedConnecting(self, connector):
            Logger.info('Application: Attempting to connect...')

        def clientConnectionFailed(self, connector, reason):
            Logger.error('Application: Connection failed!')
            application.fail_connection()
            connector.connect()

        def clientConnectionLost(self, connector, reason):  # ↑
            Logger.info('Application: Disconnected.')
            connector.connect()


    application = PenguChatApp()
    multiprocessing.freeze_support()  # Used to prevent multiprocessing from spawning more kivy
    application.run()  # windows under PyInstaller
    ExceptionManager.add_handler(ExceptionWatchdog())  # this is legacy code. It might do something, it might not.

if __name__ == '__main__':
    """ 
    THIS IS NECESSARY FOR PYINSTALLER BUILD ON WINDOWS. DO NOT UNCOMMENT UNLESS BUILDING.
    import os
    from kivy.resources import resource_add_path

     if hasattr(sys, '_MEIPASS'):
        resource_add_path(os.path.join(sys._MEIPASS))
     """
