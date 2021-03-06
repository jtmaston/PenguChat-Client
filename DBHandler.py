# Handles the database operations. SQLite is used.

from base64 import b64decode, b64encode
from datetime import datetime
from os import makedirs
from pickle import dumps as p_dumps
from pickle import loads as p_loads

from Crypto.Cipher import AES
from appdirs import user_data_dir
from peewee import *

path = user_data_dir("PenguChat")

db = SqliteDatabase(path + '/messages.db')


# the peewee framework was used to streamline database ops.

class CommonKeys(Model):  # describes the database. Common keys keeps the keys used in e2e between the
    added_by = CharField(100)  # clients
    partner_name = CharField(100)
    common_key = BlobField(null=True)
    key_updated = DateTimeField(null=True)

    class Meta:
        database = db


class PrivateKeys(Model):  # private keys used when sending friend requests
    added_by = CharField(100)
    partner_name = CharField(100)
    self_private_key = BlobField(null=True)

    class Meta:
        database = db


class Messages(Model):  # The messages. Kinda legacy code.
    added_by = CharField(100)
    sender = CharField(100)
    destination = CharField(100)
    message_data = BlobField()
    timestamp = DateTimeField()
    isfile = BooleanField()
    filename = TextField(default=None)

    class Meta:
        database = db


class Requests(Model):
    sender = CharField(100)
    public_key = BlobField()
    destination = CharField(100)

    class Meta:
        database = db


def add_common_key(partner_name, common_key, added_by):  # add a common key to the database
    def add():
        new_key = CommonKeys(
            partner_name=partner_name,
            common_key=common_key,
            key_updated=datetime.now(),
            added_by=added_by
        )
        new_key.save()
        start_message = {
            'sender': partner_name,
            'destination': added_by,
            'command': 'message',
            'content': chr(224),
            'timestamp': datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
            'isfile': False
        }
        save_message(start_message, added_by)
    try:
        query = CommonKeys.get(CommonKeys.partner_name == partner_name)
    except CommonKeys.DoesNotExist:
        add()
    else:
        query.partner_name = partner_name
        query.common_key = common_key
        query.added_by = added_by
        query.key_updated = datetime.now()

        # ok, this is exciting. This ??? handles re-encryption of all the messages after a key change
        try:
            old_key = get_common_key(partner_name, added_by)
        except DoesNotExist:
            add()
        messages = get_messages(partner_name, added_by, raw=True)
        for message in messages:
            cipher = AES.new(old_key, AES.MODE_SIV)
            if not message.isfile:
                try:
                    encrypted = p_loads(b64decode(message.message_data))
                except EOFError:
                    print(f"Message {message} is corrupted.")
                else:
                    try:
                        if message.sender == added_by:
                            message.message_data = cipher.decrypt_and_verify(encrypted[0], encrypted[1]).decode()
                            new_cipher = AES.new(str(common_key).encode(), AES.MODE_SIV)
                            message.message_data = b64encode(
                                p_dumps(new_cipher.encrypt_and_digest(message.message_data.encode())))
                            message.save()
                    except ValueError:
                        print("MAC error. Message is most likely corrupted.")

        query.save()


def get_common_key(partner_name, username):  # retrieve said common key
    try:
        query = CommonKeys.get(
            (CommonKeys.partner_name == partner_name) &
            (CommonKeys.added_by == username)
        )
    except CommonKeys.DoesNotExist:
        raise DoesNotExist
    else:
        return query.common_key


def add_private_key(partner_name, private_key, username):  # ditto above idk
    private_key = str(private_key).encode()
    try:
        key = PrivateKeys.get(PrivateKeys.partner_name == partner_name)
    except PrivateKeys.DoesNotExist:
        new_key = PrivateKeys(
            partner_name=partner_name,
            self_private_key=private_key,
            added_by=username
        )
        new_key.save()
    else:
        key.self_private_key = private_key
        key.added_by = username
        key.save()


def get_private_key(partner_name, username):
    try:
        key = PrivateKeys.get(
            (PrivateKeys.partner_name == partner_name) &
            (PrivateKeys.added_by == username)
        )
    except PrivateKeys.DoesNotExist:
        # Logger.error("DBHandler: Key not found for user!")
        pass
    else:
        return int(key.self_private_key.decode())


def delete_private_key(partner_name, username):
    PrivateKeys.get(
        (PrivateKeys.partner_name == partner_name) &
        (PrivateKeys.added_by == username)
    ).delete_instance()
    db.commit()


def get_friends(username):  # get the contacts list of a user
    query = Messages.select().where(
        (Messages.destination == username) |
        (Messages.sender == username)
    )
    return list(dict.fromkeys((
            [i.sender for i in query if i.sender != username] +
            [i.destination for i in query if i.destination != username]
    )))


def get_messages(partner, username, raw=False):  # get the messages of a user
    query = Messages.select().where(
        ((Messages.destination == partner) & (Messages.sender == username)) |
        ((Messages.sender == partner) & (Messages.destination == username)) &
        (Messages.added_by == username)
    ).order_by(Messages.timestamp)
    if raw:
        return query
    try:
        return [i for i in query if i.message_data.decode() != chr(224) and i.added_by == username]
    except AttributeError:
        return [i for i in query if i.message_data != chr(224) and i.added_by == username]


def save_message(packet, username, filename=None):  # save a message to the database. This handles both files and text
    try:
        message = packet['content'].encode()
    except AttributeError:
        message = packet['content']
    except KeyError:
        message = None

    try:
        packet['isfile']
    except KeyError:
        packet['isfile'] = False

    if message is None:
        message = b''

    Messages(
        sender=packet['sender'],
        destination=packet['destination'],
        message_data=message,
        timestamp=datetime.strptime(packet['timestamp'], "%m/%d/%Y, %H:%M:%S"),
        added_by=username,
        isfile=packet['isfile'],
        filename=filename if filename is not None else ""
    ).save()


def add_request(packet):  # add a request to the database. This handles the case
    try:  # where a user gets a second request, by ignoring the subsequent ones.
        Requests.get(Requests.sender == packet['sender'])
    except Requests.DoesNotExist:
        Requests(sender=packet['sender'],
                 public_key=str(packet['content']).encode(),
                 destination=packet['destination']).save()


def delete_request(username):  # called when a request was either accepted or rejected
    Requests.get(Requests.sender == username).delete_instance()
    db.commit()


def get_key_for_request(username, sender):
    try:
        key = Requests.get((Requests.sender == sender) & (Requests.destination == username))
        return key.public_key
    except Requests.DoesNotExist:
        return False


def get_requests(username):
    query = Requests.select(Requests.sender).where(Requests.destination == username)
    return list(dict.fromkeys([i.sender for i in query if i.sender]))


try:  # this runs first at first run of the client and sets up the appropriate files.
    db.create_tables([CommonKeys, Messages, PrivateKeys, Requests])
except OperationalError as t:
    # Logger.warning("DBHandler: Creating database file.")
    try:
        makedirs(path)
    except FileExistsError:
        pass
    try:
        open(path + '/messages.db', 'r')
    except FileNotFoundError:
        with open(path + '/messages.db', 'w+'):
            pass
    db.create_tables([CommonKeys, Messages, PrivateKeys, Requests])
