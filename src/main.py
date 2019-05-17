import time

from kivy.app import App
from kivy.base import Builder
from kivy.core.window import Window
from kivy.properties import StringProperty
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.label import Label
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.gridlayout import GridLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.textinput import TextInput
from kivy.uix.tabbedpanel import TabbedPanel
from kivy.network.urlrequest import UrlRequest
from kivy.storage.jsonstore import JsonStore
from urllib import parse
import json
from Crypto.Hash import SHA256, RIPEMD
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto import Random
import binascii
import base64
from kivy.utils import platform
from util import *
from secp256k1 import PrivateKey, PublicKey

demo_user_names = ('Alice', 'Bob', 'Charlie', 'Mark', 'King', 'Wu', 'Paige')
Builder.load_file('main.kv')  # load *.kv file
default_path = './demo_users.json'
message_path = './messages.json'


class DemoUserSelScreen(Screen):
    """select demo user screen"""
    pass


class UserCardScreen(Screen):
    """user card screen"""
    user_name = StringProperty()
    default_size = 36

    @staticmethod
    def show_contact_screen():
        """show contact screen"""
        contact_screen.on_show()
        sm.direction = 'left'
        sm.current = 'screen3'

    def on_show(self):
        """update user card"""
        self.ids['l_user_name'].text = self.user_name
        try:
            store = JsonStore(default_path)
            self.ids['ti_address'].text = store.get(self.user_name)['address']
            self.ids['ti_rsa_prikey'].text = store.get(self.user_name)['rsa_prikey']
            self.ids['ti_pubkey'].text = store.get(self.user_name)['rsa_pubkey']
            self.ids['ti_ecc_prikey'].text = store.get(self.user_name)['ecc_prikey']
            self.ids['ti_ecc_pubkey'].text = store.get(self.user_name)['ecc_pubkey']
            self.ids['ti_aes_key'].text = store.get(self.user_name)['aes_key']
            self.ids['ti_aes_iv'].text = store.get(self.user_name)['aes_iv']
        except Exception as e:
            print(str(e))


class DemoUserSelView(ScrollView):
    """demo user select view"""

    def __init__(self, **kwargs):
        super(DemoUserSelView, self).__init__(**kwargs)
        layout = GridLayout(cols=1, spacing=10, size_hint_y=None, height=1024)
        layout.bind(minimum_height=layout.setter('height'))
        for name in demo_user_names:
            c = Button(text=name, size_hint_y=None, height=160)
            c.bind(on_press=self.on_clicked_sel_button)
            layout.add_widget(c)
        c = Button(text="...", size_hint_y=None, height=160)
        c.bind(on_press=self.on_clicked_sel_button)
        layout.add_widget(c)
        self.size_hint = (1, 1)
        self.add_widget(layout)

    @staticmethod
    def on_clicked_sel_button(sender):
        """select demo user"""
        user_name = sender.text
        if user_name == '...':  # create new user
            pass
        elif user_name in demo_user_names:
            user_card_screen.user_name = user_name
            user_card_screen.on_show()
            sm.direction = 'left'
            sm.current = 'screen2'


class ContactScreen(Screen):
    """contact screen"""

    def on_show(self):
        """setting contact"""
        self.ids['sv_contact'].show_all_contacts()


class ContactLayout(BoxLayout):
    """contact layout"""
    default_size = 24
    name = StringProperty()
    address = StringProperty()
    pubkey = StringProperty()

    def __init__(self, uname=None, uaddress=None, upubkey=None, **kwargs):
        super(ContactLayout, self).__init__(**kwargs)
        self.name = uname
        self.address = uaddress
        self.pubkey = upubkey

    def show_send_message_box(self):
        """show message send box"""
        send_message_screen.contact_name = self.name
        sm.transition.direction = 'left'
        sm.current = 'screen4'


class ContactView(ScrollView):
    """contact view"""

    def __init__(self, **kwargs):
        super(ContactView, self).__init__(**kwargs)

    def show_all_contacts(self):
        """show all contacts"""
        layout = GridLayout(cols=1, spacing=10, size_hint_y=None)
        layout.bind(minimum_height=layout.setter('height'))
        my_name = user_card_screen.user_name
        self.clear_widgets()
        for name in demo_user_names:
            if name == my_name:
                continue
            try:
                store = JsonStore(default_path)
                c = ContactLayout(uname=name,
                                  uaddress=store.get(name)['address'],
                                  upubkey=store.get(name)['rsa_pubkey'])
                layout.add_widget(c)
            except Exception as e:
                print(str(e))
        self.size_hint = (1, 1)
        self.add_widget(layout)


class SendMessageBoxScreen(Screen):
    """message send box screen"""
    contact_name = StringProperty()
    contact_address = StringProperty()
    contact_pubkey = StringProperty()
    msg_height = 0

    def send_message(self):
        """send message"""
        if self.ids['ti_message'].text is None:
            return
        else:
            msg = create_message(user_card_screen.user_name, self.contact_name, self.ids['ti_message'].text)
            self.msg_height += msg.height
            self.ids['msg_list'].height = max(self.msg_height, self.height / 5 * 4)
            self.ids['msg_list'].add_widget(msg)
            try:
                store = JsonStore(message_path)
                if not store.exists(msg.hash()):
                    if not store.exists('TOP'):
                        store.put(msg.hash(), message=msg.serialize(), next='0')
                        store.put('TOP', hash=msg.hash())
                    else:
                        top_hash = store.get('TOP')['hash']
                        store.put(msg.hash(), message=msg.serialize(), next=top_hash)
                        store.put('TOP', hash=msg.hash())
            except Exception as e:
                print(str(e))


def create_message(sender, receiver, content):
    """create message"""""
    try:
        store = JsonStore(default_path)
        sender_address = store.get(sender)['address']
        sender_ecc_prikey = store.get(sender)['ecc_prikey']
        sender_ecc_pubkey = store.get(sender)['ecc_pubkey']
        receiver_address = store.get(receiver)['address']
        receiver_rsa_pubkey = store.get(sender)['rsa_prikey']
        # use receiver's rsa pubkey encrypt content
        key = RSA.importKey(receiver_rsa_pubkey)
        cipher = PKCS1_v1_5.new(key)
        encrypt = cipher.encrypt(content.encode('utf-8'))
        encrypted_content = binascii.hexlify(encrypt).decode('utf-8')
        # sign message use sender's ecc prikey
        ecc_prikey = PrivateKey(bytes(bytearray.fromhex(sender_ecc_prikey)))
        sign = ecc_prikey.ecdsa_sign(encrypt)
        msg_sing = binascii.hexlify(ecc_prikey.ecdsa_serialize(sign)).decode('utf-8')
        return MessageLayout(sender=sender_address,
                             receiver=receiver_address,
                             content=encrypted_content,
                             sign=msg_sing,
                             pubkey=sender_ecc_pubkey,
                             t=str(time.asctime(time.localtime(time.time()))))
    except Exception as e:
        print(str(e))


class MessageLayout(BoxLayout):
    """message layout"""
    default_size = 32
    m_sender = StringProperty()
    m_receiver = StringProperty()
    m_time = StringProperty()
    m_content = StringProperty()
    m_sign = StringProperty()
    m_pubkey = StringProperty()

    def __init__(self, sender=None, receiver=None, content=None, t=None, sign=None, pubkey=None, **kwargs):
        super(MessageLayout, self).__init__(**kwargs)
        self.m_sender = sender
        self.m_receiver = receiver
        self.m_time = t
        self.m_content = content
        self.m_sign = sign
        self.m_pubkey = pubkey

    def serialize(self):
        """serialize message"""
        data = [{'sender': self.m_sender,
                 'receiver': self.m_receiver,
                 'content': self.m_content,
                 'sign': self.m_sign,
                 'pubkey': self.m_pubkey,
                 'time': self.m_time}]
        return json.dumps(data)

    def hash(self):
        return hash256(self.m_content.encode('utf-8'))


class MessageShow(TextInput):
    """message show"""

    def __init__(self, txt=None, **kwargs):
        super(MessageShow, self).__init__(*kwargs)
        self.font_size = 48
        self.text = txt
        self.height = self.minimum_height
        self.size_hint = (1, None)


sm = ScreenManager()  # screen manager
demo_user_sel_screen = DemoUserSelScreen(name='screen1')
user_card_screen = UserCardScreen(name='screen2')
contact_screen = ContactScreen(name='screen3')
send_message_screen = SendMessageBoxScreen(name='screen4')
sm.add_widget(demo_user_sel_screen)
sm.add_widget(user_card_screen)
sm.add_widget(contact_screen)
sm.add_widget(send_message_screen)
sm.current = 'screen1'


class MyApp(App):
    """My application"""

    def build(self):
        self.title = 'MathMessage'
        return sm


if __name__ == '__main__':
    MyApp().run()
