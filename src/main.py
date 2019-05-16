from kivy.app import App
from kivy.base import Builder
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.gridlayout import GridLayout
from kivy.uix.scrollview import ScrollView
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


demo_user_names = ('Alice', 'Bob', 'Charlie', 'Mark', 'King', 'Wu', 'Paige')
Builder.load_file('main.kv')  # load *.kv file
default_path = './demo_users.json'


class DemoUserSelScreen(Screen):
    """select demo user screen"""
    pass


class UserCardScreen(Screen):
    """user card screen"""
    user_name = '***'

    def pre_screen(self):
        """show pre screen"""
        sm.current = 'screen1'

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


sm = ScreenManager()  # screen manager
demo_user_sel_screen = DemoUserSelScreen(name='screen1')
user_card_screen = UserCardScreen(name='screen2')
sm.add_widget(demo_user_sel_screen)
sm.add_widget(user_card_screen)
sm.current = 'screen1'


class MyApp(App):
    """My application"""

    def build(self):
        return sm


if __name__ == '__main__':
    MyApp().run()




