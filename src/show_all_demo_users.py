from kivy.storage.jsonstore import JsonStore

demo_user_names = ('Alice', 'Bob', 'Charlie', 'Mark', 'King', 'Wu', 'Paige')


def show_all_demo_users():
    """show all demo user keys"""
    try:
        store = JsonStore('../demo_users.json')
        for name in demo_user_names:
            print('User ' + name)
            print('Address:= ' + store.get(name)['address'])
            print(store.get(name)['rsa_prikey'])
            print(store.get(name)['rsa_pubkey'])
            print('ECC Private Key:= ' + store.get(name)['ecc_prikey'])
            print('ECC Public Key := ' + store.get(name)['ecc_pubkey'])
            print('AES Key:= ' + store.get(name)['aes_key'])
            print('AES IV := ' + store.get(name)['aes_iv'])
    except Exception as e:
        print(str(e))


show_all_demo_users()