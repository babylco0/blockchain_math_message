from kivy.storage.jsonstore import JsonStore

block_height = 0
store = JsonStore('./test.json')

for i in range(0, 10):
    store[block_height] = {'dat': i}
    block_height += 1

for i in range(0, 10):
    block_height -= 1
    print(store[block_height]['dat'])
