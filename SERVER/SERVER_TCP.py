from Crypto.Util.number import long_to_bytes
import socket
import threading
import pickle
import time
import sqlite3
import os
import json

from CryptoCore.DH import DHEndpoint
from CryptoCore.DS import DSGOST
from CryptoCore.BC import BlockCipher


class Server:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.online_clients = dict()
        self.pub_keys = dict()
        self.priv_keys = dict()
        self.ctr = 0

        self.BLOCK_SIZE = 4096

        self.ds = DSGOST(p=57896044618658097711785492504343953926634992332820282019728792003956564821041,
                         a=7,
                         b=43308876546767276905765904595650931995942111794451039583252968842033849580414,
                         q=57896044618658097711785492504343953927082934583725450622380973592137631069619,
                         p_x=2,
                         p_y=4018974056539037503335449422937059775635739389905545080690979365213431566280)

        self.d, self.q_point = self.ds.gen_keys()

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.ip, self.port))
        self.server.listen(0)
        threading.Thread(target=self.connect_handler).start()

        con = sqlite3.connect('AppData\\backup.db')
        cursor = con.cursor()
        create_table = f'CREATE TABLE IF NOT EXISTS messages(' \
                       'id INTEGER PRIMARY KEY AUTOINCREMENT,' \
                       'destination_id INT, ' \
                       'source_id INT, ' \
                       'text VARCHAR(256))'
        cursor.execute(create_table)
        con.commit()
        con.close()

        con = sqlite3.connect('AppData/members.db')
        cursor = con.cursor()
        create_table = f'CREATE TABLE IF NOT EXISTS users(' \
                       'id INTEGER PRIMARY KEY,' \
                       'name VARCHAR(256))'
        cursor.execute(create_table)
        con.commit()
        con.close()

        self.update_configs()

        print('Сервер запущен!')

    def update_configs(self):
        if os.path.exists(os.path.join("AppData", "config.json")):
            with open(os.path.join("AppData", "config.json")) as file:
                data = json.load(file)
                self.ctr = data['ctr']

    def set_config(self):
        with open(os.path.join("AppData", "config.json"), 'w') as file:
            payload = {
                'ctr': self.ctr
            }
            data = json.dumps(payload)
            file.write(data)

    def connect_handler(self):
        while True:
            client, address = self.server.accept()
            recv = pickle.loads(client.recv(self.BLOCK_SIZE))
            if recv['type'] == 'SET_NEW_USER':
                con = sqlite3.connect('AppData/members.db')
                cursor = con.cursor()
                cursor.execute(f'SELECT * FROM users WHERE id = {self.ctr}')
                res = cursor.fetchall()
                while res:
                    self.ctr += 1
                    cursor.execute(f'SELECT * FROM users WHERE id = {self.ctr}')
                    res = cursor.fetchall()
                con.close()
                self.ctr += 1
                self.set_config()
                if client not in self.online_clients:
                    self.online_clients[client] = {
                        'id': self.ctr,
                        'name': None,
                        'pub': None,
                        'master': None
                    }
                    dh = DHEndpoint()
                    print(f'Подключение от {address}')
                    print('Обмен параметрами ДХ')
                    print(f'pub1: {dh.pub_key}')
                    payload = {'type': 'CHANGE_CIPHER_SPEC',
                               'id': self.online_clients[client]['id'],
                               'data': {
                                   'p': dh.p,
                                   'g': dh.g,
                                   'pub': dh.pub_key,
                                   'pub_ds': self.q_point
                                },
                               'status': 'OK'
                               }
                    client.send(pickle.dumps(payload))
                    recv = pickle.loads(client.recv(self.BLOCK_SIZE))
                    if recv['status'] == 'OK':
                        if recv['type'] == 'SPEC_RESPONSE':
                            data = recv['data']
                            pub = data['pub']
                            name = data['name']
                            self.online_clients[client]['pub'] = pub
                            self.online_clients[client]['name'] = name
                    print(f'pub2: {self.online_clients[client]["pub"]}')
                    print('Генерация симметричного ключа...')
                    #master_key = long_to_bytes(dh.generate_full_key(self.online_clients[client]['pub']))
                    master_key = dh.generate_full_key(self.online_clients[client]['pub']).to_bytes(256, 'big')
                    print(f'Симметричный ключ: {master_key}')
                    self.online_clients[client]['master'] = master_key
                    print(f'{address} - Успешное подключение к чату!')
                    print(self.online_clients[client])
                    print()
                    con = sqlite3.connect('AppData/backup.db')
                    cursor = con.cursor()
                    create_table = f'CREATE TABLE IF NOT EXISTS user{self.online_clients[client]["id"]}(' \
                                   'id INTEGER PRIMARY KEY AUTOINCREMENT,' \
                                   'destination_id INT, ' \
                                   'source_id INT, ' \
                                   'text VARCHAR(256))'
                    cursor.execute(create_table)
                    con.commit()
                    con.close()
                    con = sqlite3.connect('AppData/members.db')
                    cursor = con.cursor()
                    cursor.execute(f'SELECT * FROM users WHERE id = {self.online_clients[client]["id"]}')
                    res = cursor.fetchall()
                    if not res:
                        cursor.execute(f'INSERT INTO users VALUES({self.online_clients[client]["id"]},'
                                       f' "{self.online_clients[client]["name"]}")')
                    con.commit()
                    con.close()
                    threading.Thread(target=self.message_handler, args=(client,)).start()
                    self.update_members()
            elif recv['type'] == 'CONNECT':
                if client not in self.online_clients:
                    self.online_clients[client] = {
                        'id': recv['id'],
                        'name': None,
                        'pub': None,
                        'master': None
                    }
                    dh = DHEndpoint()
                    print(f'Подключение от {address}')
                    print('Обмен параметрами ДХ')
                    print(f'pub1: {dh.pub_key}')
                    payload = {'type': 'CHANGE_CIPHER_SPEC',
                               'data': {
                                   'p': dh.p,
                                   'g': dh.g,
                                   'pub': dh.pub_key,
                                   'pub_ds': self.q_point
                               },
                               'status': 'OK'
                               }
                    client.send(pickle.dumps(payload))
                    recv = pickle.loads(client.recv(self.BLOCK_SIZE))
                    if recv['status'] == 'OK':
                        if recv['type'] == 'SPEC_RESPONSE':
                            data = recv['data']
                            pub = data['pub']
                            name = data['name']
                            self.online_clients[client]['pub'] = pub
                            self.online_clients[client]['name'] = name
                    print(f'pub2: {self.online_clients[client]["pub"]}')
                    print('Генерация симметричного ключа...')
                    master_key = dh.generate_full_key(self.online_clients[client]['pub']).to_bytes(256, 'big')
                    print(f'Симметричный ключ: {master_key}')
                    self.online_clients[client]['master'] = master_key
                    print(f'{address} - Успешное подключение к чату!')
                    print(self.online_clients[client])
                    print()
                    con = sqlite3.connect('AppData/members.db')
                    cursor = con.cursor()
                    cursor.execute(f'SELECT name FROM users WHERE id = {self.online_clients[client]["id"]}')
                    res = cursor.fetchone()[0]
                    print(res, self.online_clients[client]["name"])
                    if res != self.online_clients[client]["name"]:
                        cursor.execute(f'UPDATE users SET name = "{self.online_clients[client]["name"]}"'
                                       f' WHERE id = {self.online_clients[client]["id"]}')
                    con.commit()
                    con.close()
                    threading.Thread(target=self.message_handler, args=(client,)).start()
                    self.update_members()
            time.sleep(2)

    def message_handler(self, client_socket):
        bc = BlockCipher()
        while True:
            try:
                data = client_socket.recv(self.BLOCK_SIZE)
                key = self.online_clients[client_socket]['master']
                message = bc.decrypt(data, key, 'CBC')
                recv = pickle.loads(message)
                print(recv)
            except:
                del self.online_clients[client_socket]
                break

            if recv['status'] == 'OK':
                if recv['type'] == 'MESSAGE':
                    if recv['members'] == -1:
                        for client in self.online_clients:
                            if client != client_socket:
                                payload = {
                                    'type': 'MESSAGE',
                                    'body': {
                                        'members': '-1',
                                        'userid': recv['userid'],
                                        'data': recv['data'],
                                    },
                                    'sign': None,
                                    'status': 'OK'
                                }
                                r, s = self.ds.sign(int.from_bytes(pickle.dumps(payload['body']), 'big'), self.d)
                                print(f'Цифровая подпись: {r}, {s}')
                                payload['sign'] = (r, s)
                                key = self.online_clients[client]['master']
                                client.send(bc.encrypt(pickle.dumps(payload), key, 'CBC'))
                        query = f'INSERT INTO messages VALUES(Null, ' \
                                f'-1, {recv["userid"]}, "{recv["data"]["text"]}")'
                        con = sqlite3.connect('AppData/backup.db')
                        cursor = con.cursor()
                        cursor.execute(query)
                        con.commit()
                        con.close()
                    else:
                        query = f'INSERT INTO user{recv["members"]} VALUES(Null, ' \
                                f'{recv["members"]}, {recv["userid"]}, "{recv["data"]["text"]}")'
                        con = sqlite3.connect('AppData/backup.db')
                        cursor = con.cursor()
                        cursor.execute(query)
                        con.commit()
                        query = f'INSERT INTO user{recv["userid"]} VALUES(Null, ' \
                                f'{recv["members"]}, {recv["userid"]}, "{recv["data"]["text"]}")'
                        cursor.execute(query)
                        con.commit()
                        con.close()
                        for client in self.online_clients:
                            if self.online_clients[client]['id'] == recv['members']:
                                if client != client_socket:
                                    payload = {
                                        'type': 'MESSAGE',
                                        'body': {
                                            'members': self.online_clients[client]['id'],
                                            'userid': recv['userid'],
                                            'data': recv['data'],
                                        },
                                        'sign': None,
                                        'status': 'OK'
                                    }
                                    r, s = self.ds.sign(int.from_bytes(pickle.dumps(payload['body']), 'big'), self.d)
                                    payload['sign'] = (r, s)
                                    print(f'Цифровая подпись: {r}, {s}')
                                    key = self.online_clients[client]['master']
                                    client.send(bc.encrypt(pickle.dumps(payload), key, 'CBC'))
                                    print(f'{self.online_clients[client]["id"]}, {recv["userid"]}, "{recv["data"]["text"]})"')

                elif recv['type'] == 'UPDATE_MESSAGES':
                    source = recv['userid']
                    dest = recv['chatid']
                    if dest == -1:
                        query = f'SELECT * FROM messages WHERE destination_id = -1 ORDER BY id DESC LIMIT 10'
                    else:
                        query = f'SELECT * FROM user{source} WHERE (destination_id = {source} and source_id = {dest}) ' \
                                f'or ' \
                                f'(destination_id = {dest} and source_id = {source}) ORDER BY id DESC LIMIT 10'
                    con = sqlite3.connect('AppData/backup.db')
                    cursor = con.cursor()
                    cursor.execute(query)
                    res = cursor.fetchall()[::-1]
                    con.close()
                    payload = {
                        'type': 'MESSAGE_UPDATE_RESPONSE',
                        'data': res,
                        'status': 'OK'
                    }
                    print(payload)
                    key = self.online_clients[client_socket]['master']
                    client_socket.send(bc.encrypt(pickle.dumps(payload), key, 'CBC'))

                elif recv['type'] == "UPDATE_USERNAME":
                    userid = recv['userid']
                    username = recv['username']
                    self.online_clients[client_socket]['name'] = username
                    con = sqlite3.connect('AppData/members.db')
                    cursor = con.cursor()
                    query = f'UPDATE users SET name = "{username}" WHERE id = {userid}'
                    cursor.execute(query)
                    con.commit()
                    con.close()
                    self.update_members()

                elif recv['type'] == "EXIT":
                    print('=' * 50)
                    print(f'{client_socket} - разорвал соединение!')
                    print('=' * 50)
                    del self.online_clients[client_socket]
                    self.update_members()
                    break

    def update_members(self):
        bc = BlockCipher()
        online = {}
        for client in self.online_clients:
            id = self.online_clients[client]['id']
            name = self.online_clients[client]['name']
            online[id] = name
        query = 'SELECT * FROM users'
        con = sqlite3.connect('AppData/members.db')
        cursor = con.cursor()
        cursor.execute(query)
        res = cursor.fetchall()
        con.close()
        offline = {}
        for member in res:
            if member[0] not in online:
                offline[member[0]] = member[1]
        payload = {
            'type': 'UPDATE_MEMBERS',
            'data': {
                'online': online,
                'offline': offline
            },
            'status': 'OK'
        }
        for client in self.online_clients:
            key = self.online_clients[client]['master']
            client.send(bc.encrypt(pickle.dumps(payload), key, 'CBC'))


if __name__ == "__main__":
    server = Server('0.0.0.0', 1337)
