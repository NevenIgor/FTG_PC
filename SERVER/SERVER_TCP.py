import socket
import threading

import time
import sqlite3
import os
import json
import random
import zlib

from CryptoCore.DH import DHEndpoint
from CryptoCore.DS import DSGOST
from CryptoCore.EC import ECPoint
from CryptoCore.BC import BlockCipher
from CryptoCore.HASH import HGOST
from CryptoCore.Cipher import BlockCipher as FBlockCipher

from Display_LCD import Display


class Server():
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.online_clients = dict()
        self.ctr = 0

        self.display_connected = True
        self.display = Display()

        self.DEFAULT_SIZE = 4096

        self.h = HGOST()

        self.bc = BlockCipher()
        self.fbc = FBlockCipher()

        self.ds = DSGOST(p=57896044618658097711785492504343953926634992332820282019728792003956564821041,
                         a=7,
                         b=43308876546767276905765904595650931995942111794451039583252968842033849580414,
                         q=57896044618658097711785492504343953927082934583725450622380973592137631069619,
                         p_x=2,
                         p_y=4018974056539037503335449422937059775635739389905545080690979365213431566280)

        self.priv_ds, self.pub_ds = self.ds.gen_keys()

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.ip, self.port))
        self.server.listen(0)
        threading.Thread(target=self.connect_handler).start()

        con = sqlite3.connect('SERVER/AppData/backup.db')
        cursor = con.cursor()
        create_table = f'CREATE TABLE IF NOT EXISTS messages(' \
                       'id INTEGER PRIMARY KEY AUTOINCREMENT,' \
                       'destination_id INT, ' \
                       'source_id INT, ' \
                       'text VARCHAR(4096))'
        cursor.execute(create_table)
        con.commit()
        con.close()

        con = sqlite3.connect('SERVER/AppData/members.db')
        cursor = con.cursor()
        create_table = f'CREATE TABLE IF NOT EXISTS users(' \
                       'id INTEGER PRIMARY KEY,' \
                       'name VARCHAR(256),' \
                       'pass VARCHAR(512),' \
                       'q_spec_x VARCHAR(512),' \
                       'q_spec_y VARCHAR(512))'
        cursor.execute(create_table)
        con.commit()
        con.close()

        self.update_configs()

        print('Сервер запущен!')
        self.print('Server is running!')

    def print(self, string):
        if self.display_connected:
            self.display.write_line(string)

    def send_data(self, client, payload):
        data = json.dumps(payload)
        client.send(data.encode())

    def recv_data(self, client):
        recv = client.recv(self.DEFAULT_SIZE)
        print(recv)
        return json.loads(recv.decode())

    def update_configs(self):
        if os.path.exists(os.path.join('SERVER', "AppData", "config.json")):
            with open(os.path.join('SERVER', "AppData", "config.json")) as file:
                data = json.load(file)
                self.ctr = data['ctr']

    def set_config(self):
        with open(os.path.join("SERVER", "AppData", "config.json"), 'w') as file:
            payload = {
                'ctr': self.ctr
            }
            data = json.dumps(payload)
            file.write(data)

    def connect_handler(self):
        while True:
            client, address = self.server.accept()
            recv = self.recv_data(client)
            if recv['type'] == 'SET_NEW_USER':
                con = sqlite3.connect('SERVER/AppData/members.db')
                cursor = con.cursor()
                cursor.execute(f'SELECT * FROM users WHERE id = {self.ctr}')
                res = cursor.fetchall()
                while res:
                    self.ctr += 1
                    cursor.execute(f'SELECT * FROM users WHERE id = {self.ctr}')
                    res = cursor.fetchall()
                con.close()
                self.set_config()
                client_priv, client_pub = self.ds.gen_keys()
                q_spec = [client_pub.x, client_pub.y, client_pub.a, client_pub.b, client_pub.p]
                if client not in self.online_clients:
                    self.online_clients[client] = {
                        'id': self.ctr,
                        'name': None,
                        'img': None,
                        'pub': None,
                        'master': None,
                        'pub_ds': client_pub
                    }
                    dh = DHEndpoint()
                    print(f'Подключение от {address}')
                    self.print(f'addr: {address[0]}')
                    print('Обмен параметрами ДХ')
                    print('DH key exchanging...')
                    print(f'pub1: {dh.pub_key}')
                    pub_spec = [self.pub_ds.x, self.pub_ds.y]
                    payload = {'type': 'CHANGE_CIPHER_SPEC',
                               'id': self.online_clients[client]['id'],
                               'data': {
                                   'p': dh.p,
                                   'g': dh.g,
                                   'pub_dh': dh.pub_key,
                                   'pub_ds': pub_spec
                                },
                               'status': 'OK'
                               }
                    print(payload)
                    self.send_data(client, payload)
                    recv = self.recv_data(client)
                    if recv['status'] == 'OK':
                        if recv['type'] == 'SPEC_RESPONSE':
                            data = recv['data']
                            pub = data['pub']
                            name = data['name']
                            self.online_clients[client]['pub'] = pub
                            self.online_clients[client]['name'] = name
                    print(f'pub2: {self.online_clients[client]["pub"]}')
                    print('Генерация симметричного ключа...')
                    self.print('Symmetric key gen...')
                    master_key = dh.generate_full_key(self.online_clients[client]['pub']).to_bytes(32, 'big')
                    print(f'Симметричный ключ: {master_key}')
                    self.online_clients[client]['master'] = master_key
                    print(f'{address} - Успешное подключение к чату!')
                    self.print('Successful connected')
                    print(self.online_clients[client])
                    passwd = int.from_bytes(random.randbytes(32), 'big')
                    payload = {
                        'type': 'DS_PRIVATE_KEY',
                        'data': {
                            'priv_ds': client_priv,
                            'pass': passwd
                        },
                        'status': 'OK'
                    }
                    print(payload)
                    client.send(self.bc.encrypt(json.dumps(payload).encode(), master_key, 'CBC'))
                    con = sqlite3.connect('SERVER/AppData/backup.db')
                    cursor = con.cursor()
                    create_table = f'CREATE TABLE IF NOT EXISTS user{self.online_clients[client]["id"]}(' \
                                   'id INTEGER PRIMARY KEY AUTOINCREMENT,' \
                                   'destination_id INT, ' \
                                   'source_id INT, ' \
                                   'text VARCHAR(256))'
                    cursor.execute(create_table)
                    con.commit()
                    con.close()
                    con = sqlite3.connect('SERVER/AppData/members.db')
                    cursor = con.cursor()
                    cursor.execute(f'SELECT * FROM users WHERE id = {self.online_clients[client]["id"]}')
                    res = cursor.fetchall()
                    if not res:
                        cursor.execute(f'INSERT INTO users VALUES({self.online_clients[client]["id"]},'
                                       f' "{self.online_clients[client]["name"]}",'
                                       f' "{passwd}",'
                                       f' "{q_spec[0]}",'
                                       f' "{q_spec[1]}")')
                    con.commit()
                    con.close()
                    payload = {
                        'type': 'IMG_ASK',
                        'status': 'OK'
                    }
                    client.send(self.bc.encrypt(json.dumps(payload).encode(), master_key, 'CBC'))
                    data = b''
                    while True:
                        recv = client.recv(self.DEFAULT_SIZE)
                        if recv != b'EOF':
                            data += recv
                        else:
                            break
                    if data:
                        with open(os.path.join('SERVER', 'AppData', 'UsersImages', f'{self.online_clients[client]["id"]}.png'), 'wb') as f:
                            f.write(self.fbc.decrypt(data, master_key, 'CBC'))
                        self.online_clients[client]["img"] = zlib.crc32(
                            open(os.path.join('SERVER', 'AppData', 'UsersImages', f'{self.online_clients[client]["id"]}.png'), 'rb').read())
                    else:
                        self.online_clients[client]["img"] = None
                    payload = {
                        'type': 'CONNECT_CONFIRM',
                        'status': 'OK'
                    }
                    client.send(self.bc.encrypt(json.dumps(payload).encode(), master_key, 'CBC'))
                    threading.Thread(target=self.message_handler, args=(client,)).start()
            elif recv['type'] == 'CONNECT':
                if client not in self.online_clients:
                    print(f'Подключение от {address}')
                    self.print(f'addr: {address}')
                    id = recv['id']
                    old = None
                    for old_client in self.online_clients:
                        if self.online_clients[old_client]['id'] == id:
                            old = old_client
                    if old:
                        print(self.online_clients)
                        print(old)
                        del self.online_clients[old]
                    con = sqlite3.connect('SERVER/AppData/members.db')
                    cursor = con.cursor()
                    cursor.execute(f'SELECT q_spec_x, q_spec_y, pass FROM users WHERE id = {id}')
                    res = cursor.fetchone()
                    if res:
                        q_spec_x = int(res[0])
                        q_spec_y = int(res[1])
                        pub_ds = ECPoint(q_spec_x, q_spec_y, self.ds.a, self.ds.b, self.ds.p)
                        passwd = res[2]
                        challenge = int.from_bytes(random.randbytes(32), 'big')
                        print(f'Вызов: {challenge}')
                        self.print('Auth challenge')
                        payload = {
                            'type': 'AUTH_CHALLENGE',
                            'data': {
                                'challenge': challenge
                            },
                            'status': 'OK'
                        }
                        self.send_data(client, payload)
                        hash = self.h.hash(int(passwd) + challenge)
                        print(f'Hash: {hash}')
                        recv = self.recv_data(client)
                        if recv['status'] == 'OK':
                            if recv['type'] == 'AUTH_RESPONSE':
                                data = recv['data']
                                response = data['response']
                                sign = data['sign']
                                print(f'Ответ: {response}')
                                if response == hash:
                                    if self.ds.verify(response, sign, pub_ds):
                                        print('Аутентификация пройдена успешно')
                                        self.print('Completed')
                                        self.online_clients[client] = {
                                            'id': id,
                                            'name': None,
                                            'img': None,
                                            'pub': None,
                                            'master': None,
                                            'pub_ds': pub_ds
                                        }
                                        dh = DHEndpoint()
                                        print('Обмен параметрами ДХ')
                                        self.print('DH key exchange...')
                                        print(f'pub1: {dh.pub_key}')
                                        pub_spec = [self.pub_ds.x, self.pub_ds.y]
                                        payload = {'type': 'CHANGE_CIPHER_SPEC',
                                                   'data': {
                                                       'p': dh.p,
                                                       'g': dh.g,
                                                       'pub_dh': dh.pub_key,
                                                       'pub_ds': pub_spec,
                                                   },
                                                   'status': 'OK'
                                                   }
                                        print(payload)
                                        self.send_data(client, payload)
                                        recv = self.recv_data(client)
                                        if recv['status'] == 'OK':
                                            if recv['type'] == 'SPEC_RESPONSE':
                                                data = recv['data']
                                                pub = data['pub']
                                                name = data['name']
                                                img = data['img']
                                                self.online_clients[client]['pub'] = pub
                                                self.online_clients[client]['name'] = name
                                                self.online_clients[client]['img'] = img
                                                print(f'pub2: {self.online_clients[client]["pub"]}')
                                                print('Генерация симметричного ключа...')
                                                self.print('Symmetric key gen')
                                                master_key = dh.generate_full_key(self.online_clients[client]['pub']).to_bytes(32, 'big')
                                                print(f'Симметричный ключ: {master_key}')
                                                self.online_clients[client]['master'] = master_key
                                                print(f'{address} - Успешное подключение к чату!')
                                                self.print('Successful connected')
                                                print(self.online_clients[client])
                                                con = sqlite3.connect('SERVER/AppData/members.db')
                                                cursor = con.cursor()
                                                cursor.execute(f'SELECT name FROM users WHERE id = {self.online_clients[client]["id"]}')
                                                res = cursor.fetchone()[0]
                                                if res != self.online_clients[client]["name"]:
                                                    cursor.execute(f'UPDATE users SET name = "{self.online_clients[client]["name"]}"'
                                                                   f' WHERE id = {self.online_clients[client]["id"]}')
                                                con.commit()
                                                con.close()
                                                if img:
                                                    if os.path.exists(os.path.join('SERVER', 'AppData', 'UsersImages', f'{id}.png')):
                                                        crc = zlib.crc32(open(os.path.join('SERVER', 'AppData', 'UsersImages', f'{id}.png'), 'rb').read())
                                                        if crc != img:
                                                            payload = {
                                                                'type': 'IMG_ASK',
                                                                'status': 'OK'
                                                            }
                                                            client.send(
                                                                self.bc.encrypt(json.dumps(payload).encode(), master_key,
                                                                           'CBC'))
                                                            data = b''
                                                            while True:
                                                                recv = client.recv(self.DEFAULT_SIZE)
                                                                if recv != b'EOF':
                                                                    data += recv
                                                                else:
                                                                    break
                                                            with open(os.path.join('SERVER', 'AppData', 'UsersImages',
                                                                                   f'{self.online_clients[client]["id"]}.png'),
                                                                      'wb') as f:
                                                                f.write(self.fbc.decrypt(data, master_key, 'CBC'))
                                                            self.online_clients[client]["img"] = zlib.crc32(
                                                                open(os.path.join('SERVER', 'AppData', 'UsersImages',
                                                                                  f'{self.online_clients[client]["id"]}.png'),
                                                                     'rb').read())
                                                    else:
                                                        payload = {
                                                            'type': 'IMG_ASK',
                                                            'status': 'OK'
                                                        }
                                                        client.send(
                                                            self.bc.encrypt(json.dumps(payload).encode(), master_key, 'CBC'))
                                                        data = b''
                                                        while True:
                                                            recv = client.recv(self.DEFAULT_SIZE)
                                                            if recv != b'EOF':
                                                                data += recv
                                                            else:
                                                                break
                                                        if data:
                                                            with open(os.path.join('SERVER', 'AppData', 'UsersImages',
                                                                                   f'{self.online_clients[client]["id"]}.png'),
                                                                      'wb') as f:
                                                                f.write(self.fbc.decrypt(data, master_key, 'CBC'))
                                                            self.online_clients[client]["img"] = zlib.crc32(
                                                                open(os.path.join('SERVER', 'AppData', 'UsersImages',
                                                                                  f'{self.online_clients[client]["id"]}.png'),
                                                                     'rb').read())
                                                        else:
                                                            self.online_clients[client]["img"] = None
                                                else:
                                                    if os.path.exists(os.path.join('SERVER', 'AppData', 'UsersImages', f'{id}.png')):
                                                        os.remove(os.path.join('SERVER', 'AppData', 'UsersImages', f'{id}.png'))
                                                payload = {
                                                    'type': 'CONNECT_CONFIRM',
                                                    'status': 'OK'
                                                }
                                                client.send(
                                                    self.bc.encrypt(json.dumps(payload).encode(), master_key,
                                                                    'CBC'))
                                                threading.Thread(target=self.message_handler, args=(client,)).start()

                                    else:
                                        print('Неверный сертификат ЦП')
                                        self.print('DS verification fail!')
                                        payload = {
                                            'type': 'AUTH_CONF',
                                            'err': 'Проверка ЦП не пройдена',
                                            'status': 'err'
                                        }
                                        self.send_data(client, payload)
                                        time.sleep(2)
                                        continue
                                else:
                                    print('Неверный ответ на вызов')
                                    self.print('Challenge fail')
                                    payload = {
                                        'type': 'AUTH_CONF',
                                        'err': 'Неверный ответ на вызов',
                                        'status': 'err'
                                    }
                                    self.send_data(client, payload)
                                    time.sleep(2)
                                    continue
                    else:
                        print(f'Пользователь с идентификатором {id} не найден')
                        self.print(f'No user with id: {id}')
                        payload = {
                            'type': 'AUTH_ERR',
                            'err': f'No users found with id {id}',
                            'status': 'ERROR'
                        }
                        self.send_data(client, payload)
                        time.sleep(2)
                        continue

            time.sleep(2)

    def message_handler(self, client_socket):
        while True:
            try:
                data = client_socket.recv(self.DEFAULT_SIZE)
                key = self.online_clients[client_socket]['master']
                message = self.bc.decrypt(data, key, 'CBC')
                recv = json.loads(message.decode())
                print(recv)
            except:
                del self.online_clients[client_socket]
                break

            if recv['status'] == 'OK':
                if recv['type'] == 'MESSAGE':
                    h = int.from_bytes(self.h.hash(json.dumps(recv['data']).encode()), 'big')
                    if self.ds.verify(h, recv['sign'], self.online_clients[client_socket]['pub_ds']):
                        print('Verification: True')
                        self.print('DS verification completed')
                        if recv['members'] == -1:
                            for client in self.online_clients:
                                if client != client_socket:
                                    payload = {
                                        'type': 'MESSAGE',
                                        'body': {
                                            'members': -1,
                                            'userid': recv['userid'],
                                            'data': recv['data'],
                                        },
                                        'sign': None,
                                        'status': 'OK'
                                    }
                                    h = int.from_bytes(self.h.hash(json.dumps(payload['body']).encode()), 'big')
                                    r, s = self.ds.sign(h, self.priv_ds)
                                    print(f'Цифровая подпись: {r}, {s}')
                                    print('signing data completed')
                                    payload['sign'] = (r, s)
                                    key = self.online_clients[client]['master']
                                    client.send(self.bc.encrypt(json.dumps(payload).encode(), key, 'CBC'))
                            query = f'INSERT INTO messages VALUES(Null, ' \
                                    f'-1, {recv["userid"]}, "{recv["data"]["text"]}")'
                            con = sqlite3.connect('SERVER/AppData/backup.db')
                            cursor = con.cursor()
                            cursor.execute(query)
                            con.commit()
                            con.close()
                        else:
                            query = f'INSERT INTO user{recv["members"]} VALUES(Null, ' \
                                    f'{recv["members"]}, {recv["userid"]}, "{recv["data"]["text"]}")'
                            con = sqlite3.connect('SERVER/AppData/backup.db')
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
                                        h = int.from_bytes(self.h.hash(json.dumps(payload['body']).encode()), 'big')
                                        r, s = self.ds.sign(h, self.priv_ds)
                                        payload['sign'] = (r, s)
                                        print(f'Цифровая подпись: {r}, {s}')
                                        self.print('Signing data completed')
                                        key = self.online_clients[client]['master']
                                        client.send(self.bc.encrypt(json.dumps(payload).encode(), key, 'CBC'))
                elif recv['type'] == 'UPDATE_MESSAGES':
                    source = recv['userid']
                    dest = recv['chatid']
                    if dest == -1:
                        query = f'SELECT * FROM messages WHERE destination_id = -1 ORDER BY id DESC LIMIT 10'
                    else:
                        query = f'SELECT * FROM user{source} WHERE (destination_id = {source} and source_id = {dest}) ' \
                                f'or ' \
                                f'(destination_id = {dest} and source_id = {source}) ORDER BY id DESC LIMIT 10'
                    con = sqlite3.connect('SERVER/AppData/backup.db')
                    cursor = con.cursor()
                    cursor.execute(query)
                    res = cursor.fetchall()[::-1]
                    con.close()
                    payload = {
                        'type': 'MESSAGE_UPDATE_RESPONSE',
                        'data': res,
                        'sign': None,
                        'status': 'OK'
                    }
                    print(payload)
                    h = int.from_bytes(self.h.hash(json.dumps(payload['data']).encode()), 'big')
                    r, s = self.ds.sign(h, self.priv_ds)
                    payload['sign'] = (r, s)
                    key = self.online_clients[client_socket]['master']
                    client_socket.send(self.bc.encrypt(json.dumps(payload).encode(), key, 'CBC'))

                elif recv['type'] == "UPDATE_USERNAME":
                    userid = recv['userid']
                    username = recv['username']
                    user_img = recv['img']
                    if user_img:
                        if os.path.exists(f'SERVER/AppData/UsersImages/{self.online_clients[client_socket]["id"]}.png'):
                            crc_store = zlib.crc32(open(f'AppData/UsersImages/{self.online_clients[client_socket]["id"]}.png', 'rb').read())
                            if user_img != crc_store:
                                payload = {
                                    'type': 'IMG_ASK',
                                    'status': 'OK'
                                }
                                print(payload)
                                key = self.online_clients[client_socket]['master']
                                client_socket.send(
                                    self.bc.encrypt(json.dumps(payload).encode(), key, 'CBC'))
                                data = b''
                                while True:
                                    recv = client_socket.recv(self.DEFAULT_SIZE)
                                    if recv != b'EOF':
                                        data += recv
                                    else:
                                        break
                                if data:
                                    with open(os.path.join('SERVER', 'AppData', 'UsersImages',
                                                           f'{self.online_clients[client_socket]["id"]}.png'),
                                              'wb') as f:
                                        f.write(self.fbc.decrypt(data, key, 'CBC'))
                        else:
                            payload = {
                                'type': 'IMG_ASK',
                                'status': 'OK'
                            }
                            print(payload)
                            key = self.online_clients[client_socket]['master']
                            client_socket.send(
                                self.bc.encrypt(json.dumps(payload).encode(), key, 'CBC'))
                            data = b''
                            while True:
                                recv = client_socket.recv(self.DEFAULT_SIZE)
                                if recv != b'EOF':
                                    data += recv
                                else:
                                    break
                            if data:
                                with open(os.path.join('SERVER', 'AppData', 'UsersImages',
                                                       f'{self.online_clients[client_socket]["id"]}.png'),
                                          'wb') as f:
                                    f.write(self.fbc.decrypt(data, key, 'CBC'))
                    else:
                        if os.path.exists(f'SERVER/AppData/UsersImages/{self.online_clients[client_socket]["id"]}.png'):
                            os.remove(f'SERVER/AppData/UsersImages/{self.online_clients[client_socket]["id"]}.png')
                    self.online_clients[client_socket]['name'] = username
                    self.online_clients[client_socket]['img'] = user_img
                    con = sqlite3.connect('SERVER/AppData/members.db')
                    cursor = con.cursor()
                    query = f'UPDATE users SET name = "{username}" WHERE id = {userid}'
                    cursor.execute(query)
                    con.commit()
                    con.close()
                    self.update_members()

                elif recv['type'] == "IMG_UPDATE_REQUEST":
                    images = recv['data']['users_img']
                    for img in images:
                        payload = {
                            'type': 'IMG_SEND_SPEC',
                            'id': img,
                            'status': 'OK'
                        }
                        print(payload)
                        key = self.online_clients[client_socket]['master']
                        client_socket.send(
                            self.bc.encrypt(json.dumps(payload).encode(), key, 'CBC'))
                        time.sleep(1.2)
                        if os.path.exists(os.path.join('SERVER', 'AppData', 'UsersImages', f'{img}.png')):
                            with open(os.path.join('SERVER', 'AppData', 'UsersImages', f'{img}.png'), 'rb') as f:
                                data = f.read()
                            enc_data = self.fbc.encrypt(data, key, 'CBC')
                            with open(os.path.join('SERVER', 'AppData', 'UsersImages', f'{img}.enc'), 'wb') as f:
                                f.write(enc_data)
                            with open(os.path.join('SERVER', 'AppData', 'UsersImages', f'{img}.enc'), 'rb') as f:
                                while True:
                                    data = f.read(self.DEFAULT_SIZE)
                                    if not data:
                                        break
                                    sent = client_socket.send(data)
                                    assert sent == len(data)
                            time.sleep(1.2)
                            client_socket.send(b'EOF')
                            os.remove(os.path.join('SERVER', 'AppData', 'UsersImages', f'{img}.enc'))
                            time.sleep(1.2)

                elif recv['type'] == "EXIT":
                    text = f'{client_socket} - разорвал соединение!'
                    print('=' * len(text))
                    print(text)
                    print('=' * len(text))
                    del self.online_clients[client_socket]
                    self.update_members()
                    break
            time.sleep(1.2)

    def update_members(self):
        bc = BlockCipher()
        online = {}
        for client in self.online_clients:
            id = self.online_clients[client]['id']
            name = self.online_clients[client]['name']
            img = self.online_clients[client]['img']
            online[id] = (name, img)
        query = 'SELECT * FROM users'
        con = sqlite3.connect('SERVER/AppData/members.db')
        cursor = con.cursor()
        cursor.execute(query)
        res = cursor.fetchall()
        con.close()
        offline = {}
        for member in res:
            if member[0] not in online:
                if os.path.exists(os.path.join('SERVER', 'AppData', 'UsersImages', f'{member[0]}.png')):
                    crc = zlib.crc32(open(os.path.join('SERVER', 'AppData', 'UsersImages', f'{member[0]}.png'), 'rb').read())
                else:
                    crc = None
                offline[member[0]] = (member[1], crc)
        payload = {
            'type': 'UPDATE_MEMBERS',
            'data': {
                'online': online,
                'offline': offline
            },
            'status': 'OK'
        }
        print(payload)
        for client in self.online_clients:
            key = self.online_clients[client]['master']
            client.send(bc.encrypt(json.dumps(payload).encode(), key, 'CBC'))


if __name__ == "__main__":
    server = Server('0.0.0.0', 1337)
