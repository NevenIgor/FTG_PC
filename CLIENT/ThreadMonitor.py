import time
import json
import os

from PyQt5 import QtCore

from CryptoCore.DH import DHEndpoint
from CryptoCore.DS import DSGOST
from CryptoCore.BC import BlockCipher
from CryptoCore.Cipher import BlockCipher as FBlockCipher
from CryptoCore.HASH import HGOST


class MessageMonitor(QtCore.QThread):
    mysignal = QtCore.pyqtSignal(dict)
    server_socket = None
    symmetric_key = None
    BLOCK_SIZE = 4096

    def __init__(self, parent=None, master_key=None, priv_ds=None, srv_pub=None):
        QtCore.QThread.__init__(self, parent)

        self.parent = parent

        if master_key:
            self.symmetric_key = master_key

        if priv_ds:
            self.priv_ds = priv_ds

        if srv_pub:
            self.srv_pub = srv_pub

        self.queue = None

        self.bc = BlockCipher()
        self.fbc = FBlockCipher()
        self.h = HGOST()
        self.ds = DSGOST(p=57896044618658097711785492504343953926634992332820282019728792003956564821041,
                         a=7,
                         b=43308876546767276905765904595650931995942111794451039583252968842033849580414,
                         q=57896044618658097711785492504343953927082934583725450622380973592137631069619,
                         p_x=2,
                         p_y=4018974056539037503335449422937059775635739389905545080690979365213431566280)

    def run(self):
        while True:
            if self.server_socket is not None:
                if self.queue:
                    self.send_encrypt(self.queue)
                    self.queue = None
                data = self.server_socket.recv(self.BLOCK_SIZE)
                print('Зашифрованные данные: ', data)
                message = self.bc.decrypt(data, self.symmetric_key, 'CBC')
                print('Расшифрованные данные: ', message)
                try:
                    recv = json.loads(message.decode())
                except Exception as e:
                    print(e)
                    continue
                print('Десериализованные данные: ', recv)
                if recv['status'] == 'OK':
                    if recv['type'] == 'CHANGE_CIPHER_SPEC':
                        data = recv['data']
                        dh = DHEndpoint(data['p'], data['g'])
                        pub = data['pub']
                        payload = {
                            'type': 'SPEC_RESPONSE',
                            'data': {
                                'pub': dh.pub_key
                            },
                            'status': 'OK'
                        }
                        self.send_encrypt(payload)
                        master_key = dh.generate_full_key(pub).to_bytes(32, 'big')
                        self.mysignal.emit({'type': 'SET_MASTER_KEY',
                                            'master_key': master_key})

                    elif recv['type'] == 'MESSAGE':
                        payload = recv['body']
                        sign = recv['sign']
                        h = int.from_bytes(self.h.hash(json.dumps(payload).encode()), 'big')
                        if self.ds.verify(h, sign, self.srv_pub):
                            print('Проверка подлинности ЦП прошла успешно')
                            userid = payload['userid']
                            users = payload['members']
                            data = payload['data']
                            self.mysignal.emit({'type': 'MESSAGE',
                                                'members': users,
                                                'userid': userid,
                                                'data': data})
                        else:
                            print('Цифровая подпись не соответствует сообщению')

                    elif recv['type'] == 'IMG_ASK':
                        if os.path.exists(os.path.join("Data", "profileImages", f'{self.parent.id}.png')):
                            with open(os.path.join("Data", "profileImages", f'{self.parent.id}.png'), 'rb') as f:
                                data = f.read()
                            enc_data = self.fbc.encrypt(data, self.symmetric_key, 'CBC')
                            with open(os.path.join("Data", "profileImages", f'{self.parent.id}.enc'), 'wb') as f:
                                f.write(enc_data)
                            with open(os.path.join("Data", "profileImages", f'{self.parent.id}.enc'), 'rb') as f:
                                while True:
                                    data = f.read(self.BLOCK_SIZE)
                                    if not data:
                                        break
                                    sent = self.server_socket.send(data)
                                    assert sent == len(data)
                            time.sleep(0.5)
                            self.server_socket.send(b'EOF')
                            os.remove(os.path.join("Data", "profileImages", f'{self.parent.id}.enc'))

                    elif recv['type'] == 'IMG_SEND_SPEC':
                        id = recv['id']
                        data = b''
                        while True:
                            recv = self.server_socket.recv(self.BLOCK_SIZE)
                            if recv != b'EOF':
                                data += recv
                            else:
                                break
                        if data:
                            with open(os.path.join("Data", "profileImages", f'{id}.png'), 'wb') as f:
                                f.write(self.fbc.decrypt(data, self.symmetric_key, 'CBC'))
                        self.mysignal.emit({
                            'type': 'UPDATE_USERLIST'
                        })

                    elif recv['type'] == 'UPDATE_MEMBERS':
                        clients = recv['data']
                        online = clients['online']
                        offline = clients['offline']
                        self.mysignal.emit({'type': 'UPDATE_MEMBERS',
                                            'online': online,
                                            'offline': offline})

                    elif recv['type'] == 'MESSAGE_UPDATE_RESPONSE':
                        sign = recv['sign']
                        h = int.from_bytes(self.h.hash(json.dumps(recv['data']).encode()), 'big')
                        if self.ds.verify(h, sign, self.srv_pub):
                            print('Проверка подлинности ЦП прошла успешно')
                            self.mysignal.emit({'type': 'MESSAGE_UPDATE_RESPONSE',
                                                'messages': recv['data']})

            time.sleep(2)

    def send_encrypt(self, data):
        enc = self.bc.encrypt(json.dumps(data).encode(), self.symmetric_key, 'CBC')
        self.server_socket.send(enc)
