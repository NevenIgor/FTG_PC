import time
import pickle

from PyQt5 import QtCore

from CryptoCore.DH import DHEndpoint
from CryptoCore.DS import DSGOST
from CryptoCore.BC import BlockCipher


class MessageMonitor(QtCore.QThread):
    mysignal = QtCore.pyqtSignal(dict)
    server_socket = None
    symmetric_key = None
    BLOCK_SIZE = 4096

    def __init__(self, parent=None, master_key=None, pub_ds=None):
        QtCore.QThread.__init__(self, parent)

        if master_key:
            self.symmetric_key = master_key

        if pub_ds:
            self.pub_ds = pub_ds

        self.bc = BlockCipher()

        self.ds = DSGOST(p=57896044618658097711785492504343953926634992332820282019728792003956564821041,
                         a=7,
                         b=43308876546767276905765904595650931995942111794451039583252968842033849580414,
                         q=57896044618658097711785492504343953927082934583725450622380973592137631069619,
                         p_x=2,
                         p_y=4018974056539037503335449422937059775635739389905545080690979365213431566280)

    def run(self):
        while True:
            if self.server_socket is not None:
                data = self.server_socket.recv(self.BLOCK_SIZE)
                print('Зашифрованные данные: ', data)
                message = self.bc.decrypt(data, self.symmetric_key, 'CBC')
                print('Расшифрованные данные: ', message)
                recv = pickle.loads(message)
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
                        self.send_encrypt(pickle.dumps(payload))
                        master_key = dh.generate_full_key(pub).to_bytes(256, 'big')
                        self.mysignal.emit({'type': 'SET_MASTER_KEY',
                                            'master_key': master_key})

                    elif recv['type'] == 'MESSAGE':
                        payload = recv['body']
                        sign = recv['sign']
                        if self.ds.verify(int.from_bytes(pickle.dumps(payload), 'big'), sign, self.pub_ds):
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

                    elif recv['type'] == 'UPDATE_MEMBERS':
                        clients = recv['data']
                        online = clients['online']
                        offline = clients['offline']
                        self.mysignal.emit({'type': 'UPDATE_MEMBERS',
                                            'online': online,
                                            'offline': offline})

                    elif recv['type'] == 'MESSAGE_UPDATE_RESPONSE':
                        self.mysignal.emit({'type': 'MESSAGE_UPDATE_RESPONSE',
                                            'messages': recv['data']})

            time.sleep(2)

    def send_encrypt(self, data):
        enc = self.bc.encrypt(pickle.dumps(data), self.symmetric_key, 'CBC')
        self.server_socket.send(enc)
