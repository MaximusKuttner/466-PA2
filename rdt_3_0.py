from datetime import datetime, timedelta
import network_3_0
import time
import argparse
from time import sleep
import hashlib


class RDTException(Exception):
    pass


class Packet:
    # the number of bytes used to store packet length
    seq_num_S_length = 10
    length_S_length = 10
    # length of md5 checksum in hex
    checksum_length = 32
    
    def __init__(self, seq_num, msg_s):
        self.seq_num = seq_num
        self.msg_S = msg_s
    
    @classmethod
    def from_byte_S(cls, byte_s):
        if Packet.corrupt(byte_s):
            raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
        # extract the fields
        seq_num = int(byte_s[Packet.length_S_length: Packet.length_S_length + Packet.seq_num_S_length])
        msg_S = byte_s[Packet.length_S_length + Packet.seq_num_S_length + Packet.checksum_length:]
        return cls(seq_num, msg_S)
    
    def get_byte_S(self):
        # convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_s = str(self.seq_num).zfill(self.seq_num_S_length)
        # convert length to a byte field of length_S_length bytes
        length_s = str(self.length_S_length + len(seq_num_s) + self.checksum_length + len(self.msg_S)).zfill(
            self.length_S_length)
        # compute the checksum
        checksum = hashlib.md5((length_s + seq_num_s + self.msg_S).encode('utf-8'))
        checksum_s = checksum.hexdigest()
        # compile into a string
        return length_s + seq_num_s + checksum_s + self.msg_S
    
    @staticmethod
    def corrupt(byte_s):
        # extract the fields
        length_s = byte_s[0:Packet.length_S_length]
        seq_num_s = byte_s[Packet.length_S_length: Packet.length_S_length + Packet.seq_num_S_length]
        checksum_s = byte_s[
                     Packet.length_S_length + Packet.seq_num_S_length: Packet.length_S_length + Packet.seq_num_S_length + Packet.checksum_length]
        msg_s = byte_s[Packet.length_S_length + Packet.seq_num_S_length + Packet.checksum_length:]
        
        # compute the checksum locally
        checksum = hashlib.md5(str(length_s + seq_num_s + msg_s).encode('utf-8'))
        computed_checksum_s = checksum.hexdigest()
        # and check if the same
        return checksum_s != computed_checksum_s


class RDT:
    # receive timeout
    timeout = timedelta(seconds=1)
    # latest sequence number used in a packet
    seq_num = 1
    # buffer of bytes read from network
    byte_buffer = ''
    
    def __init__(self, role_s, server_s, port):
        # use the passed in port and port+1 to set up unidirectional links between
        # RDT send and receive functions
        # cross the ports on the client and server to match net_snd to net_rcv
        if role_s == 'server':
            self.net_snd = network_3_0.NetworkLayer(role_s, server_s, port)
            self.net_rcv = network_3_0.NetworkLayer(role_s, server_s, port + 1)
        else:
            self.net_rcv = network_3_0.NetworkLayer(role_s, server_s, port)
            self.net_snd = network_3_0.NetworkLayer(role_s, server_s, port + 1)

    def disconnect(self):
        self.net_snd.disconnect()
        del self.net_snd
        self.net_rcv.disconnect()
        del self.net_rcv
    
    def rdt_3_0_send(self, msg_s):
        p = Packet(self.seq_num, msg_s)
        timeout = 1
        while True:
            self.net_snd.udt_send(p.get_byte_S())
            start = time.time()
            end = time.time()
            # Send Packet, wait for receive to send ACK or NAK, if no response, start over
            rcv = ''
            while rcv == '' and end - start < timeout:
                rcv = self.net_snd.udt_receive()
                end = time.time()
            if rcv == '':
                print('[RETRANSMITTING] no ACK or NAK received')
                continue
            length = int(rcv[:Packet.length_S_length])
            self.byte_buffer = rcv[length:]
            corrupt = Packet.corrupt(rcv[:length])
            if corrupt:
                print('[NAK RECEIVED]:')
                self.byte_buffer = ''
                continue
            rcv_pkt = Packet.from_byte_S(rcv[:length])
            if rcv_pkt.msg_S == 'ACK':
                print('[ACK RECEIVED]:')
                self.seq_num += 1
                return
            if rcv_pkt.msg_S == 'NAK':
                print(F'[NAK RECEIVED]:')
                self.byte_buffer = ''
                continue
    
    def rdt_3_0_receive(self):
        self.byte_buffer = ''
        ret_s = None
        while True:
            self.byte_buffer += self.net_rcv.udt_receive()
            # check if we have received enough bytes
            if len(self.byte_buffer) < Packet.length_S_length:
                return ret_s  # not enough bytes to read packet length
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                return ret_s  # not enough bytes to read packet length

            corrupt = Packet.corrupt(self.byte_buffer[0:length])
            if corrupt:
                print(F"[NAK SENT]:")
                self.net_rcv.udt_send(Packet(self.seq_num, 'NAK').get_byte_S())
                self.byte_buffer = ''
                continue
            p = Packet.from_byte_S(self.byte_buffer[0:length])
            if not corrupt:
                print(F"[ACK SENT]:")
                self.net_rcv.udt_send(Packet(self.seq_num, 'ACK').get_byte_S())
            else:
                print(F"[NAK SENT]:")
                self.net_rcv.udt_send(Packet(self.seq_num, 'NAK').get_byte_S())
                self.byte_buffer = ''
                continue
            ret_s = p.msg_S if (ret_s is None) else ret_s + p.msg_S
            self.byte_buffer = self.byte_buffer[length:]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()
    
    rdt = RDT(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.rdt_3_0_send('MSG_FROM_CLIENT')
        sleep(2)
        print(rdt.rdt_3_0_receive())
        rdt.disconnect()
    else:
        sleep(1)
        print(rdt.rdt_3_0_receive())
        rdt.rdt_3_0_send('MSG_FROM_SERVER')
        rdt.disconnect()
