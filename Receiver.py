#!/usr/bin/env python3

""" This program sends a response whenever it receives the "INF" """

# Copyright 2018 Rui Silva.
#
# This file is part of rpsreal/pySX127x, fork of mayeranalytics/pySX127x.
#
# pySX127x is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public
# License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# pySX127x is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
# details.
#
# You can be released from the requirements of the license by obtaining a commercial license. Such a license is
# mandatory as soon as you develop commercial activities involving pySX127x without disclosing the source code of your
# own applications, or shipping pySX127x with a closed source product.
#
# You should have received a copy of the GNU General Public License along with pySX127.  If not, see
# <http://www.gnu.org/licenses/>.

from colorama import Fore, Back, Style
import datetime
import sqlite3 as lite
import time, base64, sys, os, binascii
from Crypto.Cipher import AES
from SX127x.constants import add_lookup, MODE, BW, CODING_RATE, GAIN, PA_SELECT, PA_RAMP, MASK, REG
from SX127x.LoRa import set_bit, getter, setter
from x25519 import base_point_mult,multscalar

# Use BOARD 1
from SX127x.LoRa import LoRa
from SX127x.board_config import BOARD
# Use BOARD 2 (you can use BOARD1 and BOARD2 at the same time)
#from SX127x.LoRa import LoRa2 as LoRa
#from SX127x.board_config import BOARD2 as BOARD


BOARD.setup()
BOARD.reset()


class mylora(LoRa):
    def __init__(self, verbose=False):
        super(mylora, self).__init__(verbose)
        self.set_mode(MODE.SLEEP)
        self.set_dio_mapping([0] * 6)
        self.key = '1234567890123456'
        self.dh_key = ''
        self.rec_ack = 0
        self.pkey1 = ''
        self.pkey2 = ''
        self.pkey3 = ''
        self.pkey4 = ''
        self.pkey = ''
        self.rec_pub = ''
        self.key22 = ''
        self.a = os.urandom(32)
        self.X = b'1925a00940bfd1615ff356f7042fd5fac603840c12debc65fe8ca8b3890a4b90'
        self.Y = b'08a7527da970ee2badf20a0a1087a344207289e5015ca153c5f051dcffbf7cb6'

    def on_rx_done(self):
        rssi_val = self.get_pkt_rssi_value()
        snr_val = self.get_pkt_snr_value()
        rx_time = time.time()
        decoded = ''
        BOARD.led_on()
        #print("\nRxDone")
        self.clear_irq_flags(RxDone=1)
        payload = self.read_payload(nocheck=True )
        mens = payload
        if (self.rec_ack == 4):
            self.key = self.aes_key
            print ("\n:::::: KEY SHARING OVER :::::")
            print ("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
            #print("NEW AES Key = ", self.key)
            print ("Received Public Key = ",self.rec_pub)
            print ("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
            print ("New Session Key:\t",self.key22)
            print ("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
            print ("\n\n:::::: ACTUAL MESSAGE SHARING STARTED :::::")
        #mens=payload[4:-1] #to discard \xff\xff\x00\x00 and \x00 at the end
        mens=bytes(mens).decode("utf-8",'ignore')
        cipher = AES.new(self.key)
        decodemens=base64.b64decode(mens)
        decoded = cipher.decrypt(decodemens)
        decoded = bytes(decoded).decode("utf-8",'ignore')
        print ("\n== RECEIVED: ",decoded)
        print ("RSSI    : ",rssi_val ," dBm")
        print ("SNR     : ",snr_val, " dB")
        #print("RX_TIME = ", rx_time)
        #print("Type of Decoded", type(decoded))
        #print("Length of Decoded", len(decoded))
        self.rec_ack = self.rec_ack + 1
        if (self.rec_ack == 1):
            print ("\n:::::: KEY GENERATION STARTED :::::")
            time_start = time.time()
            self.a = os.urandom(32)
            a_pub = base_point_mult(self.a)
            t1 = a_pub.encode()
            public_key = binascii.hexlify(t1)
            t2 = binascii.unhexlify(public_key)
            '''t3 = t2.decode("utf-8",'ignore')
            t4 = t3.encode()
            t5 = binascii.hexlify(t4)'''
            self.pkey = str(public_key)
            print ("\nMy Public Key = ",self.pkey)
            self.pkey1 = self.pkey[2:34]
            self.pkey2 = self.pkey[34:66]
            print ("\nPartial KEY-1 = ",self.pkey1)
            print ("\nPartial KEY-2 = ",self.pkey2)
            if(len(self.pkey) == 99):
                self.pkey3 = self.pkey[66:98]
                self.pkey4 = '@@@'
                print ("\nPartial KEY-3 = ",self.pkey3)
                print ("\nPartial KEY-4 = ",self.pkey4)
            elif (len(self.pkey) > 98):
                self.pkey3 = self.pkey[66:98]
                self.pkey4 = self.pkey[98:-1]
                print ("\nPartial KEY-3 = ",self.pkey3)
                print ("\nPartial KEY-4 = ",self.pkey4)
            else:
                self.pkey3 = self.pkey[66:-1]
                self.pkey4 = '@@@'
                print ("\nPartial KEY-3 = ",self.pkey3)
                print ("\nPartial KEY-4 = ",self.pkey4)
            time_end = time.time()
            print ("\n:::::: KEY GENERATION OVER :::::\n")
            print ("Time Taken For Key Generation = ",(time_end-time_start)*1000," ms\n")
            
        BOARD.led_off()
        #if (self.rec_ack >= 5)
        if len(decoded)>1:
        #if "MSG" in decoded: 
        #if decoded=="INF             ":
            #print("\nReceived data, going to send ACK\n")
            time.sleep(4)
            
            if(self.rec_ack >= 5):
                msg_text = 'ACK ' + decoded[4:8]
            elif (self.rec_ack == 1):
                print ("\n:::::: KEY SHARING STARTED :::::")
                self.dh_key = decoded
                msg_text = self.pkey1
            elif (self.rec_ack == 2):
                self.dh_key = self.dh_key + decoded
                msg_text = self.pkey2
            elif (self.rec_ack == 3):
                self.dh_key = self.dh_key + decoded
                msg_text = self.pkey3
            elif (self.rec_ack == 4):
                self.dh_key = self.dh_key + decoded
                self.dh_key = self.dh_key.replace(" ","")
                self.dh_key = self.dh_key.replace("@","")
                byte_val = bytes(self.dh_key,"UTF-8")
               #print ("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
                #print ("Received Public KEY = ",byte_val)
                self.rec_pub = byte_val
                t2 = binascii.unhexlify(byte_val)
                t3 = t2.decode("utf-8",'ignore')
                #y = os.urandom(32)
                Bob_send = multscalar(self.Y, t3) # (y) aG
                Bob_send = multscalar(self.a, Bob_send) # (yb) aG
                k_b = multscalar(self.X, Bob_send)
                k2 = binascii.hexlify(k_b.encode())
                #print ("\nCalculated Shared Key:\t",k2)
                self.key22 = k2
                #print ("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
                #print ("\nLENGTH = ",len(binascii.hexlify(k_b.encode())))
                hash_b = hash(binascii.hexlify(k_b.encode()))
                hash_b = abs(hash_b)
                #print ("\nHASH 2 = ", hash_b)
                #print("\ntype of hash val = ", type(hash_b))

                self.aes_key = str(hash_b)
                while (len(self.aes_key)<16):
                    self.aes_key = "0" + self.aes_key
                if(len(self.aes_key) >= 16):
                    self.aes_key = self.aes_key[-16:]
                    
                self.aes_key = str(k2)[3:19]
                
                msg_text = self.pkey4
                
            while (len(msg_text)%16 != 0):
                msg_text = msg_text + ' '
            cipher = AES.new(self.key)
            encoded = base64.b64encode(cipher.encrypt(msg_text))
            #print("TYPE OF DATA RECEIVED ",type(encoded))
            #print("Length OF DATA RECEIVED ",len(encoded))
            lista=list(encoded)
            #lista.insert(0,0)
            #lista.insert(0,0)
            #lista.insert(0,255)
            #lista.insert(0,255)
            #lista.append(0)
            #print("Length LISTA ",len(lista))
            self.write_payload(lista)
            #self.write_payload([255, 255, 0, 0, 68, 65, 84, 65, 32, 82, 65, 83, 80, 66, 69, 82, 82, 89, 32, 80, 73, 0]) # Send DATA RASPBERRY PI
            self.set_mode(MODE.TX)
            print ("\n====== SEND: ",msg_text)
        #if "ACK" in decoded: 
        if 'ACK' in decoded:
            print("\nReceived ACK, Waiting for next data packet...\n")
            
        time.sleep(3)
        self.reset_ptr_rx()
        self.set_mode(MODE.RXCONT)

    def on_tx_done(self):
        print("\nTxDone")
        print(self.get_irq_flags())

    def on_cad_done(self):
        print("\non_CadDone")
        print(self.get_irq_flags())

    def on_rx_timeout(self):
        print("\non_RxTimeout")
        print(self.get_irq_flags())

    def on_valid_header(self):
        print("\non_ValidHeader")
        print(self.get_irq_flags())

    def on_payload_crc_error(self):
        print("\non_PayloadCrcError")
        print(self.get_irq_flags())

    def on_fhss_change_channel(self):
        print("\non_FhssChangeChannel")
        print(self.get_irq_flags())

    def start(self):          
        while True:
            self.reset_ptr_rx()
            self.set_mode(MODE.RXCONT) # Receiver mode
            while True:
                pass;
            

lora = mylora(verbose=False)

#     Slow+long range  Bw = 125 kHz, Cr = 4/8, Sf = 4096chips/symbol, CRC on. Power 13 dBm
lora.set_pa_config(pa_select=1, max_power=21, output_power=15)
lora.set_bw(BW.BW125)
lora.set_coding_rate(CODING_RATE.CR4_8)
lora.set_spreading_factor(12)
lora.set_rx_crc(True)
#lora.set_lna_gain(GAIN.G1)
#lora.set_implicit_header_mode(False)
lora.set_low_data_rate_optim(True)

#  Medium Range  Defaults after init are 434.0MHz, Bw = 125 kHz, Cr = 4/5, Sf = 128chips/symbol, CRC on Power 13 dBm
#lora.set_pa_config(pa_select=1)


assert(lora.get_agc_auto_on() == 1)

try:
    print ("\n--------------------------------")
    print (":::::: DIFFIE HELLMAN LoRa :::::")
    print ("--------------------------------\n")
    lora.start()
except KeyboardInterrupt:
    sys.stdout.flush()
    print("Exit")
    sys.stderr.write("KeyboardInterrupt\n")
finally:
    sys.stdout.flush()
    print("Exit")
    lora.set_mode(MODE.SLEEP)
BOARD.teardown()