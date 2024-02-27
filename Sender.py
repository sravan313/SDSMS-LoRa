#!/usr/bin/env python3

#SDSMS-LoRa Sender Code

from colorama import Fore, Back, Style
import time, base64, sys, datetime, os, binascii
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

#counter = 0


class mylora(LoRa):
    def __init__(self, verbose=False):
        super(mylora, self).__init__(verbose)
        self.set_mode(MODE.SLEEP)
        self.set_dio_mapping([0] * 6)
        self.a = os.urandom(32)
        self.var=0
        self.key = '1234567890123456'
        self.X = b'1925a00940bfd1615ff356f7042fd5fac603840c12debc65fe8ca8b3890a4b90'
        self.Y = b'08a7527da970ee2badf20a0a1087a344207289e5015ca153c5f051dcffbf7cb6'
        self.dh_key = ''
        self.counter = 0
        self.key_gen = 1

    def on_rx_done(self):
        rssi_val = self.get_pkt_rssi_value()
        snr_val = self.get_pkt_snr_value()
        BOARD.led_on()
        #print("\nRxDone")
        self.clear_irq_flags(RxDone=1)
        payload = self.read_payload(nocheck=True)
        mens = payload
        #mens=payload[4:-1] #to discard \xff\xff\x00\x00 and \x00 at the end
        mens=bytes(mens).decode("utf-8",'ignore')
        cipher = AES.new(self.key)
        decodemens=base64.b64decode(mens)
        decoded = cipher.decrypt(decodemens)
        decoded = bytes(decoded).decode("utf-8",'ignore')
        print ("\n== RECEIVED: ",decoded)
        print ("RSSI    : ",rssi_val ," dBm")
        print ("SNR     : ",snr_val, " dB")
        self.key_gen = self.key_gen + 1
        if(self.key_gen == 2):
            self.dh_key = decoded
        elif(self.key_gen == 3):
            self.dh_key = self.dh_key + decoded
        elif(self.key_gen == 4):
            self.dh_key = self.dh_key + decoded
        elif(self.key_gen == 5):
            print ("\n:::::: KEY SHARING OVER :::::")
            self.dh_key = self.dh_key + decoded
            self.dh_key = self.dh_key.replace(" ","")
            self.dh_key = self.dh_key.replace("@","")
            byte_val = bytes(self.dh_key,"UTF-8")
            print ("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
            print ("Received Public Key = ",byte_val)
            print ("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
            t2 = binascii.unhexlify(byte_val)
            t3 = t2.decode("utf-8",'ignore')
            #y = os.urandom(32)
            A_send = multscalar(self.X, t3)
            A_send = multscalar(self.a, A_send)
            k_a = multscalar(self.Y, A_send)
            k1 = binascii.hexlify(k_a.encode())
            print ("New Session Key:\t",k1)
            #print ("\nLENGTH = ",len(binascii.hexlify(k_a.encode())))
            hash_a = hash(binascii.hexlify(k_a.encode()))
            hash_a = abs(hash_a)
            #print ("\nHASH 1 = ",hash_a)
            aes_key = str(hash_a)
            while (len(aes_key) < 16):
                aes_key = '0' + aes_key
            if (len(aes_key) >= 16):
                aes_key = aes_key[-16:]
                
            #self.key = aes_key
            self.aes_key = str(k1)[3:19]
            self.key = self.aes_key
            #print("\nNEW AES KEY = ",self.key)
            print ("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
            print ("\n\n:::::: ACTUAL MESSAGE SHARING STARTED :::::")
            self.counter = 0
            
            
        BOARD.led_off()
        time.sleep(2) # Wait for the client be ready
        
        '''msg_text = 'ACK #' + str(self.counter)
        while (len(msg_text)<16):
                    msg_text = msg_text + ' '
        cipher = AES.new(self.key)
        encoded = base64.b64encode(cipher.encrypt(msg_text))
        lista=list(encoded)
        lista.insert(0,0)
        lista.insert(0,0)
        lista.insert(0,255)
        lista.insert(0,255)
        lista.append(0)
        self.write_payload(lista)
        #self.write_payload([255, 255, 0, 0, 65, 67, 75, 0]) # Send ACK
        self.set_mode(MODE.TX)
        print ("\n== SEND: ", msg_text, "\nEncoded: ", encoded.decode("utf-8",'ignore'))
        #print ("\n")'''
        self.var=1

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
        
        if (self.key_gen == 1):
            print ("\n:::::: KEY GENERATION STARTED :::::")
            time_start = time.time()
            #print ("\nX-Type = ",type(self.X))
            #print ("\nY-Type = ",type(self.Y))
            self.a = os.urandom(32)
            a_pub = base_point_mult(self.a)
            t1 = a_pub.encode()
            public_key = binascii.hexlify(t1)
            t2 = binascii.unhexlify(public_key)
            '''t3 = t2.decode("utf-8",'ignore')
            t4 = t3.encode()
            t5 = binascii.hexlify(t4)'''
            pkey = str(public_key)
            print ("\nMy Public Key = ",pkey)
            pkey1 = pkey[2:34]
            pkey2 = pkey[34:66]
            print ("\nPartial KEY-1 = ",pkey1)
            print ("\nPartial KEY-2 = ",pkey2)
            #print ("\nPLEN = ",len(pkey))
            if (len(pkey) == 99):
                pkey3 = pkey[66:98]
                pkey4 = '@@@'
                print ("\nPartial KEY-3 = ",pkey3)
                print ("\nPartial KEY-4 = ",pkey4)
            elif (len(pkey) > 98):
                pkey3 = pkey[66:98]
                pkey4 = pkey[98:-1]
                print ("\nPartial KEY-3 = ",pkey3)
                print ("\nPartial KEY-4 = ",pkey4)
            else:
                pkey3 = pkey[66:-1]
                pkey4 = '@@@'
                print ("\nPartial KEY-3 = ",pkey3)
                print ("\nPartial KEY-4 = ",pkey4)
            time_end = time.time()
            print ("\n:::::: KEY GENERATION OVER :::::")
            print ("\nTime Taken For Key Generation = ",(time_end-time_start)*1000," ms\n")
                
        '''if (self.key_gen == 5):
            byte_val = bytes(self.dh_key,"UTF-8")
            print ("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
            print ("\nReceived Public KEY = ",byte_val)
            print ("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
            t2 = binascii.unhexlify(byte_val)
            t3 = t2.decode("utf-8",'ignore')
            y = os.urandom(32)
            A_send = multscalar(y, t3)
            A_send = multscalar(self.a, A_send)
            pkey = str(A_send)
            print ("\nPkey = ",pkey)
            pkey1 = pkey[2:34]
            pkey2 = pkey[34:66]
            print ("\nPKEY-1 = ",pkey1)
            print ("\nPKEY-2 = ",pkey2)
            #print ("\nPLEN = ",len(pkey))
            if (len(pkey) == 99):
                pkey3 = pkey[66:98]
                pkey4 = '@@@'
                print ("\nPKEY-3 = ",pkey3)
                print ("\nPKEY-4 = ",pkey4)
            elif (len(pkey) > 98):
                pkey3 = pkey[66:98]
                pkey4 = pkey[98:-1]
                print ("\nPKEY-3 = ",pkey3)
                print ("\nPKEY-4 = ",pkey4)
            else:
                pkey3 = pkey[66:-1]
                pkey4 = '@@@'
                print ("\nPKEY-3 = ",pkey3)
                print ("\nPKEY-4 = ",pkey4)'''
        
        #time_before_send = time.time()
        #counter = 0
        while True:
            while (self.var==0):
                self.counter = self.counter + 1
                
                if (self.key_gen >= 5):
                    msg_text = 'MSG #' + str(self.counter)
                elif (self.key_gen == 1):
                    print ("\n\n:::::: KEY SHARING STARTED :::::")
                    msg_text = pkey1
                elif (self.key_gen == 2):
                    msg_text = pkey2
                elif (self.key_gen == 3):
                    msg_text = pkey3
                elif (self.key_gen == 4):
                    msg_text = pkey4
                    
                    
                while (len(msg_text)%16 != 0):
                    msg_text = msg_text + ' '
                #print("MSG Length = ",len(msg_text))
                cipher = AES.new(self.key)
                encoded = base64.b64encode(cipher.encrypt(msg_text))
                #print("Length = ",len(encoded))
                lista=list(encoded)
                #lista.insert(0,0)
                #lista.insert(0,0)
                #lista.insert(0,255)
                #lista.insert(0,255)
                #lista.append(0)
                #print("Length = ",len(lista))
                self.write_payload(lista)
                #self.write_payload([255, 255, 0, 0, 57, 90, 54, 118, 106, 71, 75, 51, 87, 75, 107, 79, 99, 55, 76, 122, 112, 65, 86, 88, 79, 81, 61, 61, 0]) # Send INF
                self.set_mode(MODE.TX)
                print ("\n====== SEND: ",msg_text)
                #send_time = time.time() - time_before_send
                #print("Packet ",self.counter," send time = ", time.time(),"s")
                time.sleep(3) # there must be a better solution but sleep() works
                self.reset_ptr_rx()
                self.set_mode(MODE.RXCONT) # Receiver mode
            
                start_time = time.time()
                while (time.time() - start_time < 10): # wait until receive data or 10s
                    pass;
            
            self.var=0
            self.reset_ptr_rx()
            self.set_mode(MODE.RXCONT) # Receiver mode
            time.sleep(10)

lora = mylora(verbose=False)

#     Slow+long range  Bw = 125 kHz, Cr = 4/8, Sf = 4096chips/symbol, CRC on. 13 dBm
lora.set_pa_config(pa_select=1, max_power=21, output_power=15)
lora.set_bw(BW.BW125)
lora.set_coding_rate(CODING_RATE.CR4_8)
lora.set_spreading_factor(12)
lora.set_rx_crc(True)
#lora.set_lna_gain(GAIN.G1)
#lora.set_implicit_header_mode(False)
lora.set_low_data_rate_optim(True)

#  Medium Range  Defaults after init are 434.0MHz, Bw = 125 kHz, Cr = 4/5, Sf = 128chips/symbol, CRC on 13 dBm
#lora.set_pa_config(pa_select=1)


assert(lora.get_agc_auto_on() == 1)

try:
    print ("\n--------------------------------")
    print (":::::: Start SDSMS-LoRa Sender :::::")
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
