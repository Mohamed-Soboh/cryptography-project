# -*- coding: utf-8 -*-
"""
Created on Sat Dec 17 19:17:20 2022

@author: moham
"""

from globals import *
from datetime import datetime
from Rabin_signature import create_signiture, generate_keys, hash_func,verify_rabin
import sys
from camellia import encrypte ,decrypte
import binascii
class User:
    	
    def __init__(self, name, id):

        self.dh_private_key = dh.generate_private_key(BITS)
        self.name = name
        self.id = id
        self.dh_mutual_key = 1
        self.index = f"{name}-{id}"
        public_rabin_keys[self.index] = generate_keys()
        self.private_rabin_p_q=public_rabin_keys[self.index]
        print("name: "+self.name+" "+"ID: "+self.id)
        
        
    def send_key_msg(self):


            if (key_msg['X^y'] != ""):
                self.dh_mutual_key = dh.get_mutual_K(key_msg['X^y'], self.dh_private_key)

            if (key_msg['X'] != ""):
                key_msg['X^y'] = dh.get_mutual_K(key_msg['X'], self.dh_private_key)

            key_msg['X'] = dh.get_my_public(self.dh_private_key)#g^key mod p
            string=str(key_msg['X']) + str(key_msg['X^y'])
            key_msg['signiture'] = create_signiture( self.private_rabin_p_q,binascii.hexlify(string.encode()))

            key_msg['sender'] = self.index

    def send_msg(self, msg):
       
          str_msg['msg'] = encrypte(msg, self.dh_mutual_key )
          str_msg['signiture'] = create_signiture( self.private_rabin_p_q,binascii.hexlify(msg.encode()))
          str_msg['sender'] = self.index
          
          
    def get_msg(self):

        orig_msg = decrypte(str_msg['msg'],  self.dh_mutual_key)
        message=orig_msg.decode('utf-8')
        hexmessage = binascii.hexlify(message.encode()) 
        boolean=verify_rabin(public_rabin_keys[str_msg['sender']],hexmessage, str_msg['signiture'])
        if boolean==True:
            string="from "+str_msg['sender']+" at "+datetime.now().strftime("%H:%M:%S")+" "+message
            return string

        return {'from' : 'Unknown' , 'msg' : ''}      