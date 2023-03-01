# -*- coding: utf-8 -*-
"""
Created on Thu Dec 22 21:34:02 2022

@author: moham
"""
from globals import *
from User import User
import msvcrt


users = [User("Alice","34223"),  User("Mohamed", "4565645"),User("Bob", "767894")]
generate_mutual_K_for_3(users[0], users[1], users[2])
for i in range (0, len(users)):
   print(f"{users[i].name} mutual key : {users[i].dh_mutual_key}")

print("\n***to exit the program choose (!)***")
while True :

    print("\nSend a message from: ")
    for i in range (0, len(users)):
        print(f"\tchoose ({i + 1}) for {users[i].name}")

    ch = input("\nenter number 1,2,3 : ")
    ch = ord(ch[0])

    if ch == 33:
        break;
    if ch < 49 or ch >= 49 + len(users):
        print("\n**Error input, please try agian\n\n")
    else:
        msg = input('Enter the message that you want to encrypt: \n')
        users[int(ch)- 49].send_msg(msg)
        print(f"\nEncrypted message is : {str_msg['msg']}\n\nSigniture is : {str_msg['signiture']}\n\n")
        for user in users:
            if user!=users[int(ch)- 49]:
             print(f"{user.name} received message : {user.get_msg()}")


    
    