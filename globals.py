from DH_algo import DH_algo as DH
import random as random
BITS = 16    # instead of 32

dh = DH()

public_rabin_keys = {
  
    }

key_msg = {
    'X' : "",#g^ x mod  p
    'X^y' : "",#g ^ xy  mode p
    'signiture' : "",
    'sender' : ""
}

str_msg = {
    'msg' : [],
    'signiture':"",
    'sender' : ""
     }

def generate_mutual_K_for_3(user_1,user_2,user_3):
    user_1.send_key_msg()
    user_2.send_key_msg()
    user_3.send_key_msg()
    user_1.send_key_msg()
    user_2.send_key_msg()
   

# In case that the mutual key generated to be equal to 1, every user generate anouther
# private key to avoid this situation
    while user_1.dh_mutual_key == 1:
        user_1.dh_private_key = dh.generate_private_key(BITS)
        user_2.dh_private_key = dh.generate_private_key(BITS)
        user_3.dh_private_key = dh.generate_private_key(BITS)
        user_1.send_key_msg()
        user_2.send_key_msg()
        user_3.send_key_msg()
        user_1.send_key_msg()
        user_2.send_key_msg()

def foundprine(p,q):
   primes = [i for i in range(p,q) if random.isPrime(i)]
   n = random.choice(primes)
   return n

        