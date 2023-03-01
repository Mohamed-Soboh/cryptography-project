from globals import *
from User import User

import msvcrt
import sys
import tkinter as tk
#dh.generate_p_and_g()
from tkinter import *
users = [User("Alice","12345"),  User("Mohamed", "67891"),User("Bob", "12523")]
generate_mutual_K_for_3(users[0], users[1], users[2])

root = tk.Tk()
root.geometry("800x500")

# Convert the image to a PhotoImage object
root['bg']='black'


#set window color

label2 = Label( root, text = "Building munual key using Diff Hellman:", font=("Arial", 18),bg = 'black',fg='white')
label2.pack()
for i in range (0, len(users)):
    label2 = Label( root, text = f"{users[i].name} mutual key : {users[i].dh_mutual_key}", font=("Arial", 18),bg = 'black',fg='white')
    label2.pack(pady = 0)
label5 = Label( root, text = "Choose one of sender :", font=("Arial", 20),bg = 'black',fg = 'red')
label5.pack()
entertext=Text(root, height = 10, width = 70)
entertext.pack()
entertext.place(x=110,y=200) 
alise = IntVar()
bob=IntVar()
mohamed=IntVar()
al=Checkbutton(root, text="Alise", variable=alise, onvalue=1, offvalue=0,bg = 'white',fg='BLACK')
al.pack(pady=0)
al.place(x=250,y=170)
moh=Checkbutton(root, text="Mohamed", variable=mohamed, onvalue=1, offvalue=0,bg = 'white',fg='BLACK')
moh.pack(pady=0)
moh.place(x=330,y=170)
b=Checkbutton(root, text="bob", variable=bob, onvalue=1, offvalue=0,bg = 'white',fg='BLACK')
b.pack(pady=0)
b.place(x=440,y=170)

def close():
   root.destroy()
   sys.exit()

# Create a Button to call close()
exitb=Button(root, text= "Close the program", font=("Arial",15,"bold"),bg='red', command=close)
exitb.pack(pady=0) 
exitb.place(x=5,y=400)
def submet():
    def closeb():
        b.destroy()
        close()
    if alise.get() == 1:
        users[0].send_msg(entertext.get(1.0, "end-1c"))
        ch=0
    if mohamed.get()==1:
        users[1].send_msg(entertext.get(1.0, "end-1c"))
        ch=1
    if bob.get()==1:
        users[2].send_msg(entertext.get(1.0, "end-1c"))
        ch=2
        
    b = Tk(className='Main')
    b.geometry("1000x500")
    b['bg']='black'
    label2 = Label( b, text = f"Encrypted Message: {str_msg['msg']}\n\nSigniture is : {str_msg['signiture']}\n\n", font=("Arial", 16,"bold"),bg = 'black',fg='white')
    label2.pack(pady = 0) 
    for user in users: 
      if user!=users[ch] :
       label3 = Label( b, text = f"{user.name} received : {user.get_msg()}\n", font=("Arial", 20),bg = 'black',fg='white')
       label3.pack(pady = 0) 
    exitb=Button(b, text= "close", font=("Arial",15,"bold"),bg='red', command=closeb)
    exitb.place(x=5,y=400)
    exitb.pack(pady=0) 
      
sendbutton=Button(root, text= "Send", font=("Arial",15,"bold"),bg='green', command=submet)
sendbutton.pack(pady=0) 
sendbutton.place(x=700,y=400)
root.mainloop()

    
    
