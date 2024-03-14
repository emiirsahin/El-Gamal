import random
import base64
import tkinter as tk
from pathlib import Path

# This is non-changeable and set to 1024 as requested
n = 1024
b = 0
q = 0
# Lines 18-64 are the primality method and its necessities, also in the "primeGenerator" method, a part of the snippet is used.
# Another parameter of note is that for the Miller Rabin primality method, the number of trials -on the snippet- was chosen to be 20,
# which I didn't alter as it provides a moderate amount of security (The probability of a wrong assessment is 2^-40)
# The snippet is from https://www.geeksforgeeks.org/how-to-generate-large-prime-numbers-for-rsa-algorithm/

# Lines 77-82 are also taken from a snippet online, some of the parts in other methods -only about base64 encoding/decoding- are also from snippets online
# The snippet is from https://www.geeksforgeeks.org/encoding-and-decoding-base64-strings-in-python/

first_primes_list = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                     31, 37, 41, 43, 47, 53, 59, 61, 67,
                     71, 73, 79, 83, 89, 97, 101, 103,
                     107, 109, 113, 127, 131, 137, 139,
                     149, 151, 157, 163, 167, 173, 179,
                     181, 191, 193, 197, 199, 211, 223,
                     227, 229, 233, 239, 241, 251, 257,
                     263, 269, 271, 277, 281, 283, 293,
                     307, 311, 313, 317, 331, 337, 347, 349]


def nBitRandom(n):
    return random.randrange(2**(n-1)+1, 2**n - 1)


def getLowLevelPrime(n):
    while True:
        pc = nBitRandom(n)
        for divisor in first_primes_list:
            if pc % divisor == 0 and divisor**2 <= pc:
                break
        else:
            return pc


def isMillerRabinPassed(mrc):
    maxDivisionsByTwo = 0
    ec = mrc-1
    while ec % 2 == 0:
        ec >>= 1
        maxDivisionsByTwo += 1
    assert (2**maxDivisionsByTwo * ec == mrc-1)

    def trialComposite(round_tester):
        if pow(round_tester, ec, mrc) == 1:
            return False
        for i in range(maxDivisionsByTwo):
            if pow(round_tester, 2**i * ec, mrc) == mrc-1:
                return False
        return True

    numberOfRabinTrials = 20
    for i in range(numberOfRabinTrials):
        round_tester = random.randrange(2, mrc)
        if trialComposite(round_tester):
            return False
    return True


# The large prime number is generated and its primality is tested in this method, if the candidate passes the tests, it is returned
def primeGenerator(n):
    while True:
        prime_candidate = getLowLevelPrime(n)
        if not isMillerRabinPassed(prime_candidate):
            continue
        else:
            return prime_candidate


def base64Encoding(m):
    return int.from_bytes(base64.b64encode(m.encode()), "big")
    

def base64Decoding(b):
    return base64.b64decode(b.to_bytes((b.bit_length() + 7) // 8, 'big')).decode()


# GCD checker to ensure the correctness
def gcdCheck(a, b):
    while b != 0:
        a, b = b, a % b
    return not (a-1)


# Key generation method. Large prime, the generator and the secret key for the initiator are generated here. The generator and the
# initiator's secret key are chosen uniformly from their required respective sets as requested. The method returns the public keys
# and the secret key. The secret key is only accessed by the decryption method.
def gen(n):
    global q
    q = primeGenerator(n)
    g = random.randrange(2, q)
    while True:
        global b
        b = random.randrange(1, q)
        if gcdCheck(b, q):
            return (pow(g, b, q), q, g)
        else:
            continue


# The encryption method, takes the message (As is) and the public keys returned by the gen method, generates its own private key, encodes 
# the message with the encoding method, multiplies it with h^k (h is g^b (g is the generator, b is the initiator's secret key) and k is the 
# sender's secret key) then outputs g^k and the encrypted message.
def encryption(m, h, q, g):
    while True:
        k = random.randrange(1, q)
        if gcdCheck(k, q):
            break
        else:
            continue
    p = pow(g, k, q)
    s = pow(h, k, q)
    return (p, base64Encoding(m) * s)


# Takes g^k, the ciphertext, initiator's secret key, and the large prime number as input, divides the ciphertext by p^b (Which is equivalent
# to g^(kb) and g'(kb) is what the sender multiplied the encoded message by) divides the ciphertext by the key, decodes the message with the
# decoding method and returns the result.
def decryption(p, c):
    sprime = pow(p, b, q)
    return base64Decoding(c//sprime)


# Below this line is the implementation of the procedure in which the assignment will be tested and helpers

def checkIfFileExists():
    path = Path("./server.txt")
    return path.is_file()

def createServerFile():
    serverfile =  open("server.txt", "x")
    return serverfile

def deleteServerFile():
    serverfile = Path("server.txt")
    serverfile.unlink()
    return True

def clearServerFile():
    open('server.txt', 'w').close()
    return True

def typeOfDataInServer():
    path = Path("./server.txt")
    serverfile = open("server.txt", "r")
    if path.stat().st_size == 0:
        return 0 # file is empty
    else:
        letter = serverfile.readline()[0]
        if letter == 'Q' or letter == 'H' or letter == 'G':
            return 1 # encryption data in file
        elif letter == 'P' or letter == 'C':
            return 2 # encrypted message and p in file
        else:
            raise Exception("Invalid Content For server.txt")


def sendEncryptionInfo():
    keys = gen(n)
    lines = {"H: " + str(keys[0]), "Q: " + str(keys[1]), "G: " + str(keys[2])}
    with open("server.txt", "w", encoding="ascii") as serverfile:
        serverfile.writelines('\n'.join(lines))
    return True

def encryptSendCiphertext():
    serverfile = open('server.txt', 'r')
    lines = serverfile.readlines()
    message = messageSpace.get()
    for line in lines:
        if line[0] == 'H':
            h = line
        elif line[0] == 'G':
            g = line
        elif line[0] == 'Q':
            q = line
    ciphertext = encryption(message, int(h[2:]), int(q[2:]), int(g[2:]))
    clines = {"P: " + str(ciphertext[0]), "C: " + str(ciphertext[1])}
    open('server.txt', 'w').close()
    with open('server.txt', 'w', encoding="ascii") as serverfile:
        serverfile.writelines('\n'.join(clines))
    return True

def decryptPrintMessage():
    serverfile = open('server.txt', 'r')
    lines = serverfile.readlines()
    for line in lines:
        if line[0] == 'C':
            c = line
        elif line[0] == 'P':
            p = line
    print(decryption(int(p[2:]), int(c[2:])))
    infoSpace.config(text = "The Message Is Decrypted And Printed")
    open('server.txt', 'w').close()
    root.after(5000)  
    return True      
   
# Below is GUI setup
root = tk.Tk()
root.title("ElGamal Assignment Testing Interface")
window_width = 300
window_height = 550

screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()

center_x = int(screen_width/2 - window_width / 2)
center_y = int(screen_height/2 - window_height / 2)

root.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')
root.resizable(False, False)

root.rowconfigure(0, weight=1)
root.rowconfigure(1, weight=1)
root.rowconfigure(2, weight=4)
root.rowconfigure(3, weight=1)
root.rowconfigure(4, weight=1)
root.rowconfigure(5, weight=1)
root.rowconfigure(6, weight=2)

root.columnconfigure(0, weight=1)
root.columnconfigure(1, weight=1)

createSerTxt = tk.Button(
    root,
    text="Create server.txt File",
    relief = "groove",
    command = createServerFile
)

deleteSerTxt = tk.Button(
    root,
    text="Delete server.txt File",
    relief = "groove",
    command = deleteServerFile
)

sendEncInfo = tk.Button(
    root,
    text="Send Encryption Info",
    relief = "groove",
    command = sendEncryptionInfo
)

messageSpace = tk.Entry(
    root,
    text="Write message here",
    relief="solid",
)

encAndSend = tk.Button(
    root,
    text="Encrypt And Send",
    relief="groove",
    command = encryptSendCiphertext
)

decAndSend = tk.Button(
    root,
    text="Decrypt And Send",
    relief="groove",
    command = decryptPrintMessage
)

clearSerTxt = tk.Button(
    root,
    text="Clear server.txt File",
    relief="groove",
    command = clearServerFile
)

infoSpace = tk.Label(
    root,
    text="Info Space",
    relief="solid",
    borderwidth=3
)

createSerTxt.grid(column=0, row=0)
deleteSerTxt.grid(column=1, row=0)
sendEncInfo.grid(column=0, columnspan=2, row=1)
messageSpace.grid(column=0, columnspan=2, row=2)
encAndSend.grid(column=0, columnspan=2, row=3)
decAndSend.grid(column=0, columnspan=2, row=4)
clearSerTxt.grid(column=0, columnspan=2, row=5)
infoSpace.grid(column=0, columnspan=2, row=6)

def update():
    if not checkIfFileExists():
        createSerTxt["state"] = "normal"
        deleteSerTxt["state"] = "disabled"
        sendEncInfo["state"] = "disabled"
        encAndSend["state"] = "disabled"
        decAndSend["state"] = "disabled"
        clearSerTxt["state"] = "disabled"
        infoSpace.config(text = "You must create the server.txt file")
    else:
        createSerTxt["state"] = "disabled"
        deleteSerTxt["state"] = "normal"
        a = typeOfDataInServer()
        if a == 0:
            sendEncInfo["state"] = "normal"
            encAndSend["state"] = "disabled"
            decAndSend["state"] = "disabled"
            infoSpace.config(text = "Send Encryption Data Or Wait And Receive")
        elif a == 1:
            sendEncInfo["state"] = "disabled"
            encAndSend["state"] = "normal"
            decAndSend["state"] = "disabled"
            infoSpace.config(text = "Encryption Data Found, Send Your Message")
        elif a == 2:
            sendEncInfo["state"] = "disabled"
            encAndSend["state"] = "disabled"
            decAndSend["state"] = "normal"
            infoSpace.config(text = "Ciphertext found")
        clearSerTxt["state"] = "normal"
    root.after(5000, update)

update()
root.mainloop()



    
