# Created on iPad Pro

import random
import sympy


# mathy portion
def gcd(a, b):
    if a == 0:
        return b
    return gcd(b%a, a)



def multiplicative_inverse(e, phi):
    d = 0
    x1 = 0
    x2 = 1
    y1 = 1
    tphi = phi

    while e > 0:
        t1 = tphi // e
        t2 = tphi - t1 * e
        tphi = e
        e = t2

        x = x2 - t1 * x1
        y = d - t1 * y1

        x2 = x1
        x1 = x
        d = y1
        y1 = y

    if tphi == 1:
        return d + phi



def generate_key_pair(p, q):
    if not (sympy.isprime(p) and sympy.isprime(q)):
        raise ValueError("One or more values not prime")
    elif p == q:
        raise ValueError("Values p and q are equivalent")
    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randrange(1, phi)
    g = gcd(e, phi)

    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)
    
    d = multiplicative_inverse(e, phi)
    
    return ((e, n), (d, n))



def encrypt(pk, plaintext):
    key, n = pk
    cipher = [pow(ord(char), key, n) for char in plaintext]
    return cipher



def decrypt(pk, ciphertext):
    key, n = pk
    byte_arr = [str(pow(int(char), key, n)) for char in ciphertext]
    plaintext = [chr(int(char2)) for char2 in byte_arr]
    return ''.join(plaintext)


# ui portion
if __name__ == "__main__":
    print("====================== RSA ENCRYPTION ======================\n")

    p = int(input("Enter a prime number: "))
    q = int(input("Enter another, different prime: "))

    public, private = generate_key_pair(p, q)

    print("\nPublic key:",public,"\nPrivate key:",private)

    while 1 > 0:
        user_def = input(
            "\nDo you want to encrypt, decrypt,\nregenerate your keypair, set a\nnew keypair, or stop the program?: "
        ).lower().translate( {
            ord(letter): None
            for letter in ' .'
        } )



        if user_def == "stop":
            break
        


        elif "regen" in user_def:
            p = int(input("Enter a prime number: "))
            q = int(input("Enter another, different prime: "))

            public, private = generate_key_pair(p, q)

            print("\nPublic key:",public,"\nPrivate key:",private)



        elif "set" in user_def:
            print("NOTE: Only to encrypt/decrypt existing messages\nwhich require different keys. Will not\nfunction properly if not followed.\n")
            public = tuple([int(value) for value in
                input("Set public key: ").translate( {
                    ord(letter): None
                    for letter in ',()'
                } ).split()
            ])

            private = tuple([int(value) for value in
                input("Set private key: ").translate( {
                    ord(letter): None
                    for letter in ',()'
                } ).split()
            ])

            print("\nPublic key:",public,"\nPrivate key:",private)



        elif user_def == "encrypt":
            msg = input("\nEnter a message to encrypt: ")
            encrypted_msg = encrypt(public, msg)
            print("Encrypted message:", ''.join(map(lambda x: str(x), encrypted_msg)),"\nArray form:",encrypted_msg)



        elif user_def == "decrypt":
            msg = [int(value) for value in input(
                "Enter the decrypted message in array form\n(with or without commas/square brackets): "
            ).translate( {
                ord(letter): None
                for letter in ',[]'
            } ).split()]
            print("Decrypted message:",decrypt(private, msg))



        else:
            raise Exception("Command not found. Relaunch program.")