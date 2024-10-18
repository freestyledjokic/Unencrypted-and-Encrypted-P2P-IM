################################################################################
#
#                              signer.py
#       HW1, Part 3: Signed Messages
#       Author: Andrej Djokic
#       UTLN: adjoki01
#       Date 03/27/2024
#       Program purpose: Generate an RSA keypair, write the public key to a file
#                        and send a signed message over a network.
#
#
################################################################################
import socket,sys,select,argparse,signal,binascii
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


"""
parse_arguments()

Purpose:
        Parses command line arguments to determine the mode of operation for the
        program. The program can generate a new RSA keypair (--genkey) or send a 
        signed message (--c <hostname> --m <message>).

Parameters:
        None

Return:
        argparse.Namespace - An object containing the parsed command line 
        arguments.
"""
def parse_arguments():
        parser = argparse.ArgumentParser(
                description="Process command line arguments")

        # Creating and adding arguments
        parser.add_argument('--genkey', action='store_true',
                           help='Generate a new RSA keypair and save the public key to the file')
        parser.add_argument('--c', dest='hostname', type=str,
                        help='Hostname to send the signed message to')
        parser.add_argument('--m', dest='message', type=str,
                        help='Message to be signed and sent')

        args = parser.parse_args()
        
        # Check for the proper combination of arguments
        if args.genkey:
            if args.hostname or args.message:
                parser.error("When using --genkey, do not provide --c or --m")
        else:
            if not args.hostname or not args.message:
                parser.error("--c and --m must both be provided together")

        return args

"""
generate_rsa_key()

Purpose:
        Generates an RSA keypair and writes the public part of the key to a file.

Parameters:
        None

Return:
        The generated RSA keypair.
"""
def generate_RSA_key():
        key = RSA.generate(4096)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        # Write the private key to a file
        with open('privkey.pem', 'wb') as priv_f:
            priv_f.write(private_key)

        # Write the public key to a file
        with open('mypubkey.pem', 'wb') as pub_f:
            pub_f.write(public_key)

        return key

"""
sign_message(message)

Purpose:
        Signs the given message with the provided RSA private key.

Parameters:
        key: The RSA keypair containing the private key.
        message: The message to sign.

Return:
        The signature of the message.
"""
def sign_message(message):
        # Read the private key from file
        with open('privkey.pem', 'rb') as priv_f:
            private_key = RSA.import_key(priv_f.read())

        # Hash the message
        h = SHA256.new(message.encode())
        
        # Sign the message
        signature = pkcs1_15.new(private_key).sign(h)
        return signature

"""
mypadding()

Purpose:
        Generates a 4-character string representing the given number, padded 
        with leading zeros if necessary to ensure the string is 4 characters long.

Parameters:
        num: An integer number to be converted into a 4-character padded string.

Return:
        A string of length 4, containing the decimal representation of `num` 
        left-padded with zeros.
"""
def mypadding(num):
        return '0' * (4 - len(str(num))) + str(num)

"""
format_message()

Purpose:
        Formats a message to be sent over the network. The message format includes
        the length of the message in a 4-byte padded string, the message itself,
        and the hex representation of the message signature.

Parameters:
        message: The original message to be sent as a string.
        signature: The byte string of the message's signature.

Return:
        formatted_message: A byte string ready to be sent over the network, 
        containing the length, the original message, and the hex signature.
"""
def format_message(message, signature):
        message_bytes = message.encode()
        # Convert signature to hex
        signature_hex = binascii.hexlify(signature)
        # Convert length to bytes
        message_length = mypadding(len(message_bytes)).encode()
        signature_length = mypadding(len(signature_hex)).encode()
        formatted_message = message_length + message_bytes + signature_length + signature_hex
        return formatted_message

"""
send_message(hostname, formatted_message))

Purpose:
        Establishes a TCP connection to the given hostname on port 9998 and sends
        a formatted message. The function assumes that the message is properly 
        formatted according to the protocol (length, message, and signature).

Parameters:
        hostname: A string representing the IP address or domain of the server 
                  to which the message will be sent.
        formatted_message: A byte string of the message that includes the message
                           length, the message itself, and the signature.

Return:
        None
"""
def send_message(hostname, formatted_message):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((hostname, 9998))
        s.send(formatted_message)
        s.close()

"""
main

Purpose:
        Acts as the entry point of the program. Based on the parsed arguments, 
        it either starts the server or connects to a server as a client.

Parameters:
        None

Return:
        None
"""
def main():
        args = parse_arguments()

        if args.genkey:
                key = generate_RSA_key()
                return
        else:
                with open('mypubkey.pem', 'rb') as f:
                       key = RSA.import_key(f.read())
        
        if args.hostname and args.message:
            # Sign the message
            signature = sign_message(args.message)
            # Format the message with the signature
            formatted_message = format_message(args.message, signature)
            # Send the formatted message
            send_message(args.hostname, formatted_message)
        else:
            print("Error: Invalid command line arguments.")



if __name__ == "__main__":
        main()
