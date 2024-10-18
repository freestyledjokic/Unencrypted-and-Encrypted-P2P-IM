################################################################################
#
#                       encryptedim.py
#       HW1, part 2: A Simple, Encrypted P2P Instant Messenger
#       Author: Andrej Djokic
#       UTLN: adjoki01
#       Date 03/01/2024
#       Program purpose: P2P Messenger between server and client
#
#
################################################################################

import socket,sys,select,argparse,signal
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256


# Global variables to keep track of opened sockets
open_sockets = []

"""
signal_handler()

Purpose:
        Closes all opened sockets and kills the program

Parameters:
        sig, frame

Return:
        Kills the program
"""
def signal_handler(sig, frame):
        global open_sockets
        while open_sockets:
                sock = open_sockets.pop()
                sock.close()
        sys.exit(0)

"""
parse_arguments()

Purpose:
        Parses command line arguments to determine the mode of operation for the
        program. The program can run in server mode (--s) or client mode 
        (--c <hostname>).

Parameters:
        None

Return:
        argparse.Namespace - An object containing the parsed command line 
        arguments.
"""
def parse_arguments():
        parser = argparse.ArgumentParser(
                description="Process command line arguments")

        # Creating and adding arguments to mutually exclusive group
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument('--s', action='store_true',
                           help='A switch for server option')
        group.add_argument('--c', dest='hostname', type=str,
                           help='A switch for client option')

        # Add arguments for the confidentiality key and authenticity key
        parser.add_argument('--confkey', type=str, required=True,
                            help='Confidentiality key for encryption')
        parser.add_argument('--authkey', type=str, required=True,
                            help='Authenticity key for HMAC')

        args = parser.parse_args()
        # Check if --c is provided but no hostname is given
        if '--c' in sys.argv and not args.hostname:
                parser.error("Hostname required")

        return args

"""
encrypt_with_iv(data, confkey, iv)

Purpose:
        Encrypts the given data using AES in CBC mode with the provided 
        confidentiality key and initialization vector.

Parameters:
        data (bytes): The plaintext data to be encrypted.
        confkey (bytes): The confidentiality key used for AES encryption. Must 
                        be of appropriate length for AES
        iv (bytes): The initialization vector used for AES encryption. Must be 
                        16 bytes long for AES.

Return:
        bytes: The encrypted data, which includes padding according to PKCS#7 
                if necessary.

"""
def encrypt_with_iv(data, confkey, iv):
        # Create an AES cipher in CBC mode with the provided key and IV
        cipher = AES.new(confkey, AES.MODE_CBC, iv)
        # Encrypt the data using the cipher
        encrypted_data = cipher.encrypt(pad(data, AES.block_size))
        return encrypted_data

"""
compute_hmac_SHA256(data, authkey)

Purpose:
        Computes the HMAC of the given data using the SHA-256 hash function and 
                the provided authenticity key.

Parameters:
        data (bytes): The data for which the HMAC is to be computed.
        authkey (bytes): The key used for HMAC computation. 

Return:
        bytes: The computed HMAC as a byte array.

"""
def compute_hmac_SHA256(data, authkey):
        # Compute HMAC
        hmac = HMAC.new(authkey, data, SHA256)
        return hmac.digest()


"""
data_encryption(plaintext, confkey, authkey)

Purpose:
        Encrypts the plaintext message and computes HMACs for both the encrypted
                length and the encrypted message itself, using the provided 
                confidentiality and authenticity keys. The function packages 
                the IV, encrypted length, HMAC of the encrypted length, 
                encrypted message, and HMAC of the encrypted message into a 
                single data package.

Parameters:
        plaintext (str): The plaintext message to be encrypted.
        confkey (bytes): The confidentiality key used for encryption.
        authkey (bytes): The authenticity key used for computing HMACs.

Return:
        bytes: A single data package containing the IV, encrypted length, HMAC 
                of the encrypted length, encrypted message, and HMAC of the 
                encrypted message.
"""
def data_encryption(plaintext, confkey, authkey):
        # Generate IV
        iv = get_random_bytes(16)  # AES block size is 16 bytes

        # Encrypt the length of the message as a 4-byte big-endian integer
        length_bytes = len(plaintext).to_bytes(4, byteorder='big')
        length_encrypted = encrypt_with_iv(length_bytes, confkey, iv)

        # Compute HMAC for iv + encrypted length of the message
        hmac1 = compute_hmac_SHA256(iv + length_encrypted, authkey)

        # Encrypt the actual message using the same IV
        mess_encrypted = encrypt_with_iv(plaintext.encode(), confkey, iv)

        # Compute HMAC for the encrypted message
        hmac2 = compute_hmac_SHA256(mess_encrypted, authkey)

        # Concatenate all parts in the specified order
        packed_data = iv + length_encrypted + hmac1 + mess_encrypted + hmac2
        return packed_data

"""
unpack_data(packed_data):

Purpose:
        Unpacks the given data package into its constituent components: IV, 
                encrypted length, HMAC of the encrypted length, encrypted 
                message, and HMAC of the encrypted message.

Parameters:
        packed_data (bytes): The packed data containing all the components in a
                single byte array.

Return:
        tuple: A tuple containing the IV, encrypted length, HMAC of the encrypted 
                length, encrypted message, and HMAC of the encrypted message
"""
def unpack_data(packed_data):
        # Assuming IV is always 16 bytes and HMAC is always 32 bytes (SHA-256)
        iv_size = 16
        hmac_size = 32
        # The size of the encrypted length is 16 bytes (assuming it's padded to one AES block)
        encrypted_length_size = 16

        # Extract the IV
        iv = packed_data[:iv_size]

        # Extract the encrypted length and its HMAC
        length_encrypted_start = iv_size
        length_encrypted_end = length_encrypted_start + encrypted_length_size
        length_encrypted = packed_data[length_encrypted_start:length_encrypted_end]
        
        hmac1_start = length_encrypted_end
        hmac1_end = hmac1_start + hmac_size
        hmac1 = packed_data[hmac1_start:hmac1_end]

        # Extract the encrypted message and its HMAC
        message_encrypted_start = hmac1_end
        message_encrypted_end = len(packed_data) - hmac_size
        message_encrypted = packed_data[message_encrypted_start:message_encrypted_end]
        
        hmac2 = packed_data[message_encrypted_end:]

        return iv, length_encrypted, hmac1, message_encrypted, hmac2

"""
verify_hmac(data, hmac_to_verify, authkey)

Purpose:
        Verifies that the computed HMAC of the given data matches the provided 
        HMAC, using the SHA-256 hash function and the given authenticity key.

Parameters:
        data (bytes): The data to compute the HMAC of.
        hmac_to_verify (bytes): The HMAC value that is expected after computing 
                the HMAC of the data.
        authkey (bytes): The authenticity key used for HMAC computation.

Return:
        bool: True if the computed HMAC matches the provided HMAC, False otherwise.

"""
def verify_hmac(data, hmac_to_verify, authkey):
        # Compute HMAC for the given data
        computed_hmac = compute_hmac_SHA256(data, authkey)
        # Compare the computed HMAC with the provided one
        return computed_hmac == hmac_to_verify

"""
data_decryption(packed_data, confkey, authkey):
Purpose:
        Decrypts a data package containing an encrypted length and an encrypted 
                message. Verifies the HMACs of both the encrypted length and the
                message before decryption. Requires the same confidentiality and
                authenticity keys used during encryption.

Parameters:
        packed_data (bytes): The data package containing the encrypted length, 
                encrypted message, and their respective HMACs.
        confkey (bytes): The confidentiality key used for decryption.
        authkey (bytes): The authenticity key used for HMAC verification.

Return:
        tuple: A tuple containing a boolean indicating success (True) or failure
                (False), and the decrypted message if successful or an error 
                message if not.

"""
def data_decryption(packed_data, confkey, authkey):
        # Unpack the data
        iv, length_encrypted, hmac1, message_encrypted, hmac2 = unpack_data(packed_data)

        # Verify HMAC for iv + encrypted length
        if not verify_hmac(iv + length_encrypted, hmac1, authkey):
                return False, "ERROR: HMAC verification failed"

        # Verify HMAC for the encrypted message
        if not verify_hmac(message_encrypted, hmac2, authkey):
                return False, "ERROR: HMAC verification failed"
        
        # Decrypt the length
        cipher = AES.new(confkey, AES.MODE_CBC, iv)
        decrypted_length = unpad(cipher.decrypt(length_encrypted), AES.block_size)
        message_length = int.from_bytes(decrypted_length, byteorder='big')
        
        # Decrypt the message
        cipher = AES.new(confkey, AES.MODE_CBC, iv)
        decrypted_message = unpad(cipher.decrypt(message_encrypted), AES.block_size)

        # Ensure the decoded message is of the expected length
        if len(decrypted_message.decode()) != message_length:
                return False, "ERROR: Decrypted message length does not match the expected length"
        
        return True, decrypted_message.decode()

"""
    Helper function to recv n bytes or return None if EOF is hit
"""
def recvall(sock, length):
        data = b''
        while len(data) < length:
                packet = sock.recv(length - len(data))
                if not packet:
                        break # EOF reached, return what we have so far
                data += packet
        return data

"""
run_server()

Purpose:
        The server function initializes and runs the server loop, accepts 
        incoming connections, and handles incoming messages by echoing them to 
        all clients. It also handles server-side input for broadcast messages.

Parameters:
        None

Return:
        None
"""
def run_server(confkey, authkey):
        global open_sockets
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set the SO_REUSEADDR option to allow reusing the port immediately
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        open_sockets.append(server_socket)
        server_socket.bind(('', 9999))
        server_socket.listen(1)

        client_sockets = []

        # Adding sys.stdin to the sockets list with a server_socket
        sockets_list = [server_socket, sys.stdin]

        while True:
                ready_read, _, _ = select.select(sockets_list, [], [])
                for sock in ready_read:
                        if sock is server_socket:
                                conn, addr = server_socket.accept()
                                open_sockets.append(conn)
                                client_sockets.append(conn)
                                sockets_list.append(conn)
                        elif sock is sys.stdin:
                                # Sending a message
                                message = sys.stdin.readline()
                                if message == '':
                                        # If EOF, close all sockets and exit
                                        for client_socket in client_sockets:
                                                open_sockets.remove(client_socket)
                                                client_socket.close()
                                        open_sockets.remove(server_socket)
                                        server_socket.close()
                                        return
                                for client_socket in client_sockets:
                                        # Encrypt the plaintext message to get the packed data
                                        packed_data = data_encryption(message, confkey, authkey)
                                        # Calculate the length of packed_data and convert it to a 4-byte big-endian integer
                                        length_prefix = len(packed_data).to_bytes(4, byteorder='big')
                                        client_socket.send(length_prefix + packed_data)
                        else:
                                # Handling client messages
                                # First, read the length of the incoming message
                                length_data = recvall(sock, 4)
                                if length_data is None:
                                        raise RuntimeError("Socket connection broken")
                                expected_length = int.from_bytes(length_data, byteorder='big')
                                # Receiving the actual package based on the expected length
                                packed_data = recvall(sock, expected_length)
                                if not packed_data:
                                        open_sockets.remove(sock)
                                        client_sockets.remove(sock)
                                        sockets_list.remove(sock)
                                        sock.close()
                                else:
                                        success, decrypted_message = data_decryption(packed_data, confkey, authkey)
                                        if success:
                                                sys.stdout.write("{}".format(decrypted_message))
                                                sys.stdout.flush()
                                                for client_socket in client_sockets:
                                                        # Send to all but the sender
                                                        if client_socket is not sock:
                                                                client_socket.send(packed_data)
                                        else:
                                                # Print the error message to stdout
                                                sys.stdout.write("{}".format(decrypted_message))
                                                sys.stdout.flush()
                                                sys.exit(1)
                                        


"""
run_client(host)

Purpose:
        The client function connects to the server, handles incoming messages by 
        displaying them,and sends user input from standard input to the server.

Parameters:
        host - The hostname or IP address of the server to connect to.

Return:
        None
"""
def run_client(host, confkey, authkey):
        global open_sockets
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        open_sockets.append(client_socket)
        client_socket.connect((host, 9999))
        

        while True:
                read_sockets, _, _ = select.select([client_socket, sys.stdin], 
                                                   [], [])

                for socks in read_sockets:
                        if socks == client_socket:
                                # Receives the message
                                # First, read the length of the incoming message
                                length_data = recvall(socks, 4)
                                if length_data is None:
                                        raise RuntimeError("Socket connection broken")
                                expected_length = int.from_bytes(length_data, byteorder='big')
                                # Receiving the actual package based on the expected length
                                packed_data = recvall(socks, expected_length)
                                if packed_data:
                                        success, decrypted_message = data_decryption(packed_data, confkey, authkey)
                                        if success:
                                                sys.stdout.write("{}".format(decrypted_message))
                                                sys.stdout.flush()
                                        else:
                                                # Print the error message to stdout
                                                sys.stdout.write("{}".format(decrypted_message))
                                                sys.stdout.flush()
                                                sys.exit(1)
                                else:
                                        open_sockets.remove(client_socket)
                                        client_socket.close()
                                        return
                        elif socks == sys.stdin:
                                # Read and send the input to server
                                message = sys.stdin.readline()
                                if message == '':
                                        open_sockets.remove(client_socket)
                                        client_socket.close()
                                        return
                                # Encrypt the plaintext message to get the packed data
                                packed_data = data_encryption(message, confkey, authkey)
                                # Calculate the length of packed_data and convert it to a 4-byte big-endian integer
                                length_prefix = len(packed_data).to_bytes(4, byteorder='big')
                                client_socket.sendall(length_prefix + packed_data)
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

        # Hash the keys using SHA-256 regardless of their initial length
        confkey_hashed = SHA256.new(args.confkey.encode()).digest()
        authkey_hashed = SHA256.new(args.authkey.encode()).digest()

        if args.s:
                run_server(confkey_hashed, authkey_hashed)
        elif args.hostname:
                run_client(args.hostname, confkey_hashed, authkey_hashed)


if __name__ == "__main__":
        signal.signal(signal.SIGINT, signal_handler)
        main()
