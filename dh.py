################################################################################
#
#                               dh.py
#       HW1, part 3: Diffie-Hellman Key Exchange
#       Author: Andrej Djokic
#       UTLN: adjoki01
#       Date 03/24/2024
#       Program purpose: Performs Diffie-Hellman Key Exchange over a network
#
#
################################################################################

import socket,sys,select,argparse,signal,random
from random import randint

# Global variables to keep track of opened sockets and DH parameters
open_sockets = []
g = 2
p = 0x00cc81ea8157352a9e9a318aac4e33ffba80fc8da3373fb44895109e4c3ff6cedcc55c02228fccbd551a504feb4346d2aef47053311ceaba95f6c540b967b9409e9f0502e598cfc71327c5a455e2e807bede1e0b7d23fbea054b951ca964eaecae7ba842ba1fc6818c453bf19eb9c5c86e723e69a210d4b72561cab97b3fb3060b

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

        args = parser.parse_args()
        # Check if --c is provided but no hostname is given
        if '--c' in sys.argv and not args.hostname:
                parser.error("Hostname required")

        return args


"""
run_server()

Purpose:
        The server function initializes and runs the server, accepts incoming 
        connection, performs the Diffie-Hellman key exchange with a connected 
        client, and prints the shared secret key.

Parameters:
        None

Return:
        None
"""
def run_server():
        global open_sockets
        server_socket = None
        connected_socket = None
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Set the SO_REUSEADDR option to allow reusing the port immediately
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            open_sockets.append(server_socket)
            server_socket.bind(('', 9999))
            server_socket.listen(1)

            connected_socket, address = server_socket.accept()
            open_sockets.append(connected_socket)

            # Generate server's private key b and compute B
            b = random.randint(1, p - 1)
            B = pow(g, b, p)
            
            # Send B to the client
            connected_socket.send(bytes(str(B) + '\n', 'utf-8'))
            
            # Receive A from the client
            A = int(connected_socket.recv(1024).decode())
            
            # Compute the shared secret key
            K = pow(A, b, p)
            print(K)
        
        except socket.error as e:
            print(f"Socket error: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            if connected_socket:
                open_sockets.remove(connected_socket)
                connected_socket.close()
            if server_socket:
                open_sockets.remove(server_socket)
                server_socket.close()



"""
run_client(host)

Purpose:
        The client function connects to the server, performs the Diffie-Hellman 
        key exchange, and prints the shared secret key.

Parameters:
        host - The hostname or IP address of the server to connect to.

Return:
        None
"""
def run_client(host):
        global open_sockets
        connected_socket = None
        try:
            connected_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            open_sockets.append(connected_socket)
            connected_socket.connect((host, 9999))

            a = randint(1, p-1)
            A = pow(g, a, p)

            # Send 'A' to the server
            connected_socket.send(bytes(str(A) + '\n', 'utf-8'))

            # Receive 'B' from the server
            B = int(connected_socket.recv(1024).decode())

            # Compute the shared secret key
            K = pow(B, a, p)            
            print(K)

        
        except socket.error as e:
            print(f"Socket error: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            if connected_socket:
                open_sockets.remove(connected_socket)
                connected_socket.close()


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

        if args.s:
                run_server()
        elif args.hostname:
                run_client(args.hostname)


if __name__ == "__main__":
        signal.signal(signal.SIGINT, signal_handler)
        main()
