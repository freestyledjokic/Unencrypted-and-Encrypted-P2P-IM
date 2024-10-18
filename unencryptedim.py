################################################################################
#
#                       unencryptedim.py
#       HW1, part 1: A Simple, Unencrypted P2P Instant Messenger
#       Author: Andrej Djokic
#       UTLN: adjoki01
#       Date 01/27/2024
#       Program purpose: P2P Messenger between server and client
#
#
################################################################################

import socket,sys,select,argparse,signal

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

        args = parser.parse_args()
        # Check if --c is provided but no hostname is given
        if '--c' in sys.argv and not args.hostname:
                parser.error("Hostname required")

        return args

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
def run_server():
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
                                        client_socket.send(message.encode())
                        else:
                                # Handling client messages
                                data = sock.recv(1024)
                                if not data:
                                        open_sockets.remove(sock)
                                        client_sockets.remove(sock)
                                        sockets_list.remove(sock)
                                        sock.close()
                                else:
                                        sys.stdout.write("{}".format(
                                                                data.decode()))
                                        sys.stdout.flush()
                                        for client_socket in client_sockets:
                                                # Send to all but the sender
                                                if client_socket is not sock:
                                                        client_socket.send(data)


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
def run_client(host):
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
                                message = socks.recv(1024)
                                if message:
                                        sys.stdout.write("{}".format(
                                                        message.decode()))
                                        sys.stdout.flush()
                                else:
                                        open_sockets.remove(client_socket)
                                        client_socket.close()
                                        return
                        elif socks == sys.stdin:
                                # Read and send the input to server
                                mess = sys.stdin.readline()
                                if mess == '':
                                        open_sockets.remove(client_socket)
                                        client_socket.close()
                                        return
                                client_socket.sendall(mess.encode())

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
