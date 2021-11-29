import socket



s = socket.socket()
print("Socket Created")

s.bind(("localhost", 9999))
s.listen(3)
print("waiting for connection")
while True:
    c, address = s.accept()
    name = c.recv(1024).decode()
    print("Connected with ", address, name)
    c.send(bytes('Welcome to NS', 'utf-8'))
    c.close()



import socket

c = socket.socket()
c.connect(("localhost", 9999))

name = input("Enter your name : ")
c.send(bytes(name, 'utf-8'))

print(c.recv(1024).decode())


