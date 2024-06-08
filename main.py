import socket
import threading
import select

PROXY_HOST = '127.0.0.1'
PROXY_PORT = 8989

FORBIDDEN_HOSTS_FILE = 'forbidden-hosts.txt'
BANNED_WORDS_FILE = 'banned-words.txt'
LOG_FILE = 'proxy.log'

# Функция для загрузки запрещенных доменов из файла
def load_forbidden_hosts():
    # Открываем файл, указанный в переменной FORBIDDEN_HOSTS_FILE, в режиме чтения
    with open(FORBIDDEN_HOSTS_FILE, 'r') as f:
        # Считываем строки из файла, удаляем лишние пробелы и создаем множество
        return set(line.strip() for line in f)

# Функция для загрузки запрещенных слов из файла
def load_banned_words():
    # Открываем файл, указанный в переменной BANNED_WORDS_FILE, в режиме чтения
    with open(BANNED_WORDS_FILE, 'r') as f:
        # Считываем строки из файла, приводим их к нижнему регистру и создаем множество
        return set(line.strip().lower() for line in f)

# Загружаем запрещенные домены и слова в соответствующие переменные
FORBIDDEN_HOSTS = load_forbidden_hosts()
BANNED_WORDS = load_banned_words()

# Функция для логирования запросов
def log_request(client_addr, request_url, response_code):
    # Открываем файл, указанный в переменной LOG_FILE, в режиме добавления
    with open(LOG_FILE, 'a') as f:
        # Записываем в файл информацию о запросе, включая адрес клиента, URL запроса и код ответа
        f.write(f"{client_addr} Request URL: {request_url} Response: {response_code}\n")

# Функция для обработки подключения клиента
def handle_client(client_socket, client_addr):
    try:
        # Получаем запрос от клиента (максимум 4096 байт) и декодируем его из байтового представления в строку
        request = client_socket.recv(4096).decode('utf-8')
        if not request:
            return  # Если запрос пустой, завершаем обработку

        # Разделяем запрос на строки
        request_lines = request.split('\n')
        # Получаем первую строку запроса (например, "GET http://example.com HTTP/1.1")
        first_line = request_lines[0]
        # Разделяем первую строку на метод, URL и версию протокола
        method, url, _ = first_line.split()

        # Если метод запроса CONNECT, обрабатываем HTTPS запрос
        if method == 'CONNECT':
            handle_https(client_socket, client_addr, url)
        else:
            # В противном случае обрабатываем HTTP запрос
            handle_http(client_socket, client_addr, request, url)
    except Exception as e:
        # В случае возникновения ошибки выводим сообщение об ошибке
        print(f"Error handling client {client_addr}: {e}")
    finally:
        # Закрываем сокет клиента в любом случае (успешная обработка или ошибка)
        client_socket.close()

def handle_http(client_socket, client_addr, request, url):
    try:
        # Парсим первую строку запроса для получения метода, URL и версии протокола
        method, url, version = request.split('\n')[0].split()
        # Находим строку с заголовком Host
        host_header = next((line for line in request.split('\n') if line.lower().startswith('host:')), None)
        # Если заголовок Host найден, извлекаем имя хоста, иначе используем хост из URL
        host = host_header.split(':')[1].strip() if host_header else url.split('/')[2]

        # Проверка, находится ли хост в списке запрещенных
        if host in FORBIDDEN_HOSTS:
            # Формируем ответ с кодом 403 Forbidden
            response = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 34\r\n\r\nWebsite not allowed: {}\r\n".format(host)
            # Отправляем ответ клиенту
            client_socket.send(response.encode('utf-8'))
            # Логируем запрос
            log_request(client_addr, url, '403 Forbidden')
            return

        # Создаем сокет для соединения с целевым сервером
        webserver = host.split(':')[0]
        port = int(host.split(':')[1]) if ':' in host else 80

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy_socket:
            # Устанавливаем соединение с целевым сервером
            proxy_socket.connect((webserver, port))
            # Отправляем запрос целевому серверу
            proxy_socket.sendall(request.encode('utf-8'))

            while True:
                # Получаем ответ от целевого сервера
                response = proxy_socket.recv(4096)
                if not response:
                    break
                # Проверяем ответ на наличие запрещенных слов
                for word in BANNED_WORDS:
                    if word.encode('utf-8') in response.lower():
                        # Если найдено запрещенное слово, формируем ответ с кодом 403 Forbidden
                        forbidden_response = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 43\r\n\r\nWebsite content not allowed.\r\n"
                        # Отправляем ответ клиенту
                        client_socket.send(forbidden_response.encode('utf-8'))
                        # Логируем запрос
                        log_request(client_addr, url, '403 Forbidden')
                        return

                # Отправляем ответ клиенту
                client_socket.sendall(response)

        # Логируем успешный запрос
        log_request(client_addr, url, '200 OK')
    except Exception as e:
        # Обработка ошибок и вывод сообщения об ошибке
        print(f"Error handling HTTP request for {client_addr}: {e}")

def handle_https(client_socket, client_addr, url):
    try:
        # Парсим URL для получения веб-сервера и порта
        webserver, port = url.split(':')
        port = int(port)

        # Создаем сокет для соединения с целевым сервером
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy_socket:
            # Устанавливаем соединение с целевым сервером
            proxy_socket.connect((webserver, port))
            # Отправляем клиенту ответ о том, что соединение установлено
            response = "HTTP/1.1 200 Connection Established\r\n\r\n"
            client_socket.sendall(response.encode('utf-8'))

            # Устанавливаем неблокирующий режим для обоих сокетов
            client_socket.setblocking(0)
            proxy_socket.setblocking(0)

            while True:
                # Используем select для ожидания активности на любом из сокетов
                read_sockets, _, error_sockets = select.select([client_socket, proxy_socket], [], [client_socket, proxy_socket], 1)
                if error_sockets:
                    # Если произошла ошибка, выходим из цикла
                    break
                if client_socket in read_sockets:
                    # Если данные пришли от клиента, читаем их
                    data = client_socket.recv(4096)
                    if not data:
                        # Если данных нет, выходим из цикла
                        break
                    # Пересылаем данные целевому серверу
                    proxy_socket.sendall(data)
                if proxy_socket in read_sockets:
                    # Если данные пришли от целевого сервера, читаем их
                    data = proxy_socket.recv(4096)
                    if not data:
                        # Если данных нет, выходим из цикла
                        break
                    # Пересылаем данные клиенту
                    client_socket.sendall(data)

        # Логируем успешный запрос
        log_request(client_addr, url, '200 OK')
    except Exception as e:
        # Обработка ошибок и вывод сообщения об ошибке
        print(f"Error handling HTTPS request for {client_addr}: {e}")

def start_proxy():
    # Создание сокета для прокси-сервера
    proxy_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Привязка сокета к указанному хосту и порту
    proxy_server.bind((PROXY_HOST, PROXY_PORT))
    # Перевод сокета в режим прослушивания с очередью на 5 подключений
    proxy_server.listen(5)
    print(f"Starting proxy server on {PROXY_HOST}:{PROXY_PORT}")

    while True:
        # Ожидание нового подключения
        client_socket, addr = proxy_server.accept()
        print(f"Request made. Target: {addr}")
        # Создание нового потока для обработки подключения клиента
        client_handler = threading.Thread(target=handle_client, args=(client_socket, addr))
        # Запуск потока
        client_handler.start()

if __name__ == "__main__":
    # Запуск функции start_proxy при выполнении скрипта
    start_proxy()

