import nmap
import psutil
import time
import paramiko
import re
from scapy.all import IP, ICMP, sr1, conf
import csv
import os
from colorama import init, Fore, Back, Style
import logging
from logging.handlers import RotatingFileHandler
import speedtest

def mostrar_menu():
    print(Fore.CYAN + Style.DIM +  ''' 

                                   _
                              ==(W{==========-      /===-
                                ||  (.--.)         /===-_---~~~~~~~----__
                                | \_,|**|,__      |===-~___            _,-'`                            
                   -==\ \        `\ ' `--'   ),    `//~\ \ ~~~~`--._.-~
               ______-==|        /`\_. .__/\ \    | |  \ \         _-~`
         __--~~~  ,-/-==\ \      (   | .  |~~~~|   | |   `\       ,'
      _-~       /'    |  \ \     )__/==0==-\<>/   / /      \     /                              __________           .______________              __  .__                
    .'        /       |   \       /~\___/~~\/  /' /        \   /                                \______   \ ____   __| _/\__    ___/___   _______/  |_|__| ____    ____  
   /  ____  /         |    \`\.__/-~~   \  |_/'  /          \/'                                   |       _// __ \ / __ |   |    |_/ __ \ /  ___/\   __\  |/    \  / ___\ 
  /-'~    ~~~~~---__  |     ~-/~         ( )   /'        _--~`                                    |    |   \  ___// /_/ |   |    |\  ___/ \___ \  |  | |  |   |  \/ /_/  >
                    \_|      /        _) | ;  ),   __--~~                                         |____|_  /\___  >____ |   |____| \___  >____  > |__| |__|___|  /\___  / 
                      '~~--_/      _-~/- |/ \   '-~ \                                                    \/     \/     \/              \/     \/               \//_____/  
                     {\__--_/}    /\ \_>-|)<__\      \ 
                     /'   (_/  _-~  | |__>--<__|      |
                    |   _/) )-~     | |__>--<__|      |                                             Conjunto de herramientas destinadas a la monitorización de redes
                    / /~ ,_/       / /__>---<__/      |
                   o-o _//        /-~_>---<__-~      /                                                        TFG Administración de Sistemas y Redes
                   (^(~          /~_>---<__-      _-~
                  ,/|           /__>--<__/     _-~
               ,//('(          |__>--<__|     /                  .--_
              ( ( '))          |__>--<__|    |                 /' _-_~\ 
           `-)) )) (           |__>--<__|    |               /'  /   ~\`\ 
          ,/,'//( (             \__>--<__\    \            /'  //      ||
        ,( ( ((, ))              ~-__>--<_~-_  ~--__---~'/'/  /'       VV
      `~/  )` ) ,/|                 ~-_~>--<_/-__      __-~ _/
    ._-~//( )/ )) `                    ~~-'_/_/ /~~~~~__--~                                                                             Herramienta creada por Carlos Guerrero
     ;'( ')/ ,)(                              ~~~~~~~~                                                                                                               
    ' ') '( (/

''')
    print(Fore.RED + "[1] " + Fore.GREEN + "Listado de Dipositivos de red")
    print(Fore.RED + "[2] " + Fore.GREEN + "Comprobar dispositivos")
    print(Fore.RED + "[3] " + Fore.GREEN + "Ancho de banda y velocidad de internet")
    print(Fore.RED + "[4] " + Fore.GREEN + "Acceso a dispositivos por SSH")
    print(Fore.RED + "[5] " + Fore.GREEN + "Uso de recursos")
    print(Fore.RED + "[6] "+ Fore.GREEN + "Salir")

def main():

    logger = configurar_logger('Main', 'log.txt')

    while True:
        mostrar_menu()
        opcion = input("Seleccione una opción: ")

        if opcion == "1":
            registrar_log(logger, 'INFO', 'Acceso a listar dispositivos')
            listar_dispositivos_red()
        elif opcion == "2":
            registrar_log(logger, 'INFO', 'Acceso a comprobar dispositivos')
            comprobar_dispositivos()
        elif opcion == "3":
            registrar_log(logger, 'INFO', 'Acceso a medición de ancho de banda')
            rendimiento_de_red()
        elif opcion == "4":
            registrar_log(logger, 'INFO', 'Acceso a sesion ssh')
            abrir_sesion_ssh()
        elif opcion == "5":
                registrar_log(logger, 'INFO', 'Acceso a obtener recursos')
                datos = obtener_datos_remotos()         
        elif opcion == "6":
            registrar_log(logger, 'INFO', 'Saliendo de la aplicación')
            print("Saliendo de la aplicación.")
            break
        else:
            registrar_log(logger, 'ERROR', 'No se ha completado el acceso debido a una opción no válida')
            print("Opción no válida. Por favor, seleccione una opción válida.")



def listar_dispositivos_red():

    logger = configurar_logger('Listar Dispositivos', 'log.txt')

    ip = input("¿Sobre que dirección de red quiere hacer el escaneo (IP)?: ")
    mask = input("¿Que máscara tiene la red?: ")

    log_res= "Haciendo escaneo a " + ip + "/" + mask

    registrar_log(logger, 'INFO', log_res)

    ip_red = ip + "/" + mask

    if validar_ip(ip):
        print("La dirección IP es válida.")
        registrar_log(logger, 'INFO', 'Direccion IP válida')
    else:
        print ("La dirección IP no es válida, introduzca una IP válida")
        registrar_log(logger, 'ERROR', 'Dirección IP no válida')
        listar_dispositivos_red()

    scanner = nmap.PortScanner()

    respuesta = input("¿Quiere realizar el escaneo a algún puerto o puertos específicos?[y/n]")
    
    if respuesta == "y":
        puertos = "-p"+ input("¿Que puerto/s quiere escanear?")
        print(puertos)
        scanner.scan(ip_red, arguments=puertos)
    else:
        scanner.scan(ip_red, arguments='-sn')

    dispositivos = []
    for host in scanner.all_hosts():
        dispositivos.append({
            'ip': host,
            'hostname': scanner[host].hostname(),
            'estado': scanner[host].state()
        })

    print(dispositivos)
    print("Dispositivos en la red:")
    for dispositivo in dispositivos:
        print(f"Ip: {dispositivo['ip']}, Hostname: {dispositivo['hostname']}, Estado: {dispositivo['estado']}")
    time.sleep(3)

def obtener_informacion_dispositivo(ip):
    scanner = nmap.PortScanner()
    scanner.scan(ip)
    if ip in scanner.all_hosts():
        return scanner[ip]
    return None

def comprobar_dispositivos():

    logger = configurar_logger('Comprobar Dispositivos', 'log.txt')

    opcion = input("¿Quiere usar un archivo CSV para comprobar varios dispositivos? [y/n]: ")

    if opcion == "y":
        registrar_log(logger, 'INFO', 'Usando archivo CSV')
        archivos = os.listdir(os.getcwd())
        print("Archivos CSV disponibles:")
        for archivo in archivos:
            if archivo.endswith('.csv'):
                print(archivo)
        opcion2 = input("¿Que archivo quiere usar?: ")

        log_res = "Usando " + opcion2
        registrar_log(logger, 'INFO', log_res)

        datos = []
        with open(opcion2, newline='') as archivo_csv:
            lector_csv = csv.reader(archivo_csv)
            for fila in lector_csv:
                for elemento in fila:
                    datos.append(elemento)
        for i in range(len(datos)):
            ip = datos[i]
            paquete = IP(dst=ip) / ICMP()
            respuesta = sr1(paquete, timeout=5, verbose=False)
            if respuesta:
                print(f"Respuesta recibida desde: {ip}")
                info = obtener_informacion_dispositivo(ip)
                if info:
                    print(f"Información adicional del dispositivo {ip}:")
                    print(f"Hostname: {info.hostname()}")
                    print(f"Estado: {info.state()}")
                    for proto in info.all_protocols():
                        print(f"Protocolo: {proto}")
                        lport = info[proto].keys()
                        for port in lport:
                            print(f"Puerto: {port}, Estado: {info[proto][port]['state']}")
                else: print("No hay información adicional del dispositivo")
            else:
                print(f"No se recibió respuesta desde {ip}")
    else:
        registrar_log(logger, 'INFO', 'Comprobación sin CSV')
        ip = input("Que dispositivo quiere comprobar: ")
        paquete = IP(dst=ip) / ICMP()

        respuesta = sr1(paquete, timeout=2, verbose=False)

        if respuesta:
            print(f"Respuesta recibida desde {ip}.")
            info = obtener_informacion_dispositivo(ip)
            if info:
                print(f"Información adicional del dispositivo {ip}:")
                print(f"Hostname: {info.hostname()}")
                print(f"Estado: {info.state()}")
                for proto in info.all_protocols():
                    print(f"Protocolo: {proto}")
                    lport = info[proto].keys()
                    for port in lport:
                        print(f"Puerto: {port}, Estado: {info[proto][port]['state']}")
            time.sleep(3)
        else:
            print(f"No se recibió respuesta desde {ip}.")
            time.sleep(3)


def validar_ip(ip):
    patron_ip = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    if re.match(patron_ip, ip):
        partes = ip.split('.')
        if all(0 <= int(p) < 256 for p in partes):
            return True
    return False

def rendimiento_de_red():

    def medir_ancho_de_banda(intervalo = 10):

        logger = configurar_logger('Ancho de banda', 'log.txt')

        net_io_inicio = psutil.net_io_counters()

        time.sleep(intervalo) 

        net_io_final = psutil.net_io_counters()

        bytes_enviados = net_io_final.bytes_sent - net_io_inicio.bytes_sent
        bytes_recibidos = net_io_final.bytes_recv - net_io_inicio.bytes_recv

        bps_enviados = bytes_enviados * 8 / intervalo
        bps_recibidos = bytes_recibidos * 8 / intervalo

        mbps_enviados = bps_enviados / 1e6
        mbps_recibidos = bps_recibidos / 1e6

        print(f"Velocidad de envío: {mbps_enviados} Mbps")
        print(f"Velocidad de recepcion: {mbps_recibidos} Mbps")
        
        time.sleep(3)

        registrar_log(logger, 'INFO', 'Medición de ancho de banda hecha correctamente')

    def medir_velocidad_internet():

        logger = configurar_logger('Test Velocidad', 'log.txt')

        st = speedtest.Speedtest()
        st.get_best_server()
        best = st.get_best_server() 
        print(f"Conectando al servidor: {best['host']} ubicado en {best['name']}, {best['country']}")

        registrar_log(logger, 'INFO', 'Conectado al servidor')

        velocidad_descarga = st.download() / 1e6  
        velocidad_subida = st.upload() / 1e6 
        ping = st.results.ping

        print(f"velocidad_descarga_mbps: {velocidad_descarga}")
        print(f"velocidad_subida_mbps: {velocidad_subida}")
        print(f"ping_ms: {ping}")

        registrar_log(logger, 'INFO', 'Medición de Velocidad de red hecho correctamente')


    medir_ancho_de_banda()
    medir_velocidad_internet()
        


def abrir_sesion_ssh():

    logger = configurar_logger('Conexion SSH', 'log.txt')

    cliente = paramiko.SSHClient()
    cliente.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    host = input("Introduce la ip del host al que te quieres conectar: ")
    puerto = input("Introduce el puerto: ")
    usuario = input("Introduce el usuario: ")
    clave = input("Introduce la clave de acceso: ")

    try:
        cliente.connect(hostname=host, port=puerto, username=usuario, password=clave)
        print(f"Conectado a {host}")

        sesion = cliente.invoke_shell()
        time.sleep(1)

        log_res= "Conectado a " + host + ":"+ puerto + " con usuario " + usuario + " y clave " + clave
        registrar_log(logger, 'INFO', log_res)

        if sesion.recv_ready():
            sesion.recv(1024).decode()

        def enviar_comando(comando):
            sesion.send(comando + "\n")
            time.sleep(1)
            salida = ""

            while True:
                if sesion.recv_ready():
                    salida += sesion.recv(1024).decode()
                else:
                    break
                time.sleep(0.1)
            return salida

        while True:
            comando = input("Introduce un comando (o 'salir' para terminar): ")
            log_res= "Comando enviado: " + comando
            registrar_log(logger, 'INFO', log_res)
            if comando.lower() == 'salir':
                registrar_log(logger, 'INFO', 'Saliendo de la sesión SSH')
                break
            respuesta = enviar_comando(comando)
            print(respuesta)
    
    except Exception as e:
        print(f"Error al conectar o mantener la sesión SSH: {e}")
        registrar_log(logger, 'ERROR', 'Error al conectar o mantener la sesión SSH')

    finally:
        cliente.close()
        registrar_log(logger, 'INFO', 'Cerrando sesión ssh')
        time.sleep(3)

def obtener_datos_remotos():

    logger = configurar_logger('Uso de Recursos', 'log.txt')

    cliente = paramiko.SSHClient()
    cliente.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    host = input("Introduce la ip del host al que te quieres conectar: ")
    puerto = input("Introduce el puerto: ")
    usuario = input("Introduce el usuario: ")
    clave = input("Introduce la clave de acceso: ")
    
    try:
        cliente.connect(hostname=host, port=puerto, username=usuario, password=clave)
        
        comandos = {
            'cpu': r"top -bn1 | grep 'Cpu(s)' | sed 's/.*, *\([0-9.]*\)%* id.*/\\1/' | awk '{print 100 - $1}'",
            'memoria': "free -m | awk 'NR==2{printf \"%.2f%%\", $3*100/$2 }'",
            'red': "cat /proc/net/dev | grep eth0 | awk '{print $2, $10}'"
        }

        log_res= "Conectado a " + host + ":"+ puerto + " con usuario " + usuario + " y clave " + clave
        registrar_log(logger, 'INFO', log_res)

        datos = {}
        for i, comando in comandos.items():
            stdin, stdout, stderr = cliente.exec_command(comando)
            output = stdout.read().decode().strip()
            datos[i] = output

        print(f"Uso de CPU: {datos['cpu']}%")
        print(f"Uso de Memoria: {datos['memoria']}")
        print(f"Tráfico de Red: {datos['red']} bytes enviados y recibidos")    
        
        registrar_log(logger, 'INFO', 'Ejecución del código realizada con éxito')

    except Exception as e:
        print(f"Error al conectar o ejecutar comandos: {e}")
        registrar_log(logger, 'ERROR', 'Error al conectar o ejecutar comandos')
        return None

    finally:
        cliente.close()
        registrar_log(logger, 'INFO', 'Cerrando sesión ssh')
        time.sleep(3)

def configurar_logger(nombre_logger, archivo_log):

    logger = logging.getLogger(nombre_logger)
    logger.setLevel(logging.INFO)
    
    controlador = RotatingFileHandler(archivo_log, maxBytes=10485760, backupCount=5)
    controlador.setLevel(logging.INFO)
    
    formateador = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    controlador.setFormatter(formateador)
    
    if not logger.handlers:
        logger.addHandler(controlador)
    
    return logger

def registrar_log(logger, nivel, mensaje):
   
    if nivel == 'DEBUG':
        logger.debug(mensaje)
    elif nivel == 'INFO':
        logger.info(mensaje)
    elif nivel == 'WARNING':
        logger.warning(mensaje)
    elif nivel == 'ERROR':
        logger.error(mensaje)
    elif nivel == 'CRITICAL':
        logger.critical(mensaje)
    else:
        logger.info(mensaje)

main()