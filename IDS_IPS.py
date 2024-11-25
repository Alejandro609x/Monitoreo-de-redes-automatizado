import subprocess  # Módulo para ejecutar comandos del sistema.
import time  # Módulo para manejar intervalos de tiempo.
import smtplib  # Módulo para enviar correos electrónicos.
from email.mime.text import MIMEText  # Módulo para crear texto del cuerpo del correo.
from email.mime.multipart import MIMEMultipart  # Módulo para correos con varios tipos de contenido.
from email.mime.base import MIMEBase  # Base para archivos adjuntos en el correo.
from email import encoders  # Módulo para codificar archivos adjuntos.
from datetime import datetime  # Módulo para trabajar con fechas y horas.
import pandas as pd  # Módulo para manejar datos en tablas.
from scapy.all import sniff, IP, TCP, UDP  # Módulo para capturar y analizar paquetes de red.
import logging  # Módulo para registrar eventos en un archivo de log.
import os  # Módulo para trabajar con funciones del sistema operativo.
import threading  # Módulo para manejar múltiples hilos de ejecución.

# Configuración del archivo de log
logging.basicConfig(
    filename="network_security.log",  # Nombre del archivo log.
    level=logging.INFO,  # Nivel de logging.
    format="%(asctime)s - %(message)s",  # Formato del mensaje.
)

# Configuración del correo
smtp_server = 'smtp.gmail.com'  # Servidor SMTP de Gmail.
smtp_port = 587  # Puerto para el servicio SMTP.
sender_email = 'crystalteamem@gmail.com'  # Correo del remitente.
sender_password = 'qecaizmzretsnpcg'  # Contraseña del remitente.
receiver_email = 'ale609jandro609@gmail.com'  # Correo del destinatario.

# Conjuntos para IPs permitidas y otras variables de control
whitelist_ips = set()  # Conjunto de IPs permitidas cargadas desde IPS.txt.
alerted_ips = set()  # Conjunto para llevar control de alertas enviadas para IPs.
reported_errors = set()  # Conjunto para controlar los errores reportados.

def load_whitelist():
    """Carga las IPs permitidas desde el archivo 'IPS.txt'."""
    if os.path.exists("IPS.txt"):  # Verifica si el archivo existe.
        with open("IPS.txt", 'r') as file:  # Abre el archivo en modo de lectura.
            for line in file:  # Itera sobre cada línea.
                ip = line.strip()  # Elimina espacios y saltos de línea.
                whitelist_ips.add(ip)  # Agrega la IP al conjunto de IPs permitidas.
        print(f"Lista blanca de IPs cargada: {whitelist_ips}")
    else:
        print("El archivo IPS.txt no existe. No se cargó ninguna IP en la lista blanca.")

def ping_host(host, failed_hosts, results):
    """Realiza un ping a un host y guarda el resultado."""
    try:
        command = ['ping', '-n', '1', host]  # Comando de ping para Windows.
        output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)  # Ejecuta el ping.

        # Define el estado según el código de retorno (0 es activo).
        status = 'Activo' if output.returncode == 0 else 'Con error'
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Obtiene la fecha y hora actual.

        results.append({'Host': host, 'Estado': status, 'Fecha y hora': timestamp})  # Añade el resultado al registro.

        if status == 'Activo':
            print(f"{host} está disponible.")
            failed_hosts.discard(host)  # Elimina el host de la lista de fallidos.
            return True
        else:
            print(f"{host} no responde.")
            if host not in failed_hosts:  # Si el host no ha fallado antes, envía correo de error.
                send_error_email(host, results)
                failed_hosts.add(host)  # Añade el host a la lista de fallidos.
            return False
    except Exception as e:
        print(f"Error al hacer ping a {host}: {e}")
        if host not in failed_hosts:
            send_error_email(host, results)  # Envía correo de error si hay una excepción.
            failed_hosts.add(host)
        return False

def send_error_email(host, results=None):
    """Envía un correo de alerta si un host no responde."""
    if results is None:
        results = []
    msg = MIMEMultipart()  # Crea el mensaje de correo.
    subject = f"Error de conexión con {host}"  # Asunto del correo.
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Marca de tiempo.
    body = f"El host {host} no responde. Fecha y hora del error: {timestamp}."  # Cuerpo del mensaje.

    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg.attach(MIMEText(body, 'plain'))

    # Crear y adjuntar un archivo Excel con resultados de ping.
    df = pd.DataFrame(results)
    excel_file = 'resultados_ping.xlsx'
    df.to_excel(excel_file, index=False)

    with open(excel_file, 'rb') as f:
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(f.read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f'attachment; filename={excel_file}')
        msg.attach(part)

    # Enviar el correo.
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, receiver_email, msg.as_string())
            print(f"Correo de error enviado a {receiver_email} sobre el host {host}.")
    except Exception as e:
        print(f"Error al enviar el correo: {e}")

def send_alert(alert_message, ip_address):
    """Envía una alerta y loguea un mensaje si se detecta una IP no permitida."""
    if ip_address in alerted_ips or alert_message in reported_errors:
        return

    logging.info(alert_message)  # Guarda el mensaje en el log.
    print("Alerta de Seguridad:", alert_message)
    send_ip_alert_email(ip_address, alert_message)  # Enviar alerta por correo.
    alerted_ips.add(ip_address)  # Añadir IP a las IPs alertadas.
    reported_errors.add(alert_message)

def send_ip_alert_email(ip_address, alert_message):
    """Envía un correo de alerta para una conexión de IP no permitida."""
    msg = MIMEMultipart()
    subject = f"Alerta de seguridad: IP no permitida"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    body = f"{alert_message}\nFecha y hora de la alerta: {timestamp}."

    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, receiver_email, msg.as_string())
            print(f"Correo de alerta enviado a {receiver_email} sobre la IP no permitida: {ip_address}.")
    except Exception as e:
        print(f"Error al enviar el correo: {e}")

def packet_callback(packet):
    """Analiza paquetes de red y verifica si la IP destino está permitida."""
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if dst_ip not in whitelist_ips:  # Si la IP destino no está en la lista blanca, envía alerta.
            alert_message = f"Conexión bloqueada para IP no permitida: {src_ip} -> {dst_ip}."
            send_alert(alert_message, dst_ip)

def monitor_network(duration=15):
    """Inicia la captura de paquetes de red durante un tiempo específico."""
    print("Iniciando monitoreo de tráfico de red...")
    sniff(prn=packet_callback, timeout=duration, store=0)

def ping_hosts(hosts, failed_hosts, results):
    """Realiza un ping a cada host en la lista."""
    for host in hosts:
        ping_host(host, failed_hosts, results)
        time.sleep(3)

def main():
    """Función principal que carga IPs permitidas, hace ping y monitorea red."""
    load_whitelist()  # Carga las IPs permitidas.

    with open('IPS.txt', 'r') as file:
        hosts = file.readlines()

    hosts = [host.strip() for host in hosts]
    failed_hosts = set()
    results = []

    while True:
        print("Esperando 10 segundos antes de iniciar pings...")
        time.sleep(10)

        print("Realizando pings a los hosts...")
        ping_hosts(hosts, failed_hosts, results)

        print("Esperando 10 segundos antes de iniciar monitoreo de red...")
        time.sleep(10)

        monitor_network(duration=15)

if __name__ == "__main__":
    main()  # Ejecuta el programa.