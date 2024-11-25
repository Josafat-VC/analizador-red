from scapy.all import sniff, IP, TCP, UDP, ICMP
import pandas as pd
from collections import Counter
import datetime


class AnalizadorRed:
    def __init__(self, interfaz, archivo_salida):
        self.interfaz = interfaz
        self.archivo_salida = archivo_salida
        self.paquetes_capturados = []
        self.total_paquetes = 0
        self.protocolos = Counter()
        self.ips_origen = Counter()
        self.ips_destino = Counter()

    def procesar_paquete(self, paquete):
        """Procesar y registrar cada paquete"""
        if IP in paquete:
            fecha = datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')
            ip_origen = paquete[IP].src
            ip_destino = paquete[IP].dst
            tamaño = len(paquete)
            protocolo = self.determinar_protocolo(paquete)

            # Guardar datos del paquete
            self.paquetes_capturados.append({
                'Fecha': fecha,
                'IP Origen': ip_origen,
                'IP Destino': ip_destino,
                'Protocolo': protocolo,
                'Tamaño (bytes)': tamaño
            })

            # Actualizar contadores
            self.total_paquetes += 1
            self.protocolos[protocolo] += 1
            self.ips_origen[ip_origen] += 1
            self.ips_destino[ip_destino] += 1

            # Mostrar detalles básicos
            print(f"Paquete {self.total_paquetes}: IP Origen: {ip_origen}, IP Destino: {ip_destino}, Protocolo: {protocolo}, Tamaño: {tamaño} bytes")

    def determinar_protocolo(self, paquete):
        """Determinar el protocolo del paquete"""
        if TCP in paquete:
            if paquete[TCP].dport == 80 or paquete[TCP].sport == 80:
                return "HTTP"
            elif paquete[TCP].dport == 443 or paquete[TCP].sport == 443:
                return "HTTPS"
            return "TCP"
        elif UDP in paquete:
            if paquete[UDP].dport == 53 or paquete[UDP].sport == 53:
                return "DNS"
            return "UDP"
        elif ICMP in paquete:
            return "ICMP"
        elif IP in paquete:
            return "IP"
        return "Otro"

    def iniciar_captura(self, max_paquetes=None):
        """Iniciar la captura de paquetes"""
        print(f"Iniciando captura en la interfaz: {self.interfaz}")
        try:
            sniff(iface=self.interfaz, prn=self.procesar_paquete, count=max_paquetes)
        except Exception as e:
            print(f"Error durante la captura: {e}")

    def mostrar_estadisticas(self):
        """Mostrar estadísticas de la captura"""
        print("\n--------- Estadísticas ---------")
        print(f"Total de paquetes capturados: {self.total_paquetes}")
        print("Paquetes por protocolo:")
        for protocolo, cantidad in self.protocolos.items():
            print(f"  {protocolo}: {cantidad}")
        print("\nTop 5 IPs de origen:")
        for ip, cantidad in self.ips_origen.most_common(5):
            print(f"  Ip: {ip}: {cantidad} Paquetes")
        print("\nTop 5 IPs de destino:")
        for ip, cantidad in self.ips_destino.most_common(5):
            print(f"  Ip: {ip}: {cantidad} Paquetes")

    def guardar_en_excel(self):
        """Guardar los datos capturados y las estadísticas en un archivo Excel"""
        try:
            # Crear DataFrame con los paquetes capturados
            df_paquetes = pd.DataFrame(self.paquetes_capturados)

            # Crear DataFrames para las estadísticas
            df_protocolo = pd.DataFrame(
                self.protocolos.items(),
                columns=['Protocolo', 'Cantidad']
            )

            df_ips_origen = pd.DataFrame(
                self.ips_origen.most_common(5),
                columns=['IP Origen', 'Cantidad']
            )

            df_ips_destino = pd.DataFrame(
                self.ips_destino.most_common(5),
                columns=['IP Destino', 'Cantidad']
            )

            # Guardar en el archivo Excel
            with pd.ExcelWriter(self.archivo_salida, engine='openpyxl') as escritor:
                # Hoja 1: Detalles de los paquetes
                df_paquetes.to_excel(escritor, sheet_name="Paquetes Capturados", index=False)

                # Hoja 2: Estadísticas
                df_protocolo.to_excel(escritor, sheet_name="Estadísticas", startrow=0, index=False)
                df_ips_origen.to_excel(escritor, sheet_name="Estadísticas", startrow=10, index=False)
                df_ips_destino.to_excel(escritor, sheet_name="Estadísticas", startrow=20, index=False)

            print(f"\nDatos guardados en: {self.archivo_salida}")
        except Exception as e:
            print(f"Error guardando en Excel: {e}")


def main():
    # Nombre de interfaz de red
    interfaz = "Ethernet"
    # Nombre del archivo Excel
    archivo = "captura_red.xlsx"

    analizador = AnalizadorRed(interfaz, archivo)

    try:
        analizador.iniciar_captura(max_paquetes=2000)
        analizador.mostrar_estadisticas()
        analizador.guardar_en_excel()
    except KeyboardInterrupt:
        print("\nCaptura interrumpida.")
        analizador.mostrar_estadisticas()
        analizador.guardar_en_excel()


if __name__ == "__main__":
    main()
