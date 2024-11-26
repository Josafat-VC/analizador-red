from scapy.all import sniff, IP, TCP, UDP, ICMP
import pandas as pd
from collections import Counter
import datetime
import matplotlib.pyplot as plt


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
            print(
                f"Paquete {self.total_paquetes}: IP Origen: {ip_origen}, IP Destino: {ip_destino}, Protocolo: {protocolo}, Tamaño: {tamaño} bytes")

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

    def iniciar_captura(self, max_paquetes=2000):
        """Iniciar la captura de paquetes"""
        print(f"Iniciando captura en la interfaz: {self.interfaz}")
        print(f"Para detener la captura de datos: Control + C ")
        try:
            sniff(iface=self.interfaz, prn=self.procesar_paquete, count=max_paquetes)
        except Exception as e:
            print(f"Error durante la captura: {e}")

    def mostrar_estadisticas(self, generar_graficos=True):
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

        # Generar gráficos si está habilitado
        if generar_graficos:
            self.grafico_distribucion_protocolos()
            self.grafico_ips_frecuentes()

    def grafico_distribucion_protocolos(self):
        """Genera un gráfico de distribución de protocolos"""
        etiquetas = list(self.protocolos.keys())
        valores = list(self.protocolos.values())

        plt.figure(figsize=(8, 6))
        plt.pie(valores, labels=etiquetas, autopct='%1.1f%%', startangle=90)
        plt.title('Distribución de Protocolos')
        plt.axis('equal')
        plt.savefig('distribucion_protocolos.png', dpi=300)
        plt.close()
        print("Gráfico de distribución de protocolos generado: distribucion_protocolos.png")

    def grafico_ips_frecuentes(self):
        """Genera gráficos de las IPs más frecuentes"""
        plt.figure(figsize=(12, 6))

        # IPs de origen
        plt.subplot(1, 2, 1)
        ips_origen = dict(self.ips_origen.most_common(5))
        plt.bar(ips_origen.keys(), ips_origen.values(), color='skyblue')
        plt.title('Top 5 IPs de Origen')
        plt.xticks(rotation=45)

        # IPs de destino
        plt.subplot(1, 2, 2)
        ips_destino = dict(self.ips_destino.most_common(5))
        plt.bar(ips_destino.keys(), ips_destino.values(), color='lightgreen')
        plt.title('Top 5 IPs de Destino')
        plt.xticks(rotation=45)

        plt.tight_layout()
        plt.savefig('ips_frecuentes.png', dpi=300)
        plt.close()
        print("Gráfico de IPs frecuentes generado: ips_frecuentes.png")

    def guardar_en_excel(self):
        """Guardar los datos capturados y las estadísticas en un archivo Excel"""
        try:
            df_paquetes = pd.DataFrame(self.paquetes_capturados)

            df_protocolo = pd.DataFrame(self.protocolos.items(), columns=['Protocolo', 'Cantidad'])
            df_ips_origen = pd.DataFrame(self.ips_origen.most_common(5), columns=['IP Origen', 'Cantidad'])
            df_ips_destino = pd.DataFrame(self.ips_destino.most_common(5), columns=['IP Destino', 'Cantidad'])

            with pd.ExcelWriter(self.archivo_salida, engine='openpyxl') as escritor:
                df_paquetes.to_excel(escritor, sheet_name="Paquetes Capturados", index=False)
                df_protocolo.to_excel(escritor, sheet_name="Estadísticas", startrow=0, index=False)
                df_ips_origen.to_excel(escritor, sheet_name="Estadísticas", startrow=10, index=False)
                df_ips_destino.to_excel(escritor, sheet_name="Estadísticas", startrow=20, index=False)

            print(f"\nDatos guardados en: {self.archivo_salida}")
        except Exception as e:
            print(f"Error guardando en Excel: {e}")


def main():
    interfaz = input("Ingresa el nombre de la interfaz: ")
    archivo = f"captura_red_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"

    analizador = AnalizadorRed(interfaz, archivo)

    try:
        analizador.iniciar_captura(max_paquetes=2000)
        analizador.mostrar_estadisticas(generar_graficos=True)
        analizador.guardar_en_excel()
    except KeyboardInterrupt:
        print("\nCaptura interrumpida.")
        analizador.mostrar_estadisticas(generar_graficos=True)
        analizador.guardar_en_excel()


if __name__ == "__main__":
    main()
