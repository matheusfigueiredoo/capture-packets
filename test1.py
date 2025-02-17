import pyshark
import json

def capture_and_save(interface, capture_filter, output_file):
    """
    Captura pacotes em tempo real, exibe informações básicas dos pacotes TCP e salva em um arquivo JSON.
    
    Args:
        interface (str): Nome da interface de rede para captura (ex.: 'eth0').
        capture_filter (str): Filtro para captura de pacotes (ex.: 'tcp or mqtt').
        output_file (str): Nome do arquivo JSON onde os pacotes serão salvos.
    """
    capture = pyshark.LiveCapture(interface=interface, display_filter=capture_filter)
    packets_list = []

    for packet in capture.sniff_continuously():
        print("\n--- New Packet Captured ---")
        try:
            if 'TCP' in packet:
                tcp_layer = packet.tcp
                packet_data = {
                    "flags": getattr(tcp_layer, 'flags', 'N/A'),
                    "time_delta": getattr(tcp_layer, 'time_delta', 'N/A'),
                    "length": getattr(tcp_layer, 'len', 'N/A')
                }
                print(packet_data)
                packets_list.append(packet_data)

                # Salva no arquivo JSON a cada 10 pacotes
                if len(packets_list) % 10 == 0:
                    with open(output_file, 'w') as json_file:
                        json.dump(packets_list, json_file, indent=4)
        except Exception as e:
            print(f"Erro ao processar pacote: {e}")

if __name__ == "__main__":
    interface = "wlo1"
    capture_filter = "tcp or mqtt"
    output_file = "captured_packets.json"

    print("Starting packet capture. Press Ctrl+C to stop.")
    try:
        capture_and_save(interface, capture_filter, output_file)
    except KeyboardInterrupt:
        print("\nCapture terminated by user.")
    except Exception as e:
        print(f"Erro: {e}")
    finally:
        print("\nNetwork out of order")