import pyshark
import json

def capture_and_save(interface, capture_filter, output_file):
    """
    Captura pacotes em tempo real, exibe informações básicas e salva em um arquivo JSON.
    
    Args:
        interface (str): Nome da interface de rede para captura (ex.: 'wlo1').
        capture_filter (str): Filtro para captura de pacotes (ex.: 'tcp or mqtt').
        output_file (str): Nome do arquivo JSON onde os pacotes serão salvos.
    """
    capture = pyshark.LiveCapture(interface=interface, display_filter=capture_filter)
    packets_data = []

    # comentario

    for packet in capture.sniff_continuously():
        try:
            packet_info = {}
            
            # Frame (tempo de chegada do pacote)
            packet_info["frame_time"] = getattr(packet.frame_info, 'time_epoch', 'N/A')
            
            # TCP Features
            if 'TCP' in packet:
                packet_info["tcp_stream"] = getattr(packet.tcp, 'stream', 'N/A')
                packet_info["tcp_seq"] = getattr(packet.tcp, 'seq', 'N/A')
                packet_info["tcp_ack"] = getattr(packet.tcp, 'ack', 'N/A')
                packet_info["tcp_flags"] = getattr(packet.tcp, 'flags', 'N/A')
                packet_info["tcp_window_size"] = getattr(packet.tcp, 'window_size_value', 'N/A')
                packet_info["tcp_len"] = getattr(packet.tcp, 'len', 'N/A')
                packet_info["tcp_time_delta"] = getattr(packet.tcp, 'time_delta', 'N/A')

            # MQTT Features
            if 'MQTT' in packet:
                packet_info["mqtt_msgtype"] = getattr(packet.mqtt, 'msgtype', 'N/A')
                packet_info["mqtt_len"] = getattr(packet.mqtt, 'len', 'N/A')
                packet_info["mqtt_topic"] = getattr(packet.mqtt, 'topic', 'N/A')
                packet_info["mqtt_msg"] = getattr(packet.mqtt, 'msg', 'N/A')
                packet_info["mqtt_qos"] = getattr(packet.mqtt, 'qos', 'N/A')
                packet_info["mqtt_retain"] = getattr(packet.mqtt, 'retain', 'N/A')
                packet_info["mqtt_dupflag"] = getattr(packet.mqtt, 'dupflag', 'N/A')
                packet_info["mqtt_clientid"] = getattr(packet.mqtt, 'clientid', 'N/A')
                packet_info["mqtt_username"] = getattr(packet.mqtt, 'username', 'N/A')
                packet_info["mqtt_password"] = getattr(packet.mqtt, 'password', 'N/A')
                packet_info["mqtt_kalive"] = getattr(packet.mqtt, 'kalive', 'N/A')
                packet_info["mqtt_conflag_cleansess"] = getattr(packet.mqtt, 'conflag_cleansess', 'N/A')
                packet_info["mqtt_conack_flags"] = getattr(packet.mqtt, 'conack_flags', 'N/A')
                packet_info["mqtt_sub_qos"] = getattr(packet.mqtt, 'sub_qos', 'N/A')
                packet_info["mqtt_suback_qos"] = getattr(packet.mqtt, 'suback_qos', 'N/A')
                packet_info["mqtt_unsub_topic"] = getattr(packet.mqtt, 'unsub_topic', 'N/A')
                packet_info["mqtt_disconnect_reason"] = getattr(packet.mqtt, 'disconnect_reason', 'N/A')
                packet_info["mqtt_pingreq"] = getattr(packet.mqtt, 'pingreq', 'N/A')
                packet_info["mqtt_pingresp"] = getattr(packet.mqtt, 'pingresp', 'N/A')

            packets_data.append(packet_info)
            print(json.dumps(packet_info, indent=4))  # Exibir no terminal

            # Salvar a cada 10 pacotes capturados
            if len(packets_data) % 10 == 0:
                with open(output_file, 'w') as json_file:
                    json.dump(packets_data, json_file, indent=4)

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
        print("\nNetwork capture stopped.")