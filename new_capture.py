import pyshark

def captura_pacotes(interface):
    """
    Captura pacotes na interface especificada e exibe todas as features solicitadas.

    Args:
        interface (str): O nome da interface de rede para capturar pacotes.
    """

    try:
        captura = pyshark.LiveCapture(interface=interface)

        for pacote in captura.sniff_continuously():
            if 'TCP' in pacote or 'MQTT' in pacote:
                print(f"Frame Time: {pacote.frame_info.time}")

                if 'TCP' in pacote:
                    tcp_layer = pacote.tcp
                    flags_hex = int(tcp_layer.flags, 16)
                    flags = {
                        'FIN': bool(flags_hex & 0x01),
                        'SYN': bool(flags_hex & 0x02),
                        'RST': bool(flags_hex & 0x04),
                        'PSH': bool(flags_hex & 0x08),
                        'ACK': bool(flags_hex & 0x10),
                        'URG': bool(flags_hex & 0x20),
                        'ECE': bool(flags_hex & 0x40),
                        'CWR': bool(flags_hex & 0x80)
                    }

                    print(f"TCP Stream: {tcp_layer.stream}")
                    print(f"TCP Seq: {tcp_layer.seq}")
                    print(f"ACK: {int(flags['ACK'])}")
                    print(f"PSH: {int(flags['PSH'])}")
                    print(f"FIN: {int(flags['FIN'])}")
                    print(f"SYN: {int(flags['SYN'])}")
                    print(f"RST: {int(flags['RST'])}")
                    print(f"URG: {int(flags['URG'])}")
                    print(f"ECE: {int(flags['ECE'])}")
                    print(f"CWR: {int(flags['CWR'])}")
                    print(f"TCP Window Size Value: {tcp_layer.window_size_value}")
                    print(f"TCP Len: {tcp_layer.len}")
                    print(f"TCP Time Delta: {tcp_layer.time_delta}")

                if 'MQTT' in pacote:
                    mqtt_layer = pacote.mqtt
                    print(f"MQTT Msg Type: {mqtt_layer.msgtype}")
                    print(f"MQTT Len: {mqtt_layer.len}")
                    print(f"MQTT Topic: {mqtt_layer.topic}")
                    print(f"MQTT Msg: {mqtt_layer.msg}")
                    print(f"MQTT QOS: {mqtt_layer.qos}")
                    print(f"MQTT Retain: {mqtt_layer.retain}")
                    print(f"MQTT Dup Flag: {mqtt_layer.dupflag}")

                print("-" * 20)

    except Exception as e:
        print(f"Ocorreu um erro: {e}")

if __name__ == "__main__":
    interface_de_rede = 'wlp3s0'  # interface de rede
    captura_pacotes(interface_de_rede)