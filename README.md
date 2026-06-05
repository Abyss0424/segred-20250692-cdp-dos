# Attack-01 — CDP DoS (Neighbor Table Exhaustion)

> **Autor:** [Tu nombre]  
> **Matrícula:** 20250692  
> **Red asignada:** 192.168.92.0/24  
> **Curso:** [Nombre del curso]  
> **Fecha:** [Fecha]

---

## 1. Objetivo del Laboratorio

Demostrar el ataque **CDP DoS** mediante la saturación de la tabla de vecinos CDP
del switch objetivo usando frames CDP con Device-IDs aleatorios, y aplicar
la contramedida `no cdp enable` para mitigarlo.

---

## 2. Objetivo del Script

`cdp_dos.py` genera frames CDP con identificadores de dispositivo y MACs
de origen aleatorios a máxima velocidad, saturando la tabla de vecinos CDP
del switch hasta causar consumo elevado de CPU y desplazamiento de entradas legítimas.

### 2.1 Parámetros

| Parámetro | Descripción | Ejemplo |
|---|---|---|
| `-i / --iface` | Interfaz de red del atacante | `eth0` |
| `-r / --rate` | Paquetes por segundo (0 = máximo) | `100` |
| `-c / --count` | Total de paquetes (0 = infinito) | `500` |

### 2.2 Requisitos

| Requisito | Versión |
|---|---|
| Python | 3.6+ |
| Scapy | >= 2.4.0 (con contrib CDP) |
| SO | Linux / Kali |
| Privilegios | root / sudo |

```bash
pip install scapy
# o en Kali:
sudo apt install python3-scapy
```

---

## 3. Funcionamiento del Script

### Flujo de ejecución

```
1. Parseo de argumentos (-i, -r, -c)
2. Registro del handler SIGINT para salida limpia con estadísticas
3. Bucle principal:
   a. Generar MAC de origen aleatoria (_rand_mac)
   b. Generar Device-ID aleatorio (_rand_str)
   c. Construir frame CDP válido (_build_frame)
   d. Enviar con sendp() — capa 2, bypass del stack OS
   e. Mostrar estadísticas cada 100 paquetes
4. Al interrumpir: imprimir totales y salir
```

### Encapsulación del frame CDP

```
[ Dot3 (802.3) src=rand_mac dst=01:00:0c:cc:cc:cc ]
  └─[ LLC dsap=0xAA ssap=0xAA ctrl=0x03 ]
      └─[ SNAP OUI=0x00000c code=0x2000 ]
          └─[ CDPv2_HDR vers=2 ttl=180 ]
              └─[ CDPMsgDeviceID val=<ID_ALEATORIO> ]
              └─[ CDPMsgPortID   iface=GigabitEthernet0/1 ]
              └─[ CDPMsgCapabilities ]
              └─[ CDPMsgSoftwareVersion ]
              └─[ CDPMsgPlatform ]
```

**Por qué Dot3 y no Ether:** CDP usa IEEE 802.3 (campo `length` en bytes 12-13),
no Ethernet DIX (EtherType). Usar `Ether` generaría un frame inválido que el switch
podría rechazar.

**Por qué Device-ID aleatorio:** cada Device-ID único genera una entrada separada
en la tabla CDP del switch. Sin aleatoriedad, el switch actualizaría la misma entrada
y no habría saturación.

---

## 4. Documentación de la Red

### Topología

```
        R1 (vios-15.5.3M)
        Gi0/0: 192.168.92.1/24
              |
        SW1 (viosl2-15.2.4.55e)    SW2 (viosl2-15.2.4.55e)
        Gi0/0 ← R1                 Gi0/0 ← trunk SW1
        Gi0/1 ← Attacker (Kali)    Gi0/1 ← Victim2 (VPCS)
        Gi0/2 ← Victim1 (Kali)
        Gi0/3 ── trunk ──────────► SW2
```

### Direccionamiento

| Dispositivo | Interfaz | IP/Máscara | VLAN | Rol |
|---|---|---|---|---|
| R1 | Gi0/0 | 192.168.92.1/24 | 10 | Gateway + DHCP server |
| SW1 | Gi0/1 | — | 10 acc | Puerto atacante |
| SW1 | Gi0/2 | — | 10 acc | Puerto Victim1 |
| SW1 | Gi0/3 | — | trunk | Uplink SW2 |
| Attacker | eth0 | 192.168.92.x (DHCP) | 10 | Atacante (Kali) |
| Victim1 | eth0 | 192.168.92.x (DHCP) | 10 | Víctima |
| Victim2 | e0 | 192.168.92.x (DHCP) | 10 | Víctima 2 |

---

## 5. Ejecución

### Estado inicial (antes del ataque)

```
SW1# show cdp neighbors
SW1# show processes cpu | include CDP
```

### Ejecutar el ataque

```bash
sudo python3 cdp_dos.py -i eth0
```

### Verificar impacto

```
SW1# show cdp neighbors          ! tabla crece con entradas aleatorias
SW1# show processes cpu | i CDP  ! CPU sube por procesamiento CDP
```

### Capturas de pantalla

![Antes del ataque](screenshots/01_antes.png)
![Ataque en ejecución](screenshots/02_ataque.png)
![Impacto en SW1](screenshots/03_sw1_durante.png)

---

## 6. Contramedida

### Mecanismo

Deshabilitar CDP en el puerto del atacante impide que el switch procese
los frames CDP recibidos por esa interfaz. El switch descarta los frames
a nivel de puerto antes de que lleguen al proceso CDP, eliminando el vector de ataque.

### Configuración en SW1

```
SW1(config)# interface GigabitEthernet0/1
SW1(config-if)# no cdp enable
SW1(config-if)# end
SW1# write memory
```

### Verificación post-mitigación

```
SW1# show cdp interface Gi0/1
! Output: "CDP disabled on interface"

SW1# show cdp neighbors
! El atacante ya no genera nuevas entradas
```

### Re-ejecución del ataque con contramedida activa

```bash
sudo python3 cdp_dos.py -i eth0
# Script sigue enviando, pero SW1 descarta los frames silenciosamente
```

```
SW1# show cdp neighbors
! Tabla estable — solo R1 y SW2 como vecinos legítimos
```

![Contramedida aplicada](screenshots/04_contramedida.png)

---

## 7. Conclusiones

[Redactar con tus propias palabras]

---

## 8. Referencias

- IEEE 802.3 — Ethernet Standard
- Cisco CDP Specification (Cisco IOS Configuration Guide)
- Scapy Documentation: https://scapy.readthedocs.io/en/latest/api/scapy.contrib.cdp.html
