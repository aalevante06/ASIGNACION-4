# Direccionamiento final documentado

| Equipo | Puerto | Dirección | Uso |
|---|---|---|---|
| R1-2174 (Cisco 7200) | FastEthernet0/0 | `10.21.75.1/30` | Enlace a FortiGate |
| FGT-2174 | port1 | `10.21.75.2/30` | Enlace a R1 |
| FGT-2174 | port2 | `10.21.76.1/24` | LAN interna |
| Ubuntu | ens4 / e1 | `10.21.76.10/24` | Auditoría desde LAN |
| FGT-2174 | port3 | `10.21.74.2/24` | Administración vía Cloud2 |
| Ubuntu | ens3 / e0 | `10.21.74.20/24` | SSH desde Windows por Cloud1 |
| Windows VMnet1 | — | `10.21.74.3/24` | Red de administración |

El switch integrado de GNS3 funciona como dispositivo Ethernet L2 sin IOS ni running-config propio. La regla `UBUNTU_TO_R1_SSH` conecta port2 a port1 y permite SSH e ICMP; en la captura se observan origen y destino `all`, lo cual constituye una excepción por corregir (mínimo privilegio).

El router dejó de servir DHCP tras la migración; Ubuntu quedó con IP estática en `ens4`. La exportación Cisco incluida es anterior a esa migración, y por eso contiene direccionamiento/DHCP históricos.
