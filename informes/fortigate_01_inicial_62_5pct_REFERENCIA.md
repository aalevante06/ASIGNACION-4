# Auditoría inicial de FortiGate (registro visual)

**Fuente:** captura original `05-fortigate-auditoria-inicial.png`, obtenida antes de aplicar las primeras correcciones. El fichero `fortigate_auditoria_inicial.txt` fue sobrescrito más tarde y por eso este texto es una **transcripción/resumen de la evidencia visual, no una exportación original**.

| Control | Estado inicial |
|---|---|
| SSH v1 deshabilitado | Cumple |
| Timeout administrativo <= 5 min | Cumple |
| Bloqueo tras <= 3 fallos | Cumple |
| HTTPS en interfaz administrativa | Cumple |
| TLS para HTTPS >= 1.2 | Cumple |
| Telnet global deshabilitado | No cumple |
| Registro de comandos CLI | No cumple |
| TLS saliente mínimo 1.2 (primer esquema de control) | No cumple |

**Resultado histórico:** 5/8 = 62.5 %. La última comprobación fue sustituida después por «Registro de hora de acceso» al comprobar que `ssl-min-proto-version TLSv1-2` era rechazado en esta VM. Por tanto, los conjuntos de controles inicial y posterior no son exactamente idénticos; no debe presentarse la comparación como un benchmark completo o un ensayo controlado idéntico.
