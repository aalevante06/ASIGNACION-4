#!/usr/bin/env python3
import os
import re
import sys
import time
from pathlib import Path
from datetime import datetime
from getpass import getpass
import paramiko

HOST = '10.21.75.1'
USER = 'admin2174'
REPORTS = Path.home() / 'CIS-2174' / 'informes'
REPORTS.mkdir(parents=True, exist_ok=True)

class C:
    RESET='\033[0m'; GREEN='\033[92m'; RED='\033[91m'; CYAN='\033[96m'
    YELLOW='\033[93m'; DIM='\033[90m'; BOLD='\033[1m'; WHITE='\033[97m'

CONTROLS = [
    ('SSH version 2', 'Mantener conexiones remotas mediante SSHv2.'),
    ('VTY solo SSH', 'Impedir acceso Telnet y exigir autenticacion local.'),
    ('Timeout consola', 'Cerrar sesiones inactivas de consola a los 5 minutos.'),
    ('Timeout auxiliar', 'Cerrar sesiones inactivas AUX a los 5 minutos.'),
    ('Banner de advertencia', 'Notificar el acceso restringido al equipo.'),
    ('Logging buffered', 'Mantener eventos de seguridad en el buffer local.'),
    ('TCP keepalives entrada', 'Detectar conexiones TCP entrantes interrumpidas.'),
    ('TCP keepalives salida', 'Detectar conexiones TCP salientes interrumpidas.'),
]

def cls():
    print('\033[2J\033[H', end='')

def line():
    print(C.DIM + '─' * 65 + C.RESET)

def header(title):
    cls()
    print(C.CYAN + C.BOLD + '  ╔' + '═' * 61 + '╗')
    print('  ║' + '  SR-2174 | CIS SECURITY AUDITOR v2.0'.ljust(61) + '║')
    print('  ╚' + '═' * 61 + '╝' + C.RESET)
    print(f'  {C.WHITE}{title}{C.RESET}')
    print(f'  {C.DIM}Cisco IOS 15 | Router R1-2174 | {HOST}{C.RESET}')
    line()

def connect():
    password = getpass('  Contrasena SSH del router: ')
    ssh = paramiko.SSHClient()
    # Laboratorio: idealmente sustituir por una clave de host verificada.
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(HOST, username=USER, password=password, timeout=12,
                look_for_keys=False, allow_agent=False,
                disabled_algorithms={'pubkeys':['rsa-sha2-256','rsa-sha2-512']})
    sh = ssh.invoke_shell(width=200, height=1000)
    time.sleep(1)
    drain(sh)
    command(sh, 'terminal length 0')
    return ssh, sh

def drain(sh):
    out=''
    while sh.recv_ready():
        out += sh.recv(65535).decode(errors='replace')
        time.sleep(.08)
    return out.replace('\r','')

def command(sh, cmd, delay=.7):
    sh.send(cmd+'\n')
    time.sleep(delay)
    return drain(sh)

def controls(cfg):
    def section(name):
        match=re.search(r'(?m)^line '+re.escape(name)+r'\s*\n((?:[ \t]+[^\n]*\n)*)',cfg)
        return match.group(1) if match else ''
    con,aux,vty=section('con 0'),section('aux 0'),section('vty 0 4')
    return [
        bool(re.search(r'(?m)^ip ssh version 2\s*$',cfg)),
        'login local' in vty and bool(re.search(r'(?m)^\s*transport input ssh\s*$',vty)),
        bool(re.search(r'(?m)^\s*exec-timeout 5 0\s*$',con)),
        bool(re.search(r'(?m)^\s*exec-timeout 5 0\s*$',aux)),
        bool(re.search(r'(?m)^banner motd\b',cfg)),
        bool(re.search(r'(?m)^logging buffered\b',cfg)),
        bool(re.search(r'(?m)^service tcp-keepalives-in\s*$',cfg)),
        bool(re.search(r'(?m)^service tcp-keepalives-out\s*$',cfg)),
    ]

def audit(sh, filename, title):
    header(title)
    print('  Recopilando configuracion de R1-2174...')
    cfg=command(sh,'show running-config',2)
    if 'version 15.2' not in cfg or 'hostname R1-2174' not in cfg:
        raise RuntimeError('No se recibio una configuracion completa; auditoria cancelada.')
    values=controls(cfg)
    rows=[]
    for i, ((name, purpose), ok) in enumerate(zip(CONTROLS,values), 1):
        status='CUMPLE' if ok else 'NO CUMPLE'
        color=C.GREEN if ok else C.RED
        print(f'  {i:02d}. {name:<32} {color}{status}{C.RESET}')
        print(f'      {C.DIM}{purpose}{C.RESET}')
        rows.append(f'{i:02d}. [{status}] {name}\n    Proposito: {purpose}')
    good=sum(values); pct=good/len(values)*100
    print();line()
    bar='█'*int(pct/5)+'░'*(20-int(pct/5))
    color=C.GREEN if pct==100 else C.YELLOW
    print(f'  CUMPLIMIENTO: {color}{bar} {pct:.1f}%{C.RESET}')
    print(f'  Aprobados: {good} | Pendientes: {len(values)-good} | Total: {len(values)}')
    stamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    report='\n'.join([
        'SR-2174 | AUDITORIA DE HARDENING',f'Fecha: {stamp}',
        f'Equipo: R1-2174 ({HOST})',
        'Referencia: seleccion de controles de seguridad para Cisco IOS 15',
        'Alcance: auditoria parcial, NO certificacion CIS','='*65,
        *rows,'='*65,
        f'Resultado: {good}/{len(values)} controles ({pct:.1f}%)',
        'Nota: validaciones sobre running-config; se requieren pruebas operativas adicionales.'
    ])
    path=REPORTS/filename
    path.write_text(report+'\n',encoding='utf-8')
    print(f'  {C.CYAN}Informe guardado: {path}{C.RESET}')
    return values

def apply(sh):
    cmds=[
        'configure terminal',
        'service tcp-keepalives-in',
        'service tcp-keepalives-out',
        'logging buffered 16384 informational',
        'banner motd #ACCESO RESTRINGIDO - SOLO PERSONAL AUTORIZADO#',
        'line con 0', 'exec-timeout 5 0','exit',
        'line aux 0','exec-timeout 5 0','exit',
        'end'
    ]
    print('\n  Aplicando controles correctivos...')
    for idx, cmd in enumerate(cmds,1):
        output=command(sh,cmd,.5)
        if re.search(r'% (Invalid|Error|Incomplete|Ambiguous)',output,re.I):
            print(f'  {C.RED}Fallo ejecutando: {cmd}{C.RESET}\n{output}')
            command(sh,'end')
            raise RuntimeError('Configuracion interrumpida; revisar router antes de reintentar.')
        print(f'  {C.GREEN}OK{C.RESET} {idx:02d}/{len(cmds)} - {cmd}')
    output=command(sh,'write memory',2)
    if '[OK]' not in output:
        print(C.YELLOW+'  Aviso: verificar manualmente que la configuracion se guardo.'+C.RESET)
    else:
        print(C.GREEN+'  Configuracion guardada en NVRAM.'+C.RESET)

def run(option):
    header('Conexion segura al dispositivo')
    ssh=None
    try:
        ssh,sh=connect()
        print(f'  {C.GREEN}Conexion SSH establecida.{C.RESET}')
        if option=='1':
            audit(sh,'auditoria_inicial.txt','AUDITORIA INICIAL - SOLO LECTURA')
        else:
            before=audit(sh,'auditoria_previa_aplicacion.txt','ESTADO PREVIO AL HARDENING')
            print('\n  Se aplicaran cambios de seguridad en el router.')
            print('  No se alterara DHCP, IP LAN ni acceso SSH VTY.')
            if input('  Escribe APLICAR para continuar: ').strip()!='APLICAR':
                print('  Operacion cancelada sin aplicar cambios.')
                return
            apply(sh)
            after=audit(sh,'auditoria_posterior.txt','AUDITORIA POSTERIOR')
            if sum(after)<len(after):
                print(C.YELLOW+'  Aviso: quedan controles pendientes; revisar antes de presentar.'+C.RESET)
            else:
                print(C.GREEN+'  8/8 controles seleccionados verificados.'+C.RESET)
    except (paramiko.SSHException, OSError, RuntimeError) as e:
        print(C.RED+f'  ERROR: {e}'+C.RESET)
    finally:
        if ssh: ssh.close()

def main():
    while True:
        header('MENU PRINCIPAL')
        print(f'  {C.CYAN}[1]{C.RESET} Auditar sin modificar el router')
        print(f'  {C.CYAN}[2]{C.RESET} Aplicar hardening y verificar')
        print(f'  {C.CYAN}[3]{C.RESET} Mostrar ultimo informe')
        print(f'  {C.YELLOW}[0]{C.RESET} Salir')
        line()
        option=input('  Seleccione opcion: ').strip()
        if option in ('1','2'):
            run(option)
        elif option=='3':
            header('ULTIMO INFORME')
            reports=sorted(REPORTS.glob('*.txt'),key=lambda p:p.stat().st_mtime,reverse=True)
            print(reports[0].read_text() if reports else '  No hay informes generados.')
        elif option=='0':
            print('  Hasta luego.')
            break
        else:
            print('  Opcion invalida.')
        input('\n  Presiona ENTER para volver al menu...')

if __name__=='__main__':
    main()
