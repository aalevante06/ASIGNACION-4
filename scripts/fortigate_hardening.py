#!/usr/bin/env python3
"""SR-2174 FortiGate auditor - selected hardening checks, not a full CIS certification."""
import getpass
import re
import time
from pathlib import Path
from datetime import datetime
import paramiko

HOST = '10.21.74.2'
USER = 'admin'
OUTPUT = Path.home() / 'CIS-2174' / 'informes'
OUTPUT.mkdir(parents=True, exist_ok=True)

# Colores RGB (24 bits): evita que PuTTY convierta rojo/amarillo/gris en tonos ilegibles.
RESET='\033[0m'
CYAN='\033[38;2;100;225;230m'
GREEN='\033[38;2;100;225;155m'
RED='\033[38;2;255;125;125m'
ACCENT='\033[38;2;190;215;235m'
GRAY='\033[38;2;170;185;200m'
WHITE='\033[38;2;240;245;250m'
BOLD='\033[1m'
YELLOW=ACCENT


CONTROLS = [
    ('SSH v1 deshabilitado', 'Evita el protocolo SSH obsoleto.', 'ssh_v1'),
    ('Timeout administrativo <= 5 min', 'Cierra sesiones inactivas.', 'timeout'),
    ('Bloqueo tras <= 3 fallos', 'Limita intentos repetidos de inicio de sesión.', 'lockout'),
    ('HTTPS en interfaz administrativa', 'Permite administración cifrada por port3.', 'https'),
    ('TLS para HTTPS >= 1.2', 'No admite TLS 1.0/1.1 para la GUI.', 'https_tls'),
    ('Telnet global deshabilitado', 'Desactiva servicio administrativo inseguro.', 'telnet'),
    ('Registro de comandos CLI', 'Registra acciones administrativas en eventos.', 'cli_audit'),
    ('Registro de hora de acceso', 'Registra el momento de inicio de sesion administrativo.', 'login_stamp'),
]

def clean_screen():
    print('\033[2J\033[H',end='')

def rule():
    print(GRAY + '─' * 65 + RESET)

def headline(name):
    clean_screen()
    print(CYAN + BOLD + '  ╔' + '═' * 61 + '╗')
    print('  ║' + '  SR-2174 | FORTIGATE SECURITY AUDITOR v1.2'.ljust(61) + '║')
    print('  ╚' + '═' * 61 + '╝' + RESET)
    print(f'  {WHITE}{name}{RESET}')
    print(f'  {GRAY}FortiOS 7.0.9 | Firewall FGT-2174 | {HOST}{RESET}')
    rule()

def read_until_quiet(chan, timeout=20, quiet=0.7):
    start=time.monotonic(); last=time.monotonic(); chunks=[]
    while time.monotonic()-start < timeout:
        if chan.recv_ready():
            buf=chan.recv(65535).decode('utf-8',errors='replace')
            chunks.append(buf)
            last=time.monotonic()
        elif chunks and time.monotonic()-last >= quiet:
            break
        else:
            time.sleep(0.1)
    return ''.join(chunks).replace('\r','')

def cmd(chan, command, wait=20):
    chan.send(command+'\n')
    response=read_until_quiet(chan, timeout=wait)
    if re.search(r'(?im)(command fail|parse error|unknown action|return code\s+-\d+|error\s*:\s*|incomplete command)',response):
        raise RuntimeError(f'Comando rechazado: {command}\n{response[-900:]}')
    return response

def read_config(chan):
    # full-configuration muestra valores implícitos; no se recoge ni exporta la contraseña.
    global_cfg=cmd(chan,'show full-configuration system global',30)
    iface_cfg=cmd(chan,'show system interface',20)
    if 'config system global' not in global_cfg or 'config system interface' not in iface_cfg:
        raise RuntimeError('No se obtuvo toda la configuración para auditar.')
    return global_cfg,iface_cfg

def setting(config,key):
    match=re.search(r'^\s*set '+re.escape(key)+r'\s+([^\n]+)',config,re.M)
    return match.group(1).strip() if match else None

def evaluate(global_cfg, interfaces):
    port3=re.search(r'(?ms)^\s*edit "port3"\n(.*?)^\s*next\s*$',interfaces)
    access=setting(port3.group(1),'allowaccess') if port3 else None
    allowed_tls=(setting(global_cfg,'admin-https-ssl-versions') or '').split()
    val=setting(global_cfg,'admintimeout')
    lock=setting(global_cfg,'admin-lockout-threshold')
    results={
        'ssh_v1':setting(global_cfg,'admin-ssh-v1')=='disable',
        'timeout':bool(val and val.isdigit() and 1<=int(val)<=5),
        'lockout':bool(lock and lock.isdigit() and 1<=int(lock)<=3),
        'https':bool(access and 'https' in access.split() and 'http' not in access.split() and 'telnet' not in access.split()),
        'https_tls':bool(allowed_tls and all(x in ('tlsv1-2','tlsv1-3') for x in allowed_tls)),
        'telnet':setting(global_cfg,'admin-telnet')=='disable',
        'cli_audit':setting(global_cfg,'cli-audit-log')=='enable',
        'login_stamp':setting(global_cfg,'login-timestamp')=='enable',
    }
    return results

def audit(chan, filename, title):
    headline(title)
    print('  Recopilando configuración de FGT-2174...')
    glob, iface = read_config(chan)
    results = evaluate(glob, iface)
    lines = [
        'SR-2174 | AUDITORIA PARCIAL DE HARDENING - FORTIGATE',
        f'Fecha: {datetime.now().isoformat(timespec="seconds")}',
        f'Dispositivo: FGT-2174 | FortiOS 7.0.9 | IP: {HOST}',
        'Alcance: ocho comprobaciones seleccionadas; NO es una certificación CIS.',
        'Nota: TLS saliente global no incluido: comando no admitido en esta VM.',
        '-' * 65
    ]
    for index, (label, desc, key) in enumerate(CONTROLS, 1):
        ok = results[key]
        color = GREEN if ok else RED
        state = 'CUMPLE' if ok else 'NO CUMPLE'
        print(f'  {index:02d}. {WHITE}{label:<36}{RESET} {color}{state}{RESET}')
        print(f'      {GRAY}{desc}{RESET}')
        lines.append(f'{index:02d}. [{state}] {label}\n    Propósito: {desc}')
    count = sum(results.values())
    total = len(results)
    ratio = 100 * count / total
    print()
    rule()
    progress = int(ratio / 5)
    bar = '█' * progress + '░' * (20 - progress)
    score_color = GREEN if count == total else ACCENT
    print(f'  {WHITE}CUMPLIMIENTO:{RESET} {score_color}{bar} {ratio:.1f}%{RESET}')
    print(f'  {WHITE}Aprobados: {count} | Pendientes: {total-count} | Total: {total}{RESET}')
    lines += ['-' * 65, f'Resultado: {count}/{total} controles ({ratio:.1f}%)']
    path = OUTPUT / filename
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(f'  {CYAN}Informe guardado: {path}{RESET}')
    return results

def apply_controls(chan, results):
    changes=[]
    if not results['telnet']: changes.append(('admin-telnet','disable'))
    if not results['cli_audit']: changes.append(('cli-audit-log','enable'))
    if not results['login_stamp']: changes.append(('login-timestamp','enable'))
    # No tocar gestión remota, credenciales o interfaces para preservar acceso.
    if not changes:
        print(GREEN+'No hay correcciones automáticas pendientes entre los tres controles seguros.'+RESET)
        return
    print(WHITE+'  Aplicando correcciones seleccionadas...'+RESET)
    cmd(chan,'config system global')
    try:
        for setting_name,value in changes:
            cmd(chan,f'set {setting_name} {value}')
            print(GREEN+f'  OK: {setting_name} = {value}'+RESET)
    finally:
        cmd(chan,'end')

def main():
    while True:
        headline('MENÚ PRINCIPAL')
        print(f'  {CYAN}[1]{RESET} {WHITE}Auditar sin modificar el firewall{RESET}')
        print(f'  {CYAN}[2]{RESET} {WHITE}Aplicar hardening y verificar{RESET}')
        print(f'  {CYAN}[3]{RESET} {WHITE}Mostrar informe posterior{RESET}')
        print(f'  {ACCENT}[0]{RESET} {WHITE}Salir{RESET}')
        rule()
        choice = input('  Seleccione opción: ').strip()
        if choice == '0':
            print('  Hasta luego.')
            break
        if choice == '3':
            headline('ÚLTIMO INFORME - FORTIGATE')
            path = OUTPUT / 'fortigate_auditoria_posterior.txt'
            print(path.read_text(encoding='utf-8') if path.exists() else '  Aún no existe informe posterior.')
            input('\n  ENTER para volver al menú...')
            continue
        if choice not in ('1', '2'):
            print('  Opción inválida.')
            input('\n  ENTER para volver al menú...')
            continue
        password = getpass.getpass('  Contraseña de FortiGate: ')
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # Solo laboratorio
        try:
            ssh.connect(HOST, username=USER, password=password,
                        look_for_keys=False, allow_agent=False, timeout=12)
            chan = ssh.invoke_shell(width=180, height=1000)
            read_until_quiet(chan)
            if choice == '1':
                audit(chan, 'fortigate_auditoria_inicial.txt', 'AUDITORÍA INICIAL - SOLO LECTURA')
            else:
                before = audit(chan, 'fortigate_previa_aplicacion.txt', 'ESTADO PREVIO AL HARDENING')
                print(f'\n  {WHITE}Se corregirán Telnet global, auditoría CLI y registro de hora de acceso.{RESET}')
                print(f'  {GRAY}No se modificarán contraseñas, interfaces, SSH/HTTPS ni políticas.{RESET}')
                if input('  Escribe APLICAR para continuar: ').strip() == 'APLICAR':
                    apply_controls(chan, before)
                    after = audit(chan, 'fortigate_auditoria_posterior.txt', 'AUDITORÍA POSTERIOR')
                    if not all(after.values()):
                        print(RED + '  Atención: quedan controles pendientes.' + RESET)
                    else:
                        print(GREEN + '  8/8 controles seleccionados verificados.' + RESET)
                else:
                    print('  No se aplicaron cambios.')
        except Exception as ex:
            print(RED + f'  ERROR: {ex}' + RESET)
        finally:
            ssh.close()
        input('\n  ENTER para volver al menú...')

if __name__ == '__main__':
    main()
