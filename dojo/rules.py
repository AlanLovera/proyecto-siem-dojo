"""Catálogo versionado y parámetros de las reglas deterministas del motor de detección."""

from copy import deepcopy


PATTERNS = ("powershell_encoded", "shadow_delete", "discovery", "compression", "shell_identity")


def spec(name, defaults, conditions, limitations, alternatives):
    return dict(name=name, defaults=defaults, conditions=conditions,
                limitations=limitations, alternatives=alternatives)


RULES = {
    "R01": spec(
        "Autenticaciones fallidas múltiples / posible spraying",
        dict(window_seconds=900, min_failures=5, min_users=3),
        "4625 con Result=Failure, mismo host e IP y usuarios conocidos. Ventanas acotadas; distingue una cuenta de múltiples cuentas.",
        ["No demuestra password spraying ni acceso no autorizado; sin contraseña intentada ni ID de sesión.",
         "Los éxitos se muestran solo si son posteriores y coinciden host, IP y una cuenta afectada dentro de la misma ventana."],
        ["Credenciales obsoletas en servicios o clientes.", "Errores de usuarios o pruebas autorizadas."],
    ),
    "R02": spec(
        "Fallos RDP seguidos de autenticación exitosa",
        dict(window_seconds=900, min_failures=3),
        "4625/Failure con RDP o LogonType=10 explícito, seguidos estrictamente de 4624/Success también RDP; mismo host, IP, usuario y destino.",
        ["La sucesión temporal no demuestra fuerza bruta exitosa ni identidad del operador.",
         "No se enlazan procesos posteriores, sesiones ni otros hosts/IP."],
        ["Usuario autorizado que corrigió la contraseña.", "Prueba de acceso remoto autorizada."],
    ),
    "R03": spec(
        "Comandos y procesos que requieren revisión",
        dict(min_patterns=1, patterns=list(PATTERNS)),
        "4688 o 4104 con patrones de comando reconocidos; un indicador individual por registro, sin correlación temporal.",
        ["El texto de un comando o script no acredita ejecución exitosa ni sus efectos.",
         "No se decodifica PowerShell ni se ejecuta contenido. Los patrones no son un detector universal de malware."],
        ["Administración, respaldo, inventario o soporte legítimos."],
    ),
    "R04A": spec(
        "Accesos repetitivos a archivos distintos",
        dict(window_seconds=300, min_events=5, min_files=5),
        "4663 con File access: o Detailed file share access: explícito; mismo host, usuario, IP y destino; cantidad y archivos distintos mínimos.",
        ["4663 registra un acceso/intento a objeto; no acredita copia de archivos ni cifrado.",
         "Se requiere una ruta explícita; no se inventan archivos a partir del destino."],
        ["Respaldo, indexación, antivirus o trabajo legítimo con documentos."],
    ),
    "R04B": spec(
        "Serie de POST salientes con bytes registrados",
        dict(window_seconds=600, min_posts=5, min_bytes=1048576),
        "PROXY_ACCESS/Proxy, descripción HTTP(S) POST outbound, Result=Allowed o HTTP 2xx, bytes_out entero no negativo; mismo host, usuario, IP y destino.",
        ["Los bytes registrados no identifican contenido ni prueban exfiltración o prohibición.",
         "Compresión previa se agrega solo como contexto si coincide host/usuario/IP y la ventana completa. No se atribuye contenido a un archivo."],
        ["Carga legítima a un servicio, copia de seguridad o intercambio autorizado."],
    ),
    "R05A": spec(
        "Creación de tarea programada o instalación de servicio",
        dict(event_ids=["4698", "7045"]),
        "Un registro 4698 o 7045 seleccionado; señal individual descriptiva, sin inferir persistencia maliciosa.",
        ["La creación/instalación registrada no determina autorización, ejecución posterior ni naturaleza maliciosa."],
        ["Instalador, actualización, soporte o administración autorizada."],
    ),
    "R05B": spec(
        "Creaciones recurrentes de un mismo proceso",
        dict(window_seconds=1800, min_executions=3),
        "4688 con ejecutable explícito repetido; misma ruta literal normalizada, host, usuario e IP dentro de una ventana acotada.",
        ["La recurrencia no demuestra persistencia, periodicidad exacta o malware.",
         "No se equipara un basename con una ruta completa ni se vincula automáticamente a tareas o servicios."],
        ["Proceso normal recurrente, tarea legítima o aplicación reiniciada."],
    ),
    "R06A": spec(
        "Parámetros de comando en solicitudes web",
        dict(window_seconds=300, min_requests=1),
        "HTTP_ACCESS/IIS con parámetro cmd, exec o command no vacío en una URL; mismo host e IP.",
        ["Una solicitud o HTTP 200 no acredita compromiso ni ejecución.", "Se decodifica URL una sola vez, sin ejecutar el valor."],
        ["Escaneo, prueba autorizada o parámetro legítimo de la aplicación."],
    ),
    "R06B": spec(
        "Solicitud con comando y proceso posterior bajo IIS",
        dict(window_seconds=300, min_requests=1),
        "Solicitud sospechosa seguida estrictamente de 4688 bajo IIS APPPOOL, mismo host/IP y comando textual coincidente; ventana inclusiva máxima.",
        ["Es coincidencia de contexto, comando y tiempo; falta relación solicitud/proceso y cadena padre-hijo para demostrar RCE.",
         "El resto de solicitudes en esa ventana se incluye como contexto, sin calificarlas todas de sospechosas."],
        ["Prueba controlada o actividad independiente con comando coincidente."],
    ),
}


def parameter_max(key):
    return 10**15 if key == "min_bytes" else 604800 if key == "window_seconds" else 100000


def parameters(overrides=None):
    config = {rule: deepcopy(info["defaults"]) for rule, info in RULES.items()}
    for rule, values in (overrides or {}).items():
        if rule not in RULES or not isinstance(values, dict):
            raise ValueError(f"Regla o configuración inválida: {rule}")
        for key, value in values.items():
            if key not in config[rule]:
                raise ValueError(f"Parámetro desconocido: {rule}.{key}")
            config[rule][key] = deepcopy(value)
    for rule, values in config.items():
        for key, value in values.items():
            if key in ("patterns", "event_ids"):
                allowed = PATTERNS if key == "patterns" else ("4698", "7045")
                if not isinstance(value, list) or not value or any(x not in allowed for x in value) or len(set(value)) != len(value):
                    raise ValueError(f"Lista inválida: {rule}.{key}")
                values[key] = sorted(value)
            elif type(value) is not int or not 1 <= value <= parameter_max(key):
                raise ValueError(f"{rule}.{key} debe ser entero entre 1 y {parameter_max(key)}.")
        if rule == "R01" and values["min_users"] < 2:
            raise ValueError("R01.min_users debe ser al menos 2 para distinguir múltiples cuentas.")
    return config
