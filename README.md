# DOJO SIEM Analyzer

Aplicación local y educativa para importar un exportado Excel de eventos SIEM,
revisar calidad de datos, aplicar reglas explicables, correlacionar actividad,
explorar un dashboard y generar informes PDF con trazabilidad.
Contexto académico: Comunidad DOJO. El caso de estudio de desarrollo se declara
ficticio; sus datos, informes e historial privado no forman parte de esta copia.

## Tecnologías y requisitos

Python, Streamlit, pandas, openpyxl, Plotly, ReportLab y jsonschema.
Las dependencias directas están fijadas en requirements.txt. Para pruebas se
agregan pypdf y pypdfium2 desde requirements-dev.txt. No se incluyen bibliotecas,
fuentes, modelos ni entornos de terceros en el árbol público.

Entorno de validación: Windows y Python 3.14.3 de 64 bits. No se ha validado una
matriz de plataformas o versiones de Python. No se requieren Git, el Excel del
caso de estudio ni Ollama para iniciar la interfaz.

## Instalación local

Desde la raíz de esta carpeta en PowerShell:

~~~powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
~~~

No es necesario activar el entorno ni cambiar la política de ejecución.
Abrir la dirección local que informe Streamlit. La configuración limita el
servidor a 127.0.0.1, aplica tema oscuro y desactiva estadísticas de uso.

## Datos de demostración y procedencia

No se distribuye el Excel del caso de estudio. Su procedencia y autorización
para redistribución no se han establecido para esta versión pública. Tampoco
se distribuyen copias de sus filas, snapshots, PDF o resultados esperados.

El generador incluido crea **12 eventos completamente sintéticos**, definidos
en código sin leer ningún dataset externo. Usa identificadores SYNTH-, cuentas
de laboratorio inventadas, fecha artificial y direcciones de documentación.
Los comandos de los logs son texto inerte; no se ejecutan. El libro tiene
metadatos de autoría del producto, sin identidad de la máquina.

Comando canónico desde la raíz del proyecto, usando el Python del entorno con
las dependencias instaladas:

~~~powershell
python -m scripts.generate_synthetic_excel synthetic_demo.xlsx
~~~

Si el entorno no está activado, usar su intérprete explícitamente:

~~~powershell
.\.venv\Scripts\python.exe -m scripts.generate_synthetic_excel synthetic_demo.xlsx
~~~

La ejecución como módulo funciona sin configurar PYTHONPATH. El destino es un
argumento posicional; no existe una opción --output. Si el archivo ya existe,
la ejecución falla sin cambiar sus bytes ni su fecha de modificación.

El Excel generado queda ignorado por Git y fuera de PUBLIC_FILES.txt.
Este ejemplo sirve para recorrer la interfaz; no reproduce los conteos ni los
resultados del caso de estudio excluido, ni cubre todas las reglas.

## Excel esperado y recorrido

Solo .xlsx, con cabecera en la primera fila y estas columnas exactas:

~~~text
Log_ID, Timestamp, Hostname, Event_ID, User, Source_IP, Destination,
Log_Source, Event_Description, Process_CommandLine, Result, Severity
~~~

Se conservan columnas adicionales y valores originales. Timestamp admite
fechas Excel o texto AAAA-MM-DD HH:MM:SS; no se atribuye zona horaria a logs
sin ella. Los timestamps con zona no se mezclan silenciosamente con relojes
sin zona. Las fórmulas y errores se conservan y señalan, sin evaluarlos.
Los identificadores, los nombres de fuentes y los campos de comando deben
coincidir con las condiciones de las reglas; no existe mapeo universal de SIEM.

1. Cargar manualmente synthetic_demo.xlsx y elegir Synthetic Logs.
2. Revisar calidad, vista previa, filtros, archivo, hoja, fila y SHA-256.
3. Pulsar **Analizar registros** y **Correlacionar y clasificar**.
4. Explorar el dashboard y abrir evidencia; sus filtros no recalculan el motor.
5. En Informes PDF, elegir nombre y fecha de emisión y generar los tres informes.
6. Mantener Asistencia IA deshabilitada durante la validación pública.

## Funcionalidades y límites

Reglas parametrizables para fallos de autenticación, secuencias RDP, indicadores
de comandos, accesos a archivos, POST salientes, tareas/servicios, procesos
recurrentes y solicitudes IIS. La correlación conserva criterios, referencias,
solapamientos, criticidad heurística y confianza. Se generan PDF corporativo,
técnico y consolidado desde un snapshot común en memoria.

Una activación o asociación no confirma incidente, malware, exfiltración,
causalidad ni ejecución remota. El scoring no está calibrado para producción;
la cobertura depende de campos disponibles y de los formatos reconocidos.
La ausencia de registros no demuestra ausencia de actividad. No hay atribución
ni geolocalización de direcciones de documentación.

Límites de entrada: 20 MiB de archivo, 100 MiB descomprimidos, 100.000 filas y
100 columnas; son límites de admisión, no promesas de rendimiento. La correlación
aplica límites adicionales y rechaza entradas excesivas sin truncarlas en silencio.
Los datos permanecen en memoria de sesión hasta su descarga o cierre; no hay
base de datos. Una exportación conserva datos y nombres suministrados por el
operador: revisarlos antes de compartir cualquier archivo generado.

## IA local experimental

Opcional y deshabilitada por defecto. El análisis y los PDF funcionan sin ella.
El cliente solo consulta Ollama en loopback tras acciones explícitas; no descarga
modelos. Tiene controles de modelo local, presupuesto y esquema. Puede rechazar
plantillas o tokenizadores no verificados. La calidad analítica del modelo no
está validada; sus propuestas requieren revisión humana y no alteran las reglas,
el scoring ni los PDF. Esta preparación no ejecuta inferencias ni valida modelos.

## Pruebas

~~~powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
~~~

Todas las fixtures públicas son sintéticas. La suite prueba importación,
normalización, límites de reglas, correlación, clasificación y un flujo de UI
con carga por widget, dashboard, informes y acceso a IA bloqueado. La suite también ejecuta el generador como módulo en un proceso Python nuevo,
sin PYTHONPATH, valida el XLSX y comprueba la protección contra sobrescritura.
AppTest simula la interfaz; no sustituye la revisión del navegador ni del selector nativo.
Las regresiones que requieren el dataset excluido no se distribuyen ni se
presentan como ejecutadas en esta copia.

## Privacidad, publicación y licencia

Nombre previsto del repositorio: **proyecto-siem-dojo**. El branding de la
aplicación permanece **DOJO SIEM Analyzer**. Git todavía no está inicializado.

[Auditoría y alcance](docs/PRIVACY_REVIEW.md),
[validación](docs/VALIDATION.md) y
[preparación de un repositorio nuevo](docs/PUBLICATION.md).

No se asignó licencia al proyecto. Las alternativas y sus condiciones se
presentan por separado en la guía de publicación para decisión del titular.
Las dependencias mantienen sus propias licencias; no se incluyen sus paquetes
ni se presume que una futura licencia del proyecto las sustituya.
