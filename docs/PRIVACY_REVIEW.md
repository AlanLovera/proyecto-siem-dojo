# Alcance de la revisión de privacidad

Copia pública preparada mediante selección explícita de archivos y transformación
en memoria antes de escribirlos. No se copió un árbol completo ni se utilizó Git
para trasladar historial. El inventario exacto se encuentra en PUBLIC_FILES.txt.

Se sustituyó el título identificatorio por DOJO SIEM Analyzer. Las cabeceras,
metadatos de autor/título y nombres de descarga de futuros PDF usan el producto.
Se preparó documentación nueva con rutas relativas; no se copió documentación
privada ni metadatos NTFS del origen. Solo se conservaron tests cuyo código genera
fixtures sintéticas verificables; las regresiones del caso excluido se retiraron.

Excluidos: historial y configuración Git, dataset de estudio, filas exportadas,
PDF existentes, paquete de entrega, capturas, informes, snapshots, logs,
entornos, cachés, secretos y scripts ligados a datos privados o inferencias.
La configuración oculta incluida es únicamente .gitignore y la configuración
visual y local de Streamlit. No se distribuyen binarios ni libros Excel.

La revisión combina inventario, extensión y tipo de archivo, decodificación de
todo el árbol, inspección de configuración, documentación, comentarios y cadenas,
búsquedas de identificadores privados y posibles secretos, y revisión estática
de rutas y accesos a archivos. Los SHA-256 detectan cambios del conjunto auditado;
no demuestran por sí solos privacidad o legitimidad.

Los datos nuevos se definen íntegramente en el generador público: no leen ni
transforman registros del caso excluido. Las cuentas, hosts, fechas y comandos
son inventados. Las IP de las fixtures pertenecen a rangos de documentación y
los comandos no se ejecutan. No se incorporan datos de terceros sin procedencia.

Una búsqueda por patrones no garantiza anonimización completa. Queda pendiente
la revisión humana del conjunto exacto y de cada adición futura. El nombre de
la cuenta pública de GitHub, la identidad de commit y el contenido cargado por
el operador pueden revelar identidad. Los informes generados conservan evidencia
y nombres de origen: deben revisarse antes de compartirse.

Resultados de ejecución y limitaciones: VALIDATION.md. No se asignó licencia,
no se inicializó Git y no se publicó contenido.

## Resultado del conjunto preparado

Revisión de 37 archivos UTF-8, incluidos los ocultos y todos los módulos,
comentarios, pruebas y documentación. El conjunto aprobado no contiene binarios,
enlaces simbólicos ni historial. Los Excel y cachés locales fuera del manifiesto
se distinguen de los 37 archivos aprobados y no se incorporan a Git. No se encontraron identificadores
privados conocidos del desarrollador, SID, rutas de perfil personales,
correos personales ni patrones reconocibles de claves o tokens.

Se revisaron expresamente las coincidencias restantes: rutas genéricas de
Windows y UNC en fixtures sintéticas, loopback local y direcciones reservadas
de documentación. La cadena hexadecimal estática del cliente IA es una huella
de plantilla utilizada por el control de presupuesto; no es una credencial.
Los enlaces de documentación de GitHub y de opciones de licencia se verificaron
contra sus páginas oficiales. Las instrucciones no incluyen correos inventados.

El resultado se limita al conjunto inventariado y a los controles descritos.
No constituye una garantía absoluta de anonimización ni reemplaza la revisión
humana antes de publicar.


## Revisión del generador y preparación de proyecto-siem-dojo

La forma documentada es python -m scripts.generate_synthetic_excel synthetic_demo.xlsx,
desde la raíz y sin PYTHONPATH. El destino es posicional. La nueva prueba ejecuta
un intérprete independiente y crea su XLSX solo en un directorio temporal.
No se cambió el generador ni el contenido analítico de sus eventos.

La lista blanca permanece en 37 archivos de texto. No se agregaron datos,
credenciales, enlaces de repositorio inventados ni direcciones noreply supuestas.
La guía solicita al usuario su identidad y URL reales únicamente para una
inicialización y vinculación futuras, después de aprobarlas.

.gitignore excluye Excel, PDF, entornos, variables de entorno, credenciales,
cachés, logs, resultados estructurados y directorios de datos locales.
Ningún archivo de la lista blanca queda excluido. Las reglas no garantizan
privacidad: se revisan contenido y staged antes de cualquier commit.

Las cinco comprobaciones visuales satisfactorias fueron informadas por el
usuario; se mantiene la distinción respecto de las pruebas automatizadas.

El cierre mantiene 37 archivos aprobados sin coincidencias privadas pendientes.
Los 22 archivos locales excluidos son un libro sintético y 21 cachés. Los .pyc
pueden contener rutas de la máquina; no se publican ni se incorporan al manifiesto.
Los 37 archivos aprobados no tienen flujos NTFS alternativos. El inventario
se mantiene como lista exacta para el futuro primer commit.
