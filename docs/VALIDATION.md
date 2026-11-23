# Validación de la copia pública

Fecha de preparación: 2026-11-23. Conjunto aprobado: 37 archivos de texto,
enumerados en PUBLIC_FILES.txt, sin Git, datos, binarios ni entorno virtual.
Los Excel y cachés locales presentes fuera de ese manifiesto no se publican.

## Entorno y dependencias

Entorno virtual nuevo, externo al árbol público y al proyecto privado:
Python 3.14.3 de 64 bits sobre Windows. No comparte paquetes del sistema.
Se instalaron requirements.txt y requirements-dev.txt; pip check terminó
sin dependencias incompatibles. Los logs y las dependencias resueltas completas
quedan fuera del árbol público. Los pins directos se conservaron; las dependencias
transitivas no están fijadas en un lockfile, por lo que futuras instalaciones
pueden resolver versiones distintas.

## Comprobaciones aprobadas

- 87 pruebas automatizadas; 0 fallos, 0 errores y 0 omitidas.
- Compilación en memoria de todos los archivos Python, sin crear bytecode.
- Antecedente de la preparación inicial: servidor Streamlit con health HTTP 200 / ok.
- Configuración efectiva: tema dark, fondo oscuro, dirección 127.0.0.1 y
  estadísticas de uso desactivadas. No se inició otro servidor en esta corrección.
- Ejecución como módulo desde la raíz: python -m scripts.generate_synthetic_excel synthetic_demo.xlsx.
- Prueba en un proceso Python nuevo, sin PYTHONPATH, con destino temporal.
- XLSX válido, hoja Synthetic Logs y 12 eventos; reejecución rechazada sin
  alterar bytes ni fecha de modificación del archivo existente.
- Inicio de interfaz sin Excel ni resultado precargado.
- Carga de bytes XLSX por el widget de AppTest y rechazo de un archivo inválido.
- Análisis, correlación, clasificación y filtros del dashboard con datos sintéticos.
- Generación de tres PDF en memoria, con título y autoría del producto.
- Seis secciones principales y asistencia IA deshabilitada por defecto.
- Proveedor de IA bloqueado durante la suite. Sin descargas de modelos ni inferencias.
- Runner aislado: acceso al proyecto privado prohibido y red externa/Ollama
  bloqueados; sin intentos detectados. Solo se permitió IPC loopback de asyncio.

La suite conserva fixtures sintéticas revisadas y añade integración sobre un
generador nuevo. Se excluyeron 11 tests y un helper dependientes del dataset
privado de los cuatro archivos de pruebas seleccionados. Otros diez archivos
de pruebas del origen se excluyeron completos por dependencia del caso o de
sus helpers; no se distribuyeron ni ejecutaron con datos privados.

Estos 87 tests constituyen una suite pública distinta: no reproducen ni certifican
los conteos del caso excluido. Los avisos ScriptRunContext de AppTest fuera del
servidor no se cuentan como fallos.

## Comprobaciones manuales informadas

El usuario informó cinco comprobaciones visuales manuales correctas de la
versión pública y confirmó carga, análisis, correlación, dashboard y tres PDF
funcionales, con IA deshabilitada por defecto. Se registra ese resultado como
evidencia aportada por el usuario; no se repitió la automatización del navegador
en esta intervención ni se inventan fechas u observaciones nuevas.

La verificación actual usa la suite pública. No se modificaron la aplicación,
el generador, sus eventos sintéticos ni los módulos de detección, correlación,
scoring, PDF o IA. No se validó rendimiento máximo, otras plataformas,
modelos locales ni calidad analítica de IA.

No se asignó licencia, no se inicializó Git y no se publicó contenido.

## Cierre de esta corrección

La suite actual terminó con 87 pruebas aprobadas, sin fallos, errores ni omitidas.
pip check no encontró incompatibilidades. Se compilaron en memoria 28 archivos
Python. La ejecución adicional como módulo, con PYTHONPATH ausente, produjo
un libro válido en una carpeta temporal y no dejó un dataset nuevo en el árbol.

El manifiesto conserva 37 archivos. Los 22 archivos locales fuera de él son
un Excel sintético y 21 cachés preexistentes: quedaron excluidos y sin cambios.
La revisión estática de las reglas de .gitignore cubre esos archivos y los
destinos habituales de datos, resultados y credenciales; no se ejecutó
git check-ignore ni se creó un repositorio para esa comprobación.

Se verificó que generador, app.py, los 21 módulos funcionales y las dependencias
declaradas permanecen sin cambios. El control de integridad del proyecto de
origen cotejó 517 archivos de proyecto y Git, sin altas, bajas ni cambios, y
conservó HEAD, status y remotos. Ese cotejo excluye su entorno y sus cachés.
Los logs y las huellas de control se guardaron fuera del conjunto publicable.
