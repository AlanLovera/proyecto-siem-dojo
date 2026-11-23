# Preparación de proyecto-siem-dojo

Nombre previsto del repositorio: **proyecto-siem-dojo**.
Nombre de la aplicación: **DOJO SIEM Analyzer**.

Esta entrega no contiene .git ni historial. No se ejecutaron init, add, commit,
remote ni push. Los bloques siguientes son instrucciones para después de la
aprobación del conjunto exacto; no deben ejecutarse durante su preparación.

## Conjunto autorizado y archivos locales

PUBLIC_FILES.txt es la lista blanca exacta de 37 archivos aprobados.
Incluye código, configuración mínima, pruebas y documentación pública.
No agregar carpetas completas ni usar git add . o git add -A.

Los Excel generados o cargados, las cachés, resultados y PDF son archivos locales,
incluso si aparecen dentro de esta carpeta. No forman parte de la lista blanca.
.gitignore es una defensa adicional: no sustituye la revisión del staged ni
una auditoría de privacidad. Si se agrega una licencia u otro archivo, actualizar
y volver a aprobar inventario, conteo y auditoría antes de incorporarlo.

## Revisión antes de inicializar

Desde la raíz pública, comprobar el generador con el Python del entorno:

~~~powershell
python -m scripts.generate_synthetic_excel synthetic_demo.xlsx
~~~

El destino es posicional. No se configura PYTHONPATH. Si ya existe ese archivo,
el generador lo rechaza; usar otro nombre local para una nueva demostración.
Los libros generados nunca se incorporan al primer commit.

Revisar contenido de los 37 archivos y ejecutar las pruebas públicas. Las cinco
comprobaciones visuales satisfactorias fueron informadas por el usuario; no se
presentan como una inspección nueva del asistente en esta intervención.
No incorporar archivos dudosos hasta resolver su procedencia y privacidad.

## Identidad pública, aportada por el usuario

En GitHub Settings > Emails, copiar la dirección noreply exacta que proporciona
la cuenta. No inventarla ni derivarla del nombre de usuario. Elegir también un
nombre público para autor y committer. Ambos quedarán visibles en el commit.
La dirección noreply oculta el correo personal, pero puede identificar la cuenta.

Fuentes oficiales:
- [Correo de commits](https://docs.github.com/en/account-and-profile/how-tos/email-preferences/setting-your-commit-email-address).
- [Formatos noreply](https://docs.github.com/en/account-and-profile/reference/email-addresses-reference).

## Inicialización independiente, solo después de aprobar

Abrir PowerShell en la raíz pública. El script se detiene si faltan archivos,
si existe Git o si hay variables capaces de redirigirlo o sustituir identidades.

~~~powershell
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath PUBLIC_FILES.txt -PathType Leaf)) { throw 'Falta el inventario aprobado.' }
if (Test-Path -LiteralPath .git) { throw 'Ya existe Git: detener y revisar.' }
$gitOverrides = @(Get-ChildItem Env: | Where-Object {
    $_.Name -match '^(GIT_(DIR|WORK_TREE|COMMON_DIR|INDEX_FILE|OBJECT_DIRECTORY|ALTERNATE_OBJECT_DIRECTORIES|CONFIG.*|AUTHOR_.*|COMMITTER_.*)|EMAIL)$'
})
if ($gitOverrides.Count) { throw 'Revisar las variables de entorno de Git antes de continuar.' }
$approved = @(Get-Content -LiteralPath PUBLIC_FILES.txt -Encoding UTF8)
if ($approved.Count -ne 37 -or @($approved | Sort-Object -Unique).Count -ne 37) { throw 'Inventario inesperado.' }
foreach ($file in $approved) {
    if ([IO.Path]::IsPathRooted($file) -or $file -match '(^|/)\.\.(/|$)' -or -not (Test-Path -LiteralPath $file -PathType Leaf)) {
        throw 'Ruta ausente o no aprobada: revisar el inventario.'
    }
}
$publicName = Read-Host 'Nombre publico aprobado para el commit'
$publicEmail = Read-Host 'Direccion noreply exacta copiada de GitHub Settings > Emails'
if ([string]::IsNullOrWhiteSpace($publicName)) { throw 'Falta nombre publico.' }
if ($publicEmail -notmatch '^[^\s@]+@users\.noreply\.github\.com$') { throw 'Revisar el correo noreply.' }
# Este formato no prueba titularidad: cotejarlo con la cuenta real.
git init -b main
if ($LASTEXITCODE -ne 0) { throw 'No se pudo inicializar Git.' }
git config --local user.useConfigOnly true
git config --local user.name "$publicName"
git config --local user.email "$publicEmail"
git var GIT_AUTHOR_IDENT
git var GIT_COMMITTER_IDENT
git config --show-origin --get core.hooksPath
~~~

Confirmar que autor y committer son los aprobados. La ausencia de core.hooksPath
normalmente devuelve código 1 y utiliza .git/hooks; inspeccionar ese directorio.
Revisar también configuraciones globales heredadas. No continuar ante identidades,
hooks o redirecciones inesperadas.

## Incorporación exclusiva y revisión

En la misma sesión, incorporar únicamente el manifiesto aprobado:

~~~powershell
git --literal-pathspecs add --pathspec-from-file=PUBLIC_FILES.txt
if ($LASTEXITCODE -ne 0) { throw 'No se incorporaron todos los archivos: detener.' }
$staged = @(git -c core.quotepath=false diff --cached --name-only)
if (Compare-Object ($approved | Sort-Object) ($staged | Sort-Object)) {
    throw 'El contenido preparado no coincide con la lista blanca.'
}
git diff --cached --check
if ($LASTEXITCODE -ne 0) { throw 'Revisar errores del diff.' }
git status --short
git diff --cached --stat
git diff --cached
~~~

Leer el diff completo, incluidos ocultos y documentación. El staged debe contener
exactamente 37 archivos y ningún Excel, PDF, credencial, caché ni resultado local.
Los archivos ignorados pueden seguir existiendo en disco; no están aprobados
para el commit. Detenerse ante cualquier coincidencia dudosa.

## Único commit inicial, tras revisar el staged

~~~powershell
git commit -m "Initial public release"
if ($LASTEXITCODE -ne 0) { throw 'No se creó el commit inicial.' }
git rev-list --count HEAD
git log -1 --format=fuller
git status --short
git remote -v
~~~

El conteo debe ser 1, con autor y committer aprobados, sin cambios pendientes
versionables y sin remoto. No se reutiliza ni importa el historial académico.

## Vinculación posterior con GitHub

Después de la aprobación correspondiente, crear manualmente en la cuenta elegida
un repositorio vacío llamado proyecto-siem-dojo. Para conservar un solo historial
inicial, no crear en GitHub otro README, .gitignore o licencia automáticamente.
Copiar su URL HTTPS real desde GitHub; no se proporciona aquí una URL inventada.

Solo cuando ese repositorio exista y se autorice vincularlo:

~~~powershell
$remoteUrl = Read-Host 'URL HTTPS real del repositorio vacio proyecto-siem-dojo'
$remoteUri = [Uri]$remoteUrl
if (-not $remoteUri.IsAbsoluteUri -or $remoteUri.Scheme -ne 'https' -or $remoteUri.Host -ne 'github.com' -or
    $remoteUri.UserInfo -or $remoteUri.Query -or $remoteUri.Fragment -or
    $remoteUri.AbsolutePath -notmatch '^/[^/]+/proyecto-siem-dojo(?:\.git)?/?$') {
    throw 'Revisar la URL real del repositorio.'
}
if (@(git remote).Count) { throw 'Ya existe un remoto: detener y revisar.' }
git remote add origin "$remoteUrl"
if ($LASTEXITCODE -ne 0) { throw 'No se pudo vincular el remoto.' }
git remote -v
~~~

Vincular un remoto no publica los archivos. La transferencia queda para otra
intervención autorizada; esta guía se detiene antes del push.

[Guía oficial de GitHub sobre remotos](https://docs.github.com/en/get-started/git-basics/managing-remote-repositories).

## Licencia pendiente de decisión

No se incorpora un archivo LICENSE ni textos de licencias de terceros.
Opciones a evaluar por el titular, sin asignarlas automáticamente:

| Opción | Criterio y condiciones principales |
| --- | --- |
| MIT | Permisiva y breve; conservar avisos de copyright y licencia. |
| Apache-2.0 | Permisiva, con concesión expresa de patentes; conservar avisos y señalar modificaciones según sus términos. |

Consultar los textos completos antes de decidir:
[MIT](https://opensource.org/license/mit) y
[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).
No copiar nombres o avisos de terceros como si fueran autoría del proyecto.
