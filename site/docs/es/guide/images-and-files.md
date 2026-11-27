<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: ee7b34adad9e -->
# Imágenes, archivos y texto con formato

Para cualquiera que copie algo más que texto sin formato. En esta página aprendes qué tipos de contenido se sincronizan entre ordenadores y teléfonos, cómo enviar y guardar imágenes y archivos desde la línea de comandos o un teléfono, y cómo cambiar los límites de tamaño por dispositivo.

Cuando copias una imagen, archivos de un gestor de archivos o texto con formato en un dispositivo, el dispositivo que copia sella el contenido de extremo a extremo y lo anuncia a tu grupo. Los demás dispositivos con **Sincronizar** activado lo obtienen automáticamente hasta sus límites de tamaño. Para saber cómo funciona el cifrado de extremo a extremo, consulta [Cómo funciona](how-it-works.md#what-happens-when-you-copy).

## Qué va adónde

| Contenido copiado | Ordenadores con escritorio | Teléfonos | Ordenadores y dispositivos pequeños sin escritorio |
|---|---|---|---|
| **Texto con formato** (HTML de un navegador o una app de ofimática) | Se pega con formato (hasta 8 MiB de HTML) | Se pega como texto sin formato | Texto sin formato |
| **Imagen** (PNG, JPEG, GIF; TIFF en macOS y HEIC en teléfonos se convierten) | Se pega directamente como imagen | Se sincroniza con el portapapeles cuando abres **CBB** o tocas el botón de sincronización; también se guarda en la galería en Android y Aurora OS o en **Fotos** en el iPhone cuando se recibe como archivo | Solo texto sin formato; guarda la imagen con `cbb paste -o DIR` |
| **Archivos y carpetas** | Se pegan como archivos en un gestor de archivos o en una app | **Android:** se guardan en `Downloads/CBB` (una sola imagen o un solo vídeo va al álbum `CBB` de la galería). **iPhone:** se guardan en **Archivos > En mi iPhone > CBB** (una sola imagen o un solo vídeo va a **Fotos**). **Aurora OS:** se guardan en `Downloads/CBB` (las imágenes, en la galería). **HarmonyOS:** se guardan con el botón **Guardar los archivos recibidos** | Guárdalos con `cbb paste -o DIR` |

Cortar archivos en un gestor de archivos se trata como una copia: Connect Beyond Borders nunca borra los archivos originales en ningún dispositivo. Cuando el portapapeles de un ordenador de escritorio contiene a la vez texto y una imagen sin selección de archivos aparte, el texto sin formato tiene prioridad salvo que se copie una imagen de forma explícita.

## Enviar y guardar desde un teléfono

1. **Enviar archivos o imágenes desde un teléfono:** Abre un gestor de archivos, la galería u otra app, elige **Compartir > Connect Beyond Borders** y confirma si te lo pide. En Android, iPhone, Aurora OS y HarmonyOS, las imágenes y los archivos compartidos se sincronizan con los ordenadores de tu grupo.
2. **Guardar archivos recibidos en un teléfono:** Abre **CBB** (o activa la sincronización). En Android, iPhone y Aurora OS, los archivos se guardan automáticamente en las ubicaciones de la tabla anterior. En HarmonyOS, toca **Guardar los archivos recibidos** en **Inicio** cuando te avise de que hay archivos listos.

**Resultado:** Las imágenes compartidas aparecen en el portapapeles de tus ordenadores, y los archivos recibidos aparecen en la carpeta de descargas, de archivos o de la galería de tu teléfono.

## Enviar y guardar desde la línea de comandos

Ejecuta estos comandos en cualquier ordenador o dispositivo pequeño sin `sudo`:

1. **Enviar archivos y carpetas como una sola copia:**

   ```sh
   cbb copy photo.jpg notes/
   ```

   Añade `-text "summary"` para incluir un texto alternativo sin formato para los dispositivos que solo admiten texto.

   **Resultado:** Connect Beyond Borders imprime cuántos archivos y bytes ha copiado al grupo.

2. **Enviar una sola imagen o un archivo HTML como datos del portapapeles:**

   ```sh
   cbb copy -type png screenshot.png
   ```

   `-type` acepta `png`, `jpeg` (o `jpg`), `gif` o `html`.

   **Resultado:** Los ordenadores de escritorio reciben el archivo como datos de imagen o HTML en el portapapeles en lugar de como un archivo adjunto.

3. **Guardar las imágenes o los archivos actuales del portapapeles en una carpeta:**

   ```sh
   cbb paste -o ~/Downloads
   ```

   **Resultado:** `cbb` espera si la copia todavía se está transfiriendo, escribe los archivos y las carpetas con sus nombres (o `image.png`, `image.jpg`, `image.gif` o `clipboard.html` para datos del portapapeles) e imprime cada ruta de nivel superior que ha creado. Nunca sobrescribe archivos existentes y no hace ejecutable nada.

4. **Comprobar el progreso de la transferencia:** Ejecuta `cbb status` para ver si una copia grande todavía está llegando o si se ha omitido por superar el límite de tamaño de este dispositivo.

## Cambiar los límites de tamaño

Cada dispositivo aplica sus propios límites de tamaño para imágenes y archivos. Fuera de casa, el límite `max-copy-away` del hub limita a todos los dispositivos que se conectan a través de ese hub.

| Ámbito | Por defecto | Rango permitido | Cómo cambiarlo |
|---|---|---|---|
| **En casa** (ordenadores y dispositivos pequeños) | 100 MiB por copia | De 1 MiB a 1 GiB | `cbb config max-copy SIZE` |
| **Por el túnel del grupo** (ordenadores, dispositivos pequeños y hubs) | 25 MiB por copia | De 1 MiB a `max-copy` | `cbb config max-copy-away SIZE` |
| **Hoja Compartir del teléfono** | 100 MiB en Android; 50 MB en iPhone, Aurora OS y HarmonyOS | Fijo | No se puede cambiar |

Para ver o cambiar los límites en un ordenador:

1. Consulta los límites actuales:

   ```sh
   cbb config
   ```

2. Sube o baja un límite (por ejemplo, a 250 MiB en casa o a 50 MiB fuera de casa):

   ```sh
   cbb config max-copy 250MiB
   cbb config max-copy-away 50MiB
   ```

**Resultado:** El dispositivo aplica el nuevo límite de inmediato. Bajar `max-copy` por debajo de `max-copy-away` baja también `max-copy-away` para igualarlo. Las copias mayores que el límite de un dispositivo no se obtienen en ese dispositivo, y `cbb status` indica que la copia se omitió.

Para consultar todos los límites de tamaño y de partes de una copia (incluido el límite de 10 000 partes y el límite de 256 KiB para el texto alternativo), consulta [Límites y duraciones](../reference/limits.md#copies).

## Seguridad

- **Almacenamiento temporal privado:** En ordenadores de escritorio, el agente del portapapeles descomprime los archivos recibidos en una carpeta privada dentro de tu caché de usuario (`~/.cache/cbb/received` en Linux y FreeBSD, `~/Library/Caches/cbb/received` en macOS, `%LocalAppData%\cbb\received` en Windows), legible solo por tu usuario, y borra las carpetas de copias anteriores 10 minutos después de que llegue una copia más nueva.
- **Avisos de descarga:** Los archivos recibidos nunca se marcan como ejecutables. macOS añade el atributo `com.apple.quarantine` y Windows añade la Marca de la Web (`Zone.Identifier`) para que el sistema operativo avise antes de abrir un programa recibido.
- **Nombres de archivo seguros:** Connect Beyond Borders sanea los nombres de archivo entre sistemas operativos y omite los enlaces simbólicos y los archivos especiales dentro de las carpetas copiadas.
- **Secretos como texto sin formato:** Nunca se lee el formato de los secretos; un secreto viaja solo como texto sin formato.
- **Caché del servicio:** El servicio en segundo plano conserva como máximo los últimos 8 bloques sellados de copias en su directorio de estado mientras está en marcha y vacía esa caché en cada reinicio.
