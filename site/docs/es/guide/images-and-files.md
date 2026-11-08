<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 6f28736f9b01 -->
# Imágenes, archivos y texto con formato

Para quien copia algo más que texto sin formato. Una imagen, archivos de un gestor de archivos o texto con su formato, copiados en un dispositivo, pueden pegarse en los demás tal cual.

## Qué va adónde

| Lo copiado | Ordenadores con escritorio | Teléfonos | Un ordenador sin escritorio | Miembro ligero |
|---|---|---|---|---|
| Texto con su formato (un navegador, un programa de ofimática) | se pega con su formato | se pega como texto sin formato | texto sin formato | texto sin formato |
| Una imagen (PNG, JPEG; el TIFF de un Mac y el HEIC de un teléfono se convierten) | se pega como imagen | el botón de la app la pega; también llega sola, en el iPhone mientras la app se ejecuta | solo su texto; `cbb paste -o DIR` guarda la imagen | solo su texto; transmite la imagen |
| Archivos y carpetas | se pegan como archivos copiados | la app los guarda: en Descargas en Android, en la carpeta de la app en Archivos en el iPhone | `cbb paste -o DIR` los guarda | los transmite, no guarda ninguno |

Una copia con un texto y una imagen se envía como texto. Un cortar en un gestor de archivos se toma como una copia: no se borra nada en ningún sitio.

## Cómo viaja

La copia en sí se queda en el dispositivo donde se hizo. Los demás saben que hay una copia nueva, con su tamaño, y los que tienen la sincronización activada la traen enseguida de ese dispositivo, o de otro que la tenga, por las mismas conexiones cifradas que el texto.

Fuera de casa, el hub trae cada copia y la transmite por el túnel del grupo, hasta su propio límite.

## Tamaños

| Dónde | Por defecto | Cámbialo en cada dispositivo |
|---|---|---|
| En casa | 100 MiB por copia | `cbb config max-copy SIZE`, de 1 MiB a 1 GiB |
| Por el túnel del grupo | 25 MiB por copia | `cbb config max-copy-away SIZE`, como máximo `max-copy` |
| Desde el menú Compartir de los teléfonos | 100 MiB en Android, 50 MB desde el iPhone | no |

Una copia que supera el límite de un dispositivo no se trae a él, y `cbb status` lo indica. El `max-copy-away` del hub limita a todos los dispositivos que llegan a él desde lejos. Todos los límites están en [límites y duraciones](../reference/limits.md#copies).

## Desde la línea de comandos

```sh
cbb copy photo.jpg notes/              # sends files and folders as one copy
cbb copy -type png screenshot.png      # sends one image as an image
cbb paste -o ~/Downloads               # saves the clipboard's images or files there
cbb status                             # shows a copy that is still arriving
```

`cbb paste -o` espera mientras una copia sigue llegando, nunca sustituye un archivo y no hace ejecutable nada.

## Seguridad

- Los archivos recibidos se guardan en una carpeta propia dentro de la caché de tu usuario, legible solo por ti, y se eliminan 10 minutos después de una copia más reciente. Un Mac los marca como descargados (cuarentena) y Windows con la marca de la web (Mark of the Web), de modo que el sistema avisa antes de abrir un programa entre ellos. No se hace ejecutable nada.
- Los nombres se vuelven seguros para todos los sistemas, y los enlaces y archivos especiales de una carpeta se omiten.
- El formato de un secreto nunca se lee; un secreto se envía solo como texto sin formato.
- El servicio conserva la copia actual y las anteriores durante 10 minutos en su directorio de estado, y nada después de un reinicio.
