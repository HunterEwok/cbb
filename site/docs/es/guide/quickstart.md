<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: e8caf339efb7 -->
# Inicio rápido

Copy Beyond Borders da a tu teléfono y a tus ordenadores un único portapapeles: copias en uno y pegas en otro. Los dispositivos forman un **grupo** en tu red doméstica. El teléfono guarda la clave del grupo y deja entrar a cada dispositivo nuevo, así que nadie puede unirse sin ti.

![Cada ordenador se une al grupo del teléfono con los seis dígitos que muestra el teléfono; después los dispositivos comparten un portapapeles](../images/group.svg)

Son cuatro pasos: instalar la app y crear el grupo, instalar Copy Beyond Borders en un
ordenador, escribir en el ordenador los seis dígitos que muestra el teléfono, y copiar.

Un grupo puede tener un ordenador en su centro o estar hecho solo de teléfonos: ambos funcionan,
y recomendamos un ordenador que esté encendido a menudo, que mantiene la sincronización fuera de
casa en todo momento ([dos tipos de grupo](how-it-works.md#two-kinds-of-group)).
Solo con teléfonos, sáltate los pasos 2 y 3: toca **+** en el primer teléfono y, en cada uno de
los demás, toca **Unirse a un grupo** y escanea el código que muestra el primero.

## 1. Instala la app en el teléfono

- **Android** 10 o posterior: descarga `cbb-X.Y.Z.apk` desde la [última versión](https://github.com/HunterEwok/cbb/releases/latest) en el propio teléfono y ábrelo; cuando Android lo pida, permite que el navegador instale aplicaciones.
- **iPhone**: la app llegará con TestFlight, que todavía no está abierto. Hasta entonces, un grupo empieza en Android o en un ordenador: consulta [Sin la app](without-app.md).

Abre la app y toca **Crear un grupo**. La app crea la clave del grupo (te pide la huella, la
cara o el código) y luego pregunta cómo guardar la clave de recuperación: **Escribir en una
hoja** o **Escribir en una YubiKey**. Guárdala lejos de tus dispositivos; recupera el grupo si
pierdes el teléfono ([claves](keys.md)).

## 2. Instala Copy Beyond Borders en un ordenador

Elige cualquier ordenador de tu red doméstica: un portátil, un sobremesa, una Raspberry Pi.

En **Linux** o en un **Mac**, en una terminal:

```sh
curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
```

En **Windows** 10 u 11, en un PowerShell abierto con «Ejecutar como administrador»:

```powershell
irm https://github.com/HunterEwok/cbb/releases/latest/download/get.ps1 | iex
```

El instalador comprueba la descarga, inicia Copy Beyond Borders y hace dos preguntas: si abrir el cortafuegos para él (responde `y`) y si debe actualizarse automáticamente (`y` también es una buena respuesta). Después, cierra sesión y vuelve a entrar una vez, o abre una terminal nueva en Windows. Homebrew, Docker y los detalles están en [Instalación](install.md).

## 3. Añade el ordenador

En la app, toca **+** (Añadir un dispositivo). Muestra un código QR y seis dígitos debajo, y
espera unos minutos.

En el ordenador:

```sh
sudo cbb pair -code
```

En Windows, ejecuta `cbb pair -code` en la terminal de administrador. Escribe los seis dígitos:
el ordenador encuentra la ventana de emparejamiento del teléfono en la red de casa y se une. O,
sin terminal, abre la app CBB en el ordenador (la app de la bandeja en Windows y Linux, la de la
barra de menús en un Mac), haz clic en **Unirse a un grupo** y escribe ahí los dígitos; antes
pide la contraseña del administrador.

Añade cada otro ordenador igual: instalar, **+** en la app y `sudo cbb pair -code`.

## 4. Copia en uno, pega en otro

Lo que copias en el ordenador llega al grupo, y lo que copia el grupo llega a él. Copia en el ordenador y pega en el teléfono, o al revés:

- **Android** recibe por sí solo lo que copian los ordenadores. Para enviar lo que copia el teléfono, pulsa el botón grande de Inicio de la app, el icono **Send clipboard** de Ajustes rápidos o Send en la notificación; o activa **Send my copies by themselves** en la app para que se haga solo.
- **Entre ordenadores**: copia en uno y pega en otro. No hay nada que pulsar.

Para que el portapapeles de un dispositivo sea solo suyo durante un tiempo, desactiva la sincronización: el botón de la casa en la primera pantalla de la app, o `cbb sync off` ([los comandos](../reference/cli.md#cbb)). El resto de lo que hacen las apps está en [Las apps](apps.md).

## 5. Recomendado: deja que un ordenador siempre encendido ayude al teléfono

El grupo funciona solo con el teléfono, pero dos cosas mejoran con un ordenador que se queda encendido, como un servidor doméstico, una Raspberry Pi o un sobremesa:

- **Conviértelo en administrador.** En el teléfono, pulsa el ordenador en Inicio y luego **Make it an admin**. Un ordenador sin TPM ni Secure Enclave guarda sus claves en un archivo, y la app te avisa primero ([claves](keys.md#the-three-levels)). Entonces también puede añadir y quitar dispositivos (`sudo cbb pair`, `sudo cbb revoke NAME`), así que no necesitas tener el teléfono a mano cada vez. El teléfono sigue siendo la raíz del grupo, su dispositivo de mayor confianza: la clave de la raíz nunca sale del chip de seguridad del teléfono.
- **Conviértelo en el hub**, para que tus dispositivos sigan sincronizando cuando estén fuera de casa. Consulta [Fuera de casa](away-from-home.md).

Añade también un segundo teléfono, para que perder uno no cueste nada: toca **+** en el primer
teléfono y, en el segundo, toca **Unirse a un grupo** y escanea el código. El primer teléfono lo
hace administrador.

## Qué sigue

- [Cómo funciona](how-it-works.md): el grupo, los roles e imágenes de todas las formas en que se conectan los dispositivos, en casa y fuera.
- [Fuera de casa](away-from-home.md): sincroniza desde cualquier sitio a través de un hub.
- [Sin la app](without-app.md): un grupo llevado por un ordenador.
- [Solución de problemas](troubleshooting.md), cuando algo no funciona.
