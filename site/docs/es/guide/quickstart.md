<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 97987cb74ebc -->
# Inicio rápido

Para cualquiera que configure Connect Beyond Borders por primera vez con un teléfono y un ordenador en una red doméstica. En cuatro pasos, instalas la app del teléfono, creas un grupo, añades tu primer ordenador y compartes tu portapapeles entre ellos.

Connect Beyond Borders comparte un único portapapeles cifrado entre tus propios dispositivos sin nube ni cuentas. Tus dispositivos forman un **grupo**: un conjunto de dispositivos que confían entre sí mediante registros firmados en lugar de un servidor central. El teléfono que crea el grupo es su **dispositivo principal** (llamado *root* en las herramientas de línea de comandos y los diagramas): guarda la clave principal del grupo y admite dispositivos nuevos.

![Un teléfono que guarda la clave del grupo se conecta con ordenadores Linux, Mac y Windows para que cada dispositivo comparta un único portapapeles directamente en tu red doméstica](../images/group.svg)

Si quieres iniciar un grupo sin una app de teléfono (usando solo ordenadores), sigue [Sin la app](without-app.md). Si solo tienes teléfonos, sáltate los pasos 2 y 3, toca **+** en el primer teléfono y toca **Unirse a un grupo** en cada teléfono adicional para escanear su código QR (consulta [dos tipos de grupo](how-it-works.md#two-kinds-of-group)).

## 1. Instala la app y crea un grupo en tu teléfono

Este tutorial usa un teléfono Android (Android 10 o posterior). Para otras apps de teléfono (iPhone, Aurora OS y HarmonyOS), consulta [Las apps](apps.md).

1. En tu teléfono Android, descarga `cbb-X.Y.Z.apk` desde la [última versión en GitHub](https://github.com/HunterEwok/cbb/releases/latest).
2. Abre el archivo descargado para instalar Connect Beyond Borders. Cuando Android lo pida, permite que tu navegador o gestor de archivos instale aplicaciones.
3. Abre **CBB** y toca **Crear un grupo**.
4. Confirma con tu huella, tu cara o el bloqueo de pantalla cuando te lo pida. La app crea la clave principal del grupo dentro del hardware de seguridad de tu teléfono.
5. Guarda la **clave de recuperación** del grupo, que la app muestra una sola vez. Elige **Escribir en una hoja** para imprimirla o guardarla, **Escribir en la YubiKey** para almacenarla en una YubiKey, o ambas. Guarda la clave de recuperación separada de tus dispositivos: es la única forma de mover el grupo a otro dispositivo principal si pierdes este teléfono ([Claves y atestación](keys.md)).

**Qué verás:** Después de cerrar la pantalla de la clave de recuperación, la app abre **Añadir un dispositivo** con un código QR y un código de emparejamiento de seis dígitos. Si cierras esa pantalla, la app muestra **Inicio** con tu teléfono listado como en línea.

## 2. Instala Connect Beyond Borders en un ordenador

Elige un ordenador en la misma red doméstica que tu teléfono, como un portátil, un sobremesa o una Raspberry Pi.

- En **Linux** o **macOS**, abre una terminal y ejecuta:

  ```sh
  curl -fsSL https://github.com/HunterEwok/cbb/releases/latest/download/get.sh | sudo sh
  ```

  En macOS 14 o posterior, también puedes descargar y abrir `cbb-X.Y.Z.pkg` desde la [última versión en GitHub](https://github.com/HunterEwok/cbb/releases/latest) para instalar tanto el servicio en segundo plano como la app de la barra de menús.

- En **Windows** 10 (1809 o posterior) u 11, abre PowerShell con **Ejecutar como administrador** y ejecuta:

  ```powershell
  irm https://github.com/HunterEwok/cbb/releases/latest/download/get.ps1 | iex
  ```

Durante la configuración, el instalador comprueba la firma de la descarga, instala el servicio en segundo plano (`cbb`) y hace hasta dos preguntas:

1. **Reglas de cortafuegos** (se muestra cuando hay un cortafuegos activo): responde `y` para permitir que Connect Beyond Borders se comunique en tu red doméstica.
2. **Actualizaciones automáticas**: responde `y` para permitir que Connect Beyond Borders busque a diario actualizaciones firmadas y las instale automáticamente.

En Linux, cierra sesión y vuelve a iniciarla una vez para que tu cuenta pueda ejecutar `cbb` sin `sudo`. En Windows, abre una ventana de terminal nueva.

**Qué verás:** El instalador informa de que Connect Beyond Borders se está ejecutando en el puerto TCP 8764 e imprime el siguiente comando para unirse a un grupo. Para Homebrew, Docker, routers y otras opciones, consulta [Instalación](install.md).

## 3. Añade el ordenador a tu grupo

1. En tu teléfono, asegúrate de que **Añadir un dispositivo** esté abierto. Si estás en **Inicio**, toca **+** y elige **Añadir un dispositivo**. La pantalla muestra un código QR y seis dígitos, y espera durante cinco minutos.
2. En tu ordenador, únete usando una terminal o la app de escritorio:
   - **En una terminal (Linux y macOS):** ejecuta `sudo cbb pair -code` y escribe los seis dígitos que muestra tu teléfono.
   - **En una terminal (Windows):** abre una terminal como administrador, ejecuta `cbb pair -code` y escribe los seis dígitos.
   - **En la app de escritorio (app de bandeja en Linux, app de bandeja en Windows o app de la barra de menús en macOS):** abre **CBB**, selecciona **Unirse a un grupo**, escribe los seis dígitos y confirma con tu contraseña de administrador cuando te lo pida.

**Qué verás:** Tu ordenador confirma que se unió al grupo y la pantalla **Añadir un dispositivo** se cierra en tu teléfono. En la pantalla **Inicio** de tu teléfono, el ordenador aparece en tu lista de dispositivos y se muestra en línea.

Añade cualquier otro ordenador de la misma manera: instala Connect Beyond Borders, abre **Añadir un dispositivo** en tu teléfono y ejecuta `cbb pair -code` (o usa **Unirse a un grupo** en la app de escritorio).

## 4. Copia en uno, pega en otro

Prueba a copiar una línea de texto en tu ordenador y luego pégala en tu teléfono. Después copia texto en tu teléfono y envíalo a tu ordenador.

- **Entre ordenadores:** Copia en un ordenador y pega en otro automáticamente.
- **Del ordenador a Android:** Las copias de tus ordenadores llegan automáticamente al portapapeles de tu teléfono en segundo plano.
- **De Android al ordenador:** Abre **CBB** para enviar automáticamente lo que copiaste (si el envío falla, aparece el botón **Enviar lo que copié** en **Inicio**). Sin abrir la app, puedes tocar **Enviar** en la notificación de CBB, tocar el widget de la pantalla de inicio **Enviar portapapeles**, compartir texto o archivos con **Connect Beyond Borders**, o activar **Sincronización del portapapeles** en **Ajustes** de la app para enviar las copias automáticamente.

Para pausar la sincronización en un dispositivo y que su portapapeles siga siendo privado:

- En tu teléfono, toca el botón **Sincronizar** (el icono de la casa) en **Inicio** —o mantenlo pulsado para pausar durante 15 minutos, 1 hora, 8 horas o hasta que lo vuelvas a activar—, o toca el mosaico **Sincronizar** en los Ajustes rápidos de Android.
- En un ordenador, ejecuta `cbb sync off` (y `cbb sync on` para reanudar), o usa el interruptor **Sincronizar** en la app de escritorio.

Para ver todas las funciones y gestos de las apps en todas las plataformas, consulta [Las apps](apps.md).

## Siguientes pasos recomendados

Cuando tu primer teléfono y tu ordenador ya estén sincronizando, considera estas dos mejoras:

- **Convertir un ordenador siempre encendido en administrador y hub:** Si tienes un ordenador que permanece encendido (como un sobremesa, un servidor doméstico o una Raspberry Pi), ábrelo en **Inicio** en tu teléfono principal y toca **Hacerlo administrador**. Un ordenador administrador puede añadir y quitar dispositivos (`sudo cbb pair` y `sudo cbb remove NAME`) cuando no tienes el teléfono a mano. Si el ordenador no tiene un chip de seguridad por hardware (TPM o Secure Enclave), sus claves se guardan en un archivo y la app te avisa antes de confirmar ([Claves y atestación](keys.md#the-three-levels)). También puedes convertir un ordenador siempre encendido en el **hub** de tu grupo para que tus dispositivos sigan sincronizando fuera de casa; consulta [Fuera de casa](away-from-home.md).
- **Añadir un segundo teléfono:** Toca **+** en tu teléfono principal, luego toca **Unirse a un grupo** en el segundo teléfono y escanea el código QR. El segundo teléfono se une como miembro. Para permitir que también gestione dispositivos, ábrelo en **Inicio** en tu teléfono principal y toca **Hacerlo administrador**. Guarda a buen recaudo tu clave de recuperación por si alguna vez necesitas mover el grupo a otro dispositivo principal ([Si se pierde un dispositivo](lost-device.md)).

## Qué sigue

- [Cómo funciona](how-it-works.md): Entiende las funciones del grupo, el cifrado y cómo se conectan los dispositivos en casa y fuera.
- [Las apps](apps.md): Explora qué muestran y qué hacen las apps para teléfono, reloj, televisor y escritorio.
- [Fuera de casa](away-from-home.md): Sincroniza tu portapapeles fuera de tu red doméstica mediante un hub o un relé ciego.
- [Solución de problemas](troubleshooting.md): Diagnostica problemas de conexión, cortafuegos y emparejamiento.
