<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 31ed0dc98c03 -->
# Sin la app

Para cualquiera que quiera crear y gestionar un grupo de Connect Beyond Borders usando solo ordenadores, sin una app de teléfono. En esta página creas un grupo en un ordenador, añades más ordenadores en tu red doméstica, configuras un segundo administrador y añades ordenadores desde otra red por SSH o por una VPN.

![Un ordenador Linux sostiene el grupo y añade el Mac y Windows con un código de seis dígitos](../images/without-app.svg)

Un ordenador que crea un grupo pasa a ser su **dispositivo principal** (llamado *root* en las herramientas de línea de comandos y los diagramas). Una [instalación sin root en Linux](install.md#without-sudo-rootless) nunca puede ser el dispositivo principal ni un administrador, y un contenedor de Docker requiere `CBB_KEYS_IN_FILE=yes` en su entorno antes de guardar claves de grupo.

## 1. Crea el grupo en un ordenador

Elige un ordenador que esté encendido con regularidad (Linux, macOS, Windows o FreeBSD) e [instala Connect Beyond Borders](install.md).

1. Ejecuta en ese ordenador (omite `sudo` en una terminal de administrador en Windows, o haz clic en **Crear un grupo** en la app para Mac o en la app de la bandeja):

   ```sh
   sudo cbb new
   ```

2. Guarda la **hoja de recuperación** que se muestra en pantalla: cuatro líneas de letras y dígitos más un código QR. Imprímela o anótala y guárdala separada de tus dispositivos.

**Resultado:** Este ordenador pasa a ser el dispositivo principal del grupo. En un Mac con chip de Apple o chip T2, o en un PC con Linux o Windows con TPM 2.0, sus claves viven en hardware de seguridad; si no, viven en archivos protegidos (`cbb keys` empieza en `files`; consulta [Claves y atestación](keys.md)). Nada guarda una copia de la hoja de recuperación: es la única forma de mover el grupo si se pierde este ordenador.

## 2. Añade ordenadores en tu red doméstica

Instala Connect Beyond Borders en cada ordenador adicional de la misma red doméstica y emparéjalo:

1. En el dispositivo principal (o en cualquier ordenador administrador), abre una ventana de emparejamiento:

   ```sh
   sudo cbb pair
   ```

   **Resultado:** La terminal muestra un código de emparejamiento de 6 dígitos y un código QR, y espera durante 5 minutos. También puedes abrir una ventana de emparejamiento desde el botón **+** en la app para Mac o en la app de la bandeja.

2. En el ordenador nuevo, únete al grupo:
   - **Terminal:** Ejecuta `sudo cbb pair -code` (omite `sudo` en una terminal de administrador en Windows) y escribe los 6 dígitos cuando te los pida.
   - **App de escritorio:** Abre **CBB**, elige **Unirse a un grupo** y escribe los 6 dígitos.

   Cada código erróneo gasta uno de los 3 intentos; la ventana se cierra tras 3 intentos fallidos o en cuanto un dispositivo se une.

**Resultado:** Ambos ordenadores confirman la unión y tus portapapeles se sincronizan automáticamente. Copia texto en un ordenador y pégalo en el otro para verificarlo (consulta [Inicio rápido: copia en uno, pega en otro](quickstart.md#4-copy-on-one-paste-on-another)).

## 3. Añade un segundo administrador y guarda segura tu hoja de recuperación

Haz **administrador** a un segundo ordenador para poder seguir añadiendo y quitando dispositivos cuando el dispositivo principal esté sin conexión. Ten en cuenta que un ordenador solo puede hacerse administrador si se emparejó directamente con el dispositivo principal.

1. Consulta el nombre o el ID de dispositivo del ordenador con `cbb status`.
2. En el dispositivo principal, haz administrador al ordenador:
   - **Ordenador con TPM 2.0 o Secure Enclave:**

     ```sh
     sudo cbb admin NAME
     ```

   - **Ordenador cuyas claves viven en archivos** (requiere el nivel de claves `files`, fijado con `sudo cbb keys files`):

     ```sh
     sudo cbb admin -allow-file-key NAME
     ```

     Cualquiera que copie los archivos de claves de un administrador con claves en archivo puede actuar como administrador hasta que otro administrador quite ese ordenador, así que haz administradores solo a ordenadores que mantengas físicamente seguros y con el disco cifrado.

**Resultado:** `cbb status` muestra el segundo ordenador como administrador, y puede ejecutar `sudo cbb pair` y `sudo cbb remove NAME` para miembros normales.

Si el dispositivo principal se pierde o se estropea alguna vez, mueve el grupo a otro ordenador del grupo usando tu hoja de recuperación:

```sh
sudo cbb recovery -leave LOST-DEVICE
```

Luego escribe la clave de recuperación de la hoja cuando te la pida (o pasa `-yubikey` si la sellaste en una YubiKey). Consulta [Si se pierde o roban un dispositivo](lost-device.md) para ver el procedimiento completo.

## Unirse desde otra red

Para añadir un ordenador que no está en tu red doméstica, puedes enviar una [invitación a través de un hub](away-from-home.md#a-computer-that-is-not-at-home-an-invitation), o emparejar a través de un túnel SSH o de tu propia VPN.

### Por SSH

1. En el ordenador nuevo, redirige un puerto local al puerto de miembro del dispositivo principal o de un administrador (8764 por defecto):

   ```sh
   ssh -N -L 18764:localhost:8764 user@admin-machine
   ```

2. En una sesión SSH aparte en el dispositivo principal o en el ordenador administrador, abre una ventana de emparejamiento:

   ```sh
   sudo cbb pair
   ```

   Copia la línea completa `cbb://pair?...` impresa debajo de los 6 dígitos. (Sin descubrimiento de red local, los 6 dígitos por sí solos no pueden identificar la ventana; la línea `cbb://pair?...` lleva tanto los datos de la ventana como el código.)

3. En el ordenador nuevo, únete a través del puerto redirigido y pega la línea `cbb://pair?...` cuando te la pida:

   ```sh
   sudo cbb pair -code 127.0.0.1:18764
   ```

**Resultado:** El ordenador nuevo se une al grupo a través del túnel SSH dentro de TLS 1.3.

### Por tu propia VPN

1. En Linux, si configuraste la VPN después de instalar Connect Beyond Borders, vuelve a ejecutar el instalador para que las reglas del cortafuegos permitan tu subred VPN.
2. En el dispositivo principal o en el ordenador administrador, ejecuta `sudo cbb pair` y copia la línea `cbb://pair?...` impresa debajo de los 6 dígitos.
3. En el ordenador nuevo, únete usando la dirección VPN y el puerto del ordenador administrador, y pega la línea `cbb://pair?...` cuando te la pida:

   ```sh
   sudo cbb pair -code ADMIN-VPN-ADDRESS:8764
   ```

**Resultado:** El ordenador nuevo se une a tu grupo por la VPN dentro de TLS 1.3.

El secreto de emparejamiento nunca viaja en claro: ambos ordenadores derivan la prueba de sesión dentro de TLS 1.3. El ordenador nuevo sigue sincronizando por la ruta temporal de emparejamiento hasta que su servicio se reinicia; para seguir sincronizando de forma permanente después de cerrar SSH o tu VPN, configura antes la [sincronización fuera de casa](away-from-home.md) en ambos dispositivos.
