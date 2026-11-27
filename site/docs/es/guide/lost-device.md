<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 3475f09f1379 -->
# Si se pierde o roban un dispositivo

Para cualquiera cuyo teléfono, ordenador u otro dispositivo del grupo se haya perdido o haya sido robado. En esta página quitas el dispositivo perdido, congelas un ordenador administrador robado, mueves el grupo a un nuevo dispositivo principal si has perdido el dispositivo principal y desactivas funciones remotas en tus demás dispositivos.

Quita un dispositivo desaparecido en cuanto notes que falta. Tus demás dispositivos permanecen en el grupo y siguen sincronizando sin necesidad de volver a emparejarlos.

## 1. Quita el dispositivo perdido

Quitar un dispositivo difunde un registro de eliminación firmado para que todos los demás dispositivos rechacen sus conexiones y dejen de sellar copias para él. Solo el **dispositivo principal** (llamado *root* en las herramientas de línea de comandos) o un **teléfono administrador** pueden quitar a otro administrador; un ordenador administrador solo quita miembros ordinarios.

- **En el dispositivo principal o en un teléfono administrador:**
  1. Abre **CBB** y toca el dispositivo perdido en **Inicio**.
  2. Toca **Quitar** y confirma con tu cara, huella, código o (en Aurora OS) tu PIN de administrador.
- **En el dispositivo principal o en un ordenador administrador (terminal):**

  ```sh
  sudo cbb remove NAME
  ```

  Sustituye `NAME` por el nombre del dispositivo o el ID del dispositivo que muestra `cbb status` (omite `sudo` en una terminal de administrador en Windows).
- **En la app para Mac o la app de la bandeja (dispositivo principal o administrador):** Abre el panel de detalles del dispositivo perdido, haz clic en **Quitar** y confirma.

**Resultado:** Todos los dispositivos conectados rechazan el dispositivo quitado de inmediato, y los dispositivos desconectados lo rechazan en cuanto vuelven a conectarse. Un dispositivo quitado solo puede volver a unirse emparejándose de nuevo como un dispositivo nuevo.

## 2. Si era un ordenador administrador: congélalo primero

Un ordenador administrador puede firmar cambios del grupo y enviar órdenes. Si un ordenador administrador puede estar en manos de otra persona y no tienes a mano el dispositivo principal ni un teléfono administrador para quitarlo, congélalo primero desde cualquier dispositivo administrador.

1. Ejecuta en cualquier dispositivo administrador:
   - **Terminal:** `sudo cbb freeze NAME`
   - **App del teléfono o de escritorio:** Abre el ordenador administrador en **Inicio**, selecciona **Congelar** y confirma.

   **Resultado:** Nada de lo que firme el administrador congelado cuenta a partir de ese momento, y todos los demás dispositivos rechazan sus conexiones. Un administrador congelado no puede congelar al dispositivo principal ni a un teléfono administrador.

2. En cuanto tengas el dispositivo principal o un teléfono administrador, quita el ordenador congelado (paso 1).

Si dos ordenadores administradores se congelan entre sí antes de enterarse de la congelación del otro, ambos permanecen congelados hasta que el dispositivo principal decida: ejecuta `sudo cbb unfreeze NAME` o `sudo cbb remove NAME` en el ordenador principal, o elige **Descongelar** o **Quitar** en el teléfono principal.

## 3. Si era el dispositivo principal: mueve el grupo

El **dispositivo principal** guarda la clave principal del grupo. Si el dispositivo principal se pierde o se estropea, mueve el grupo a otro dispositivo que ya esté en el grupo usando la **clave de recuperación** de tu grupo: la hoja de recuperación impresa o la YubiKey que guardaste cuando creaste el grupo.

Nadie puede mover el grupo sin la clave de recuperación, ni siquiera un administrador. Si no tienes la clave de recuperación, no puedes mover el grupo: abandona el grupo antiguo en cada dispositivo que te quede (`sudo cbb leave` o **Abandonar el grupo** en la app), crea un grupo nuevo y vuelve a emparejar tus dispositivos.

### Mover el grupo a un teléfono del grupo

1. En otro teléfono que ya esté en tu grupo, abre **CBB** y ve a **Ajustes > Mover el grupo a este teléfono**.
2. Proporciona la clave de recuperación:
   - **Hoja de recuperación:** Escanea el código QR de la hoja o escribe su texto.
   - **YubiKey:** Acerca la YubiKey al teléfono (NFC) o conéctala al puerto USB-C (en Aurora OS, solo por USB-C), introduce su PIN y toca la YubiKey cuando te lo pida.
3. Revisa la lista de dispositivos del grupo y desmarca el dispositivo principal perdido (y cualquier otro dispositivo que quieras excluir).
4. Toca **Hacer de este teléfono el dispositivo principal** y confirma con tu cara, huella, código o (en Aurora OS) tu PIN de administrador.

**Resultado:** Este teléfono pasa a ser de inmediato el dispositivo principal del grupo con una clave principal nueva. Cada dispositivo marcado sigue en el grupo y sigue al nuevo dispositivo principal en cuanto se conecta; cada dispositivo sin marcar queda excluido y el grupo lo rechaza.

### Mover el grupo a un ordenador del grupo

1. En otro ordenador de tu grupo, abre una terminal (como administrador en Windows) y ejecuta:
   - **Con la hoja de recuperación:**

     ```sh
     sudo cbb recovery -leave LOST-DEVICE
     ```

   - **Con una YubiKey** (requiere `pcscd` en Linux y FreeBSD):

     ```sh
     sudo cbb recovery -yubikey -leave LOST-DEVICE
     ```

   Repite `-leave NAME` por cada dispositivo que quieras excluir. También puedes iniciar este proceso en la app para Mac o en la app de la bandeja con **Mover el grupo a este Mac** / **Mover el grupo a este ordenador**.
2. Revisa quién se queda y quién sale, confirma y luego escribe la clave de recuperación de la hoja por la entrada estándar (o introduce el PIN de la YubiKey y tócala cuando parpadee).

**Resultado:** El servicio del ordenador se reinicia como el nuevo dispositivo principal del grupo, conserva todos los dispositivos incluidos y rechaza todos los dispositivos excluidos. El ordenador descarta la clave de recuperación después del cambio.

## 4. Desactiva funciones remotas si hace falta

Quitar el dispositivo perdido le impide actuar en tu grupo. Si no puedes quitarlo enseguida, o quieres proteger de inmediato tus demás dispositivos, cualquier administrador puede desactivar estas funciones desde otro dispositivo:

| Función | Comando en un ordenador administrador | En la app de un teléfono administrador |
|---|---|---|
| [Pegado remoto](remote-paste.md) | `sudo cbb paste-receive off -on DEVICE` (o `-all`) | Abre la página del dispositivo y desactiva el pegado remoto |
| [Acciones rápidas](quick-actions.md) | `sudo cbb action off -on DEVICE` (o `-all`) | Abre la página del dispositivo y toca **Desactivar todo** |
| [Sincronizar fuera de casa](away-from-home.md) | `sudo cbb global off -on DEVICE` | Abre la página del dispositivo y desactiva la sincronización fuera de casa |

**Resultado:** Los dispositivos afectados desactivan esas funciones de inmediato. Solo el propio usuario de cada dispositivo puede volver a activarlas localmente.

## A qué puede acceder un ladrón

Lo que puede obtener alguien que robe tu dispositivo depende de dónde guarde ese dispositivo sus claves (consulta [Claves y atestación](keys.md)):

- **Claves en hardware** (teléfonos con chip de seguridad, Mac con Apple silicon o chip T2, y PC Linux o Windows con TPM 2.0): Las claves no se pueden copiar fuera del dispositivo. En los teléfonos, las claves principal y de administrador solo firman tras tu cara, huella, código o (en Aurora OS) tu PIN de administrador.
- **Claves en archivos** (Mac con Intel sin chip T2, PC Linux y Windows sin TPM, FreeBSD, dispositivos pequeños, teléfonos con Aurora OS 4 y Sailfish OS, e instalaciones sin root en Linux): Cualquiera que pueda leer el disco puede copiar los archivos de clave y hacerse pasar por ese dispositivo hasta que lo quites. Mantén activado el cifrado completo del disco (FileVault, BitLocker o LUKS).

Connect Beyond Borders no guarda historial del portapapeles. Las copias ordinarias caducan tras la duración de copia del grupo (5 minutos por defecto), y los secretos permanecen solo en memoria y caducan tras 60 segundos por defecto.
