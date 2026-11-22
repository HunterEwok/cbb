<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: e056f57a7649 -->
# Si se pierde o roban un dispositivo

Para quien ha perdido un teléfono, un ordenador u otro dispositivo del grupo. Quítalo del grupo en cuanto puedas; los demás dispositivos siguen en el grupo y continúan sincronizando.

## 1. Quítalo

En un teléfono que sea administrador, pulsa el dispositivo perdido en **Inicio** y luego **Remove**. En un ordenador administrador:

```sh
sudo cbb remove NAME     # NAME, or the device ID, as cbb status shows it
```

Todos los dispositivos del grupo se enteran y dejan de hablar con el perdido. Solo la raíz, o un teléfono administrador, quita a un administrador.

## 2. Si era un ordenador administrador: congélalo primero

Las claves de un ordenador administrador pueden firmar. Si puede estar en manos de otra persona, congélalo desde cualquier administrador, para que nada de lo que firme a partir de ahora cuente, y luego quítalo:

```sh
sudo cbb freeze NAME
```

Un administrador congelado no puede congelar a la raíz ni a un teléfono administrador. Si lo congela a su vez, ambos siguen congelados hasta que la raíz decida (`cbb unfreeze` o `cbb remove` en la raíz, o **Unfreeze** y **Remove** en el teléfono raíz).

## 3. Si era la raíz: asume el grupo

La raíz guarda la clave raíz del grupo. Cuando falta, otro dispositivo del grupo pasa a ser la
raíz con la **clave de recuperación** del grupo, la hoja o la YubiKey que guardaste al crear el
grupo, y todos los demás dispositivos siguen en el grupo:

- con teléfonos: en tu otro teléfono, abre la recuperación en la app y dale la clave de
  recuperación;
- con ordenadores: en otro ordenador del grupo, `sudo cbb recovery` con la hoja de
  recuperación (`sudo cbb recovery -yubikey` con la YubiKey), nombrando el dispositivo
  perdido con `-leave NAME`.

Muestra quién se queda y quién sale y pregunta una vez; el cambio vale al instante, y desde
entonces el grupo rechaza el dispositivo perdido. Nadie asume el grupo sin la clave de
recuperación, ni siquiera un administrador.

Sin la clave de recuperación el grupo no se puede asumir: crea un grupo nuevo y añade los
dispositivos otra vez. Por eso la app pregunta cómo guardarla en cuanto se crea el grupo.

## 4. Desactiva lo que podía alcanzar

Quitar el dispositivo basta para el grupo. Si todavía no puedes quitarlo, o quieres estar seguro de los demás dispositivos, un administrador también puede desactivar a distancia:

| Qué | Comando en un ordenador administrador |
|---|---|
| [Pegado remoto](remote-paste.md) en un dispositivo, o en todos | `cbb paste-receive off -on DEVICE`, `-all` |
| [Acciones rápidas](quick-actions.md) en un dispositivo, o en todos | `cbb action off -on DEVICE`, `-all` |
| Sincronización fuera de casa en un dispositivo | `cbb global off -on DEVICE` |

Un teléfono administrador ofrece lo mismo en la página del dispositivo, y un reloj administrador también puede enviar estas órdenes. Solo el propio usuario de cada dispositivo vuelve a activarlas.

## Qué obtiene un ladrón

Depende de dónde guardaba el dispositivo sus claves ([claves y atestación](keys.md)):

- **Claves en hardware** (teléfonos, Mac con Secure Enclave, ordenadores con TPM): nada que copiar. Las claves firman solo en ese dispositivo, y las claves de raíz y de administrador de un teléfono firman solo tras tu cara, tu huella o tu código.
- **Claves en un archivo** (Mac con Intel sin el chip T2, PC con Windows y ordenadores Linux sin TPM, dispositivos pequeños): quien copie el archivo puede actuar como ese dispositivo hasta que lo quites. Cifra el disco (FileVault, BitLocker, LUKS) para que un dispositivo robado no revele nada.

El historial del portapapeles no se guarda en los dispositivos, y un secreto desaparece 60 segundos después de copiarlo.
