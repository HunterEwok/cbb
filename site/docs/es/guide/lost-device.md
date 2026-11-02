<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 9165921fa4f0 -->
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

La raíz guarda la clave raíz del grupo. Cuando desaparece, un administrador pasa a ser la raíz y todos los demás dispositivos siguen en el grupo:

- con teléfonos: en el otro teléfono, que es administrador, quita el perdido; la app asume el grupo en el mismo paso;
- con ordenadores: en un ordenador administrador, `sudo cbb takeover NAME`, donde NAME es la raíz perdida.

Los iPhone que usan el atajo se vuelven a emparejar tras una toma de control. Si el grupo no tenía otro administrador, no se puede asumir: crea un grupo nuevo y añade de nuevo los dispositivos. Por eso las apps sugieren un segundo teléfono administrador, o un ordenador administrador, en cuanto el grupo tiene un solo administrador.

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
- **Claves en un archivo** (Mac con Intel sin el chip T2, PC con Windows y ordenadores Linux sin TPM, el miembro ligero): quien copie el archivo puede actuar como ese dispositivo hasta que lo quites. Cifra el disco (FileVault, BitLocker, LUKS) para que un dispositivo robado no revele nada.

El historial del portapapeles no se guarda en los dispositivos, y un secreto desaparece 60 segundos después de copiarlo.
