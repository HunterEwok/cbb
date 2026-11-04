<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: e105316b2bdb -->
# Claves y atestación

Cada dispositivo de un grupo tiene claves: una demuestra a los demás quién es, y las claves de la raíz y de los administradores añaden y quitan dispositivos. El lugar donde un dispositivo guarda sus claves decide lo que se lleva un ladrón con él. Esta página dice dónde guarda las suyas cada tipo de dispositivo, cómo puede comprobarlo el grupo y qué nivel de rigor elegir. Las reglas exactas están en el [protocolo](../protocol.md), sección 17.

> Hecho y probado en CI con un TPM por software; en dispositivos reales, por ahora solo el Secure Enclave del iPhone y Windows en una máquina virtual. La [tabla de estado](../../README.md#status) del README dice qué se ha probado y dónde.

## Dónde viven las claves

| Dónde | Dispositivos | Qué se lleva un ladrón |
|---|---|---|
| **En un archivo** | Mac con Intel sin el chip T2, PC con Windows y ordenadores Linux sin TPM, el miembro ligero | una copia del archivo, que funciona en cualquier sitio hasta que un administrador quita el dispositivo |
| **En hardware** | iPhone (Secure Enclave), teléfonos Android (Keystore: StrongBox o el TEE), Mac con Apple silicon o el chip T2 (Secure Enclave), ordenadores Linux y PC con Windows con TPM | nada que copiar: la clave firma solo en ese dispositivo, y en un teléfono las claves de la raíz y de los administradores solo tras tu cara, tu huella o tu código |
| **Hardware demostrado** | un teléfono Android cuya clave comprobó la raíz del grupo | lo mismo que el hardware, y el grupo sabe que es verdad, no solo que el dispositivo lo dice |

La lista de dispositivos de las apps y `cbb status` (la columna KEYS) muestran cuál tiene cada dispositivo.

## Cómo se demuestra una clave

Un dispositivo puede decir que su clave está en hardware, pero un programa modificado también podría decirlo. Algunos tipos de hardware pueden demostrarlo:

- **Android.** Cuando la app crea su clave, el Keystore del teléfono firma un certificado que describe la clave: en StrongBox o en el TEE, en un teléfono con el gestor de arranque bloqueado y un sistema verificado. El certificado llega hasta la raíz de atestación de Google. La app lo envía a la raíz del grupo, que lo comprueba y registra el teléfono como **demostrado**. Para esto no se envía nada a Google.
- **Un teléfono con el gestor de arranque desbloqueado, o con un sistema firmado con su propia clave** (GrapheneOS y similares) guarda su clave en hardware, pero la comprobación no puede dar fe del sistema que la rodea. Cuenta como hardware, no como demostrado.
- **Teléfonos revocados.** Google publica una lista de teléfonos cuyas claves de atestación se filtraron. Un servidor del proyecto, `cbb.tools`, la copia una vez al día y firma la copia. La raíz del grupo obtiene esa copia, así que tus dispositivos nunca preguntan a Google. Un teléfono de la lista baja de demostrado a hardware.
- **Los ordenadores Linux con TPM** guardan en él sus claves de miembro y de administrador, así que las claves cuentan como hardware. Un TPM cuyo fabricante escribió su certificado en el chip (los chips de Infineon, ST y Nuvoton, como las placas TPM de la Raspberry Pi) lo demuestra a la raíz del grupo, que entonces registra el ordenador como **demostrado**; no se pregunta nada al fabricante. Los TPM de firmware de Intel y AMD suelen guardar su certificado en el servidor del fabricante, así que siguen siendo hardware. Los **dispositivos Apple** (App Attest) todavía no demuestran sus claves.

## Los tres niveles

Tu grupo tiene un nivel, que decide cuánta certeza necesita el grupo antes de que un dispositivo pueda actuar como raíz, administrador o hub.

1. **Estricto.** Solo el hardware demostrado puede ser la raíz, un administrador o el hub. Para demostrar más dispositivos, este nivel también consulta servicios ajenos a tu casa: Apple para App Attest, e Intel o AMD para algunos certificados TPM. Esos servicios se enteran de que un dispositivo de ese tipo preguntó, desde tu dirección. Las cadenas de Android solo cuentan cuando llegaron mediante el Remote Key Provisioning de Google.
2. **Hardware (por defecto, recomendado).** Las claves en hardware pueden ser la raíz, un administrador o el hub, demostradas o no. Las pruebas que no necesitan ningún servicio externo (Android, TPM con su certificado en el chip) se siguen comprobando y mostrando. Nada sobre tus dispositivos sale de tu casa, aparte de obtener la copia de revocación de `cbb.tools`, que es el mismo archivo para todos.
3. **Archivos permitidos (el menos seguro).** Un dispositivo con las claves en un archivo también puede ser administrador, tras una advertencia: quien copie el archivo actúa como administrador hasta que otro administrador quite el dispositivo. Un ordenador cuyas claves no están en un TPM ni en el Secure Enclave solo llega a administrador de esta manera (`cbb admin -allow-file-key`, o la advertencia del cuadro «Make it an admin» del teléfono).

El nivel 2 es el predeterminado porque mantiene las claves fuera de los archivos siempre que el hardware lo permite, sin decir a ningún servicio externo qué dispositivos tienes.

Un ordenador instalado sin `sudo` ([sin root](install.md#without-sudo-rootless)) nunca es la raíz, un administrador ni el hub, en ningún nivel: cualquier programa de su usuario puede leer sus claves.

## Si se pierde un dispositivo

Quítalo del grupo en cuanto puedas: consulta [si se pierde o roban un dispositivo](lost-device.md). Una clave en hardware no puede usarse sin el dispositivo; una clave en un archivo sí, hasta que se quita el dispositivo.

## Lo que aún no está construido

Los niveles anteriores son el diseño; esta versión construye una parte:

- Los teléfonos Android demuestran sus claves, y la raíz comprueba la prueba y la lista de Google. La copia de `cbb.tools` empezará cuando existan las claves de firma del proyecto.
- El nivel es un ajuste: Ajustes, Claves de administrador, en el teléfono raíz, o `cbb keys` en un ordenador raíz. Un grupo creado en un teléfono empieza en el nivel 2; hacer administrador allí a un ordenador con las claves en un archivo, tras la advertencia, pasa el grupo al nivel 3. Un grupo creado en un ordenador cuya clave raíz está en un archivo empieza en el nivel 3, ya que su raíz no cumple ella misma el nivel 2. El nivel 1 todavía no consulta los servicios ajenos a tu casa, y un teléfono cuya propia clave no está demostrada no puede elegirlo.
- Los ordenadores Linux y los PC con Windows con TPM 2.0 guardan en él sus claves de miembro y de administrador desde el momento en que se unen a un grupo; un ordenador que se unió antes conserva su archivo hasta que vuelva a unirse. En Windows aún no se ha probado en un PC real. Los Mac con Apple silicon o el chip T2 las guardan del mismo modo en el Secure Enclave. La clave raíz del grupo en un ordenador y App Attest todavía no están construidos: hasta entonces sus claves están en un archivo.
