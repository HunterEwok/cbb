<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 09c16892691e -->
# Claves y atestación

Para cualquiera que quiera entender dónde guarda cada dispositivo sus claves criptográficas, cómo demuestran los dispositivos que sus claves viven en hardware de seguridad y qué **nivel de claves** elegir para su grupo. Para la especificación completa del protocolo, consulta [Protocolo](../protocol.md), sección 17, y [Criptografía](../cryptography.md).

Cada dispositivo de un grupo guarda una **clave de miembro** que demuestra su identidad ante tus demás dispositivos. El **dispositivo principal** (llamado *root* en las herramientas de línea de comandos) guarda la clave principal del grupo, y cada **administrador** guarda una clave de administrador que firma cambios y órdenes del grupo. El lugar donde un dispositivo guarda esas claves determina qué puede extraer un atacante si el dispositivo es robado.

## Dónde guarda cada dispositivo sus claves

La lista de dispositivos en las apps y la columna `KEYS` de `cbb status` muestran el nivel de almacenamiento de claves de cada dispositivo: **verificado** (`proven hardware`), **hardware** (`hardware`), **archivo** (`in a file`) o **sin root** (`in a file, rootless`).

| Dispositivo | Dónde viven las claves de miembro, administrador y principal | Confirmación antes de firmar como principal/administrador | Nivel de almacenamiento mostrado | Qué se puede llevar un ladrón |
|---|---|---|---|---|
| **iPhone y iPad** | Secure Enclave (hardware) | Face ID, Touch ID o código | `hardware` | Nada que copiar; las claves solo firman en ese dispositivo tras desbloquearlo |
| **Teléfono o tableta Android** (gestor de arranque bloqueado, sistema verificado) | Android Keystore (StrongBox o TEE, hardware) | Huella, rostro o bloqueo de pantalla (exigido por Keystore) | `proven hardware` | Nada que copiar; además, el grupo verifica la prueba de hardware sin conexión |
| **Teléfono o tableta Android** (gestor de arranque desbloqueado o sistema con firma propia como GrapheneOS) | Android Keystore (StrongBox o TEE, hardware) | Huella, rostro o bloqueo de pantalla | `hardware` | Nada que copiar; las raíces de Google no pueden avalar la verificación del sistema operativo |
| **Teléfono con Aurora OS 5** | Elemento seguro OP-TEE (hardware) | PIN de administrador propio de la app (al menos 6 dígitos al crearlo; 7 intentos fallidos bloquean la clave de administrador para siempre) | `hardware` | Nada que copiar; la clave de miembro sincroniza sin PIN y la clave de administrador/principal requiere PIN |
| **Teléfono con Aurora OS 4 y Sailfish OS** | Archivo de la app en el teléfono | Ninguna por hardware | `in a file` | Una copia del archivo de clave, utilizable en cualquier sitio hasta que se quite el dispositivo |
| **Teléfono o tableta con HarmonyOS 5+** | HUKS (TEE, hardware) | Rostro, huella o PIN (User Authentication Kit) | `hardware` | Nada que copiar; las claves solo firman en ese dispositivo tras autenticarse |
| **Mac con Apple silicon o chip T2** | Secure Enclave (hardware); secretos locales y del túnel sellados por el Secure Enclave | Touch ID de macOS o contraseña de administrador mediante el aviso del sistema | `hardware` | Nada que copiar; las claves solo firman en ese Mac |
| **Mac con Intel sin chip T2** | Archivos de estado del servicio (`/Library/Application Support/cbb/state`) | Contraseña de administrador de macOS | `in a file` | Una copia de los archivos de clave si se puede leer el disco; cífralo con FileVault |
| **PC Linux o Windows con TPM 2.0 y `cbb-helper`** | TPM 2.0 (hardware); secretos locales y del túnel sellados por el TPM | polkit en Linux o Windows Hello / aviso de administrador | `proven hardware` (con certificado EK en el chip) o `hardware` | Nada que copiar; las claves solo firman en ese PC |
| **PC Linux o Windows sin TPM, FreeBSD, OpenWrt, OPNsense, dispositivos pequeños sin `cbb-helper`, Docker** | Archivos de estado del servicio (legibles solo por la cuenta del servicio) | Privilegios de administrador (`sudo` o terminal de administrador) | `in a file` | Una copia de los archivos de clave si se puede leer el disco o volumen; cifra el disco (LUKS, BitLocker) |
| **Instalación sin root en Linux (`--rootless`)** | Archivos de usuario en `~/.local/state/cbb` | Ninguna (cualquier programa de tu usuario puede leerlos) | `in a file, rootless` | Cualquier programa que se ejecute bajo tu cuenta puede copiar los archivos de clave; nunca dispositivo principal, administrador ni hub |

Configurar `CBB_TPM=off` en un ordenador guarda las claves recién generadas en archivos en lugar de en hardware. Un contenedor Docker rechaza guardar claves principales o de administrador salvo que definas `CBB_KEYS_IN_FILE=yes` en su entorno.

### La clave de recuperación

Cuando creas un grupo, Connect Beyond Borders deriva la **clave de recuperación** del grupo (una clave ECDSA P-256 emparejada con una clave poscuántica SLH-DSA-SHA2-128s) a partir de un único secreto aleatorio de 32 bytes. El secreto se muestra una sola vez y nunca se guarda en ningún dispositivo del grupo. Lo guardas en papel (la hoja de recuperación), sellado en una ranura PIV retirada sin usar (ranuras 95 a 82) de una YubiKey (firmware 5.3 o posterior), o en ambos.

## Cómo se verifica una clave

Cualquier dispositivo puede afirmar que su clave vive en hardware, y un programa modificado podría afirmarlo falsamente. La **atestación de hardware** permite que un chip de seguridad firme una prueba criptográfica de que la clave se generó dentro del chip y no puede salir de él.

- **Android Key Attestation:** Cuando la app de Android crea su clave, Android Keystore firma una cadena de certificados que describe la clave (StrongBox o TEE, gestor de arranque bloqueado, estado de arranque verificado) con raíz en los certificados raíz de atestación de Google. El dispositivo principal verifica esta cadena sin conexión y registra el teléfono como **verificado**. No se envía nada a Google.
- **Gestores de arranque desbloqueados y sistemas personalizados:** Los teléfonos con el gestor de arranque desbloqueado o con un sistema operativo autofirmado (como GrapheneOS) siguen guardando las claves dentro de StrongBox o TEE, así que la clave no se puede extraer. Como la cadena no avala un sistema operativo verificado de fábrica, el grupo registra el teléfono como **hardware** en lugar de **verificado**.
- **Claves de atestación de Android revocadas:** Google publica una lista de dispositivos cuyas claves de atestación de hardware fueron comprometidas. El servidor del proyecto en `cbb.tools` descarga esa lista una vez al día y sirve una copia firmada (`https://cbb.tools/attest/`). El dispositivo principal descarga la copia firmada de `cbb.tools`, así que tus dispositivos nunca contactan con Google. Cualquier teléfono cuyo número de serie de certificado aparezca en la lista baja de **verificado** a **hardware**.
- **Atestación TPM 2.0 en ordenadores:** Un ordenador Linux o Windows con un TPM 2.0 y `cbb-helper` guarda sus claves en el TPM. Cuando el TPM tiene en el propio chip un certificado de Endorsement Key (EK) de su fabricante (habitual en chips TPM discretos de Infineon, ST y Nuvoton, como las placas TPM para Raspberry Pi), el dispositivo principal verifica sin conexión la activación de credenciales del TPM sin contactar con ningún servidor externo y registra el ordenador como **verificado**. Los TPM de firmware (habituales en CPU Intel y AMD) suelen omitir el certificado EK en el chip y por tanto permanecen en **hardware**.

## Los tres niveles

El **nivel de claves** de tu grupo establece el nivel mínimo de almacenamiento de claves necesario para que un dispositivo actúe como **dispositivo principal**, **administrador** o **hub que lee las copias**.

Un **hub que solo reenvía las copias** no necesita ningún nivel de claves porque cada copia va sellada de extremo a extremo sin incluirlo: un atacante que copie sus claves puede retrasar el tráfico y observar metadatos (consulta [Privacidad: qué ven los dispositivos intermedios](privacy.md#what-the-devices-in-between-see)), pero no puede leer ni falsificar copias. Un **miembro sin root** nunca puede ser dispositivo principal, administrador ni hub en ningún nivel de claves.

1. **Solo hardware verificado (`proven`):** Solo los dispositivos cuyas claves están demostradas mediante atestación de hardware (`proven`) pueden ser el dispositivo principal, un administrador o un hub que lee las copias. En Android, la verificación estricta exige cadenas emitidas a través de Google Remote Key Provisioning (RKP). Un dispositivo principal cuya propia clave no sea `proven` no puede poner el grupo en este nivel.
2. **Claves en hardware (`hardware`, predeterminado y recomendado):** Cualquier dispositivo cuyas claves vivan en hardware de seguridad (`hardware` o `proven`) puede ser el dispositivo principal, un administrador o un hub que lee las copias. Las pruebas sin conexión (Android Key Attestation y los TPM con certificado EK en el chip) se siguen verificando y mostrando, y ninguna información del dispositivo sale de tu red doméstica más allá de descargar la lista compartida de revocaciones de `cbb.tools`.
3. **Claves también en archivos (`files`):** También permite que los dispositivos cuyas claves vivan en archivos (`file`) sean el dispositivo principal, un administrador o un hub que lee las copias, tras una advertencia explícita cada vez (`cbb admin -allow-file-key` en una terminal, o el cuadro de advertencia en las apps). Un grupo creado en un ordenador sin TPM ni Secure Enclave empieza en `files`.

### Ver o cambiar el nivel de claves

Solo el **dispositivo principal** del grupo puede cambiar el nivel de claves:

- **En la app del teléfono o de escritorio:** Abre **Ajustes**, activa **Ajustes avanzados** y ve a **Grupo > Claves de administrador**.
- **En una terminal de un ordenador principal:** Ejecuta `cbb keys` para ver el nivel actual, o cámbialo con:

  ```sh
  sudo cbb keys proven
  sudo cbb keys hardware
  sudo cbb keys files
  ```

Los administradores y hubs que ya están en el grupo con claves más débiles permanecen activos hasta que los quites, y Connect Beyond Borders te avisa de qué dispositivos quedan por debajo del nuevo nivel.

## Si se pierde un dispositivo

Quita el dispositivo perdido de tu grupo lo antes posible; consulta [Si se pierde o roban un dispositivo](lost-device.md). Una clave guardada en hardware no se puede extraer ni usar fuera de ese dispositivo; una clave guardada en un archivo se puede copiar y usar hasta que quites el dispositivo.
