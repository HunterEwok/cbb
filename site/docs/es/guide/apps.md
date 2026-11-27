<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 07bd60070629 -->
# Las apps

Para cualquiera que use las apps de Connect Beyond Borders en un teléfono, una tableta, un reloj, un televisor o un ordenador. Para instalar el servicio en segundo plano en ordenadores, routers y servidores, consulta [Instalación](install.md). Para los detalles técnicos, consulta [Especificación de las apps](../apps.md).

Connect Beyond Borders ofrece apps nativas para teléfonos, tabletas, relojes, Android TV y ordenadores de escritorio. Las apps de teléfono pueden guardar la clave principal del grupo y gestionar dispositivos; las apps de escritorio ofrecen una ventana y un icono de menú sobre el servicio en segundo plano que se ejecuta en ese ordenador.

## Apps disponibles

| App | Dónde conseguirla | Notas |
|---|---|---|
| **Android** (Android 10 o posterior) | `cbb-X.Y.Z.apk` en cada [versión en GitHub](https://github.com/HunterEwok/cbb/releases) | Incluye compatibilidad con relojes Wear OS, actualizaciones automáticas y notificaciones push |
| **Android sin Google** (compilación F-Droid) | `cbb-fdroid-X.Y.Z.apk` en cada [versión en GitHub](https://github.com/HunterEwok/cbb/releases) | Compilación reproducible sin servicios de Google Play; usa UnifiedPush para avisos con la app cerrada y omite Wear OS |
| **Android TV, Google TV y Fire OS** | El mismo APK de Android (`cbb-X.Y.Z.apk` o `cbb-fdroid-X.Y.Z.apk`) | Interfaz para mando direccional; se une como miembro de solo recepción |
| **iPhone y iPad** (iOS 17 o posterior) | TestFlight (con invitación) o compilada desde `apps/ios` con Xcode | El control del Centro de control requiere iOS 18 o posterior |
| **Apple Watch** (watchOS 10 o posterior) | Incluida con la app del iPhone | Funciona a través del iPhone emparejado |
| **Wear OS** (Wear OS 3 o posterior) | `cbb-wear-X.Y.Z.apk` en cada [versión en GitHub](https://github.com/HunterEwok/cbb/releases) (instalar con `adb install`) | Funciona a través del teléfono Android emparejado (compilación completa) |
| **Aurora OS y Sailfish OS** | Compilada desde `apps/silica` (RPM firmados para Aurora OS 5.1.5) | Guarda las claves de administrador en OP-TEE tras un PIN de la app en Aurora 5; claves en archivo en Aurora 4 y Sailfish OS |
| **HarmonyOS** (HarmonyOS 5 o posterior, teléfono, tableta y reloj) | Compilada desde `apps/harmony` | Guarda las claves en HUKS; la app del reloj funciona a través del teléfono HarmonyOS emparejado |
| **App para Mac** (macOS 14 o posterior) | `cbb-X.Y.Z.pkg` en cada [versión en GitHub](https://github.com/HunterEwok/cbb/releases) | App de la barra de menús instalada junto con el servicio en segundo plano |
| **App de bandeja para Linux y Windows** | Incluida en los archivos de versión de Windows y Linux (x86-64, ARM64) | Se instala automáticamente con el servicio (requiere GTK 4 y WebKitGTK 6.0 en Linux) |

Para ver qué apps se han probado en hardware real frente a emuladores y CI, consulta [Paridad entre plataformas](../parity.md#on-real-devices).

## Teléfonos

### Crear un grupo o unirse a uno

Cuando abres la app sin ningún grupo configurado, tienes tres opciones:

- **Crear un grupo:** La app crea la clave principal del grupo dentro del hardware de seguridad de tu teléfono (Secure Enclave en iPhone, Keystore en Android, OP-TEE en Aurora OS 5 o HUKS en HarmonyOS) y te pide confirmar con tu cara, huella, código o (en Aurora OS) el PIN propio de la app. Después muestra una sola vez la **clave de recuperación** del grupo y ofrece **Escribir en una hoja**, **Escribir en la YubiKey** (por NFC o USB-C donde sea compatible), o ambas. Cuando la guardes, la app abre la ventana de emparejamiento **Añadir un dispositivo**.
- **Unirse a un grupo:** Escanea el código QR que muestra **Añadir un dispositivo** en un teléfono o un ordenador administrador de tu red doméstica, o te deja escribir sus seis dígitos. Un teléfono siempre se une como miembro; el dispositivo principal puede hacerlo administrador después.
- **Unirse con una invitación:** Escanea el código QR de una invitación, pega su texto o abre un archivo de invitación para unirte a un grupo desde fuera de casa a través del hub del grupo.

Para añadir un dispositivo desde **Inicio** en el dispositivo principal o en un teléfono administrador, toca **+** y elige **Añadir un dispositivo** (muestra un código QR y seis dígitos durante cinco minutos) o **Enviar una invitación** (para un dispositivo que está fuera de casa).

### Sincronización diaria

La pantalla **Inicio** muestra cuántos dispositivos están en línea junto con dos interruptores:

- **Sincronizar** (icono de casa): Toca para desactivar o activar la sincronización en este teléfono. Mantén pulsado para pausar la sincronización durante 15 minutos, 1 hora, 8 horas o hasta que vuelvas a activarla. Mientras la sincronización está desactivada, tu portapapeles es privado de este teléfono.
- **En todas partes** (icono de globo): Activa o desactiva la sincronización fuera de casa. Mientras **Sincronizar** está desactivado, **En todas partes** espera hasta que vuelvas a activar **Sincronizar**.

Debajo de la cabecera, **Inicio** muestra los avisos del grupo, la última copia recibida (con un botón **Copiar** para devolverla a tu portapapeles) y los dispositivos de tu grupo en mosaicos o en lista. Cada mosaico de dispositivo muestra su estado de conexión tanto con un punto como con texto en su página de detalles.

La forma de copiar y pegar depende del sistema operativo de tu teléfono:

- **Abrir la app (todos los teléfonos):** Cuando abres **CBB** o vuelves a ella desde segundo plano, envía tu portapapeles si copiaste algo nuevo; si no, trae la última copia del grupo. Mientras la app permanece abierta en pantalla, las copias entrantes entran automáticamente en tu portapapeles.
- **iPhone:** iOS solo deja a las apps leer el portapapeles en primer plano. En la primera configuración, permite **Pegar desde otras apps** en los Ajustes de iOS para que iOS no pregunte cada vez (si lo rechazas, aparece un botón de pegado del sistema en **Inicio**). Fuera de la app, intercambia tu portapapeles con el grupo en un solo gesto con el atajo **Sincronizar portapapeles** (asignado a Tocar atrás o al botón de Acción) o con el widget de la pantalla de inicio **Sincronizar portapapeles**. Usa el control **Sincronizar** en el Centro de control (iOS 18 o posterior) para activar o desactivar la sincronización. **Compartir → Connect Beyond Borders** pone en cola texto, enlaces, imágenes o archivos (hasta 50 MB juntos) y los envía la próxima vez que abras **CBB**. En iOS 17 o posterior, la Dynamic Island y la pantalla de bloqueo muestran un emparejamiento activo, el tiempo de conexión del túnel y la confirmación de sincronización (nunca el texto del portapapeles).
- **Android:** Las copias de tus ordenadores llegan automáticamente al portapapeles de tu teléfono en segundo plano. Para enviar también automáticamente las copias de tu teléfono, activa **Sincronización del portapapeles** en **Ajustes** (un servicio de accesibilidad; en Android 13 o posterior, las instalaciones por APK requieren primero **Permitir ajustes restringidos** en Información de la app). Sin **Sincronización del portapapeles**, envía con un toque usando:
  - **Enviar** en la notificación permanente de CBB
  - El widget de la pantalla de inicio **Enviar portapapeles**
  - **Compartir → Connect Beyond Borders** o el menú de selección de texto (hasta 100 MB para archivos)
  - La entrada del lanzador **cbb send** (usable con Toque rápido en Pixel o Back-Tap en Samsung)
  - El mosaico **Sincronizar** en los Ajustes rápidos de Android activa o desactiva la sincronización (mantén pulsado para abrir la app).
- **Aurora OS y HarmonyOS:** Abrir la app sincroniza como arriba. **Compartir → Connect Beyond Borders** envía texto, imágenes y archivos (hasta 50 MB juntos). Aurora OS muestra el estado y acciones rápidas de sincronización en la portada de la app; HarmonyOS incluye un widget de pantalla de inicio y estado en Live View.

Para imágenes, texto con formato y dónde se guardan los archivos recibidos, consulta [Imágenes, archivos y texto con formato](images-and-files.md).

### Organizar dispositivos

Puedes ordenar tus dispositivos en un orden personalizado y agruparlos en **colecciones** (por ejemplo, «Oficina» o «Casa»). Tu disposición y tus colecciones se quedan solo en ese dispositivo y nunca se comparten con el grupo ni con ningún servidor.

- Cambia entre **Mosaicos** y **Lista** (y **Órbita** en tabletas y escritorios) desde el menú de **Inicio**.
- Inicia **Ordenar dispositivos** desde el menú (o mantén pulsado un mosaico) para arrastrar dispositivos a su orden o soltarlos en colecciones, o usa **Volver al orden del grupo** para restablecerlo.
- Cuando un grupo tiene más de 12 dispositivos, **Inicio** muestra una barra de búsqueda y los filtros **En línea** y **Requiere atención**.

### Gestionar dispositivos

Toca cualquier dispositivo en **Inicio** para ver su estado, función, sistema operativo y versión de Connect Beyond Borders, con detalles técnicos adicionales (tipo de dispositivo, dirección MAC, ID del dispositivo) en **Más**.

Si tu teléfono es el dispositivo principal o un administrador, la página de un dispositivo te permite:

- **Sincronizar** o **Silenciar / Quitar silencio:** Activar o desactivar la sincronización en un ordenador conectado, o silenciar cualquier dispositivo durante 15 minutos, 1 hora, 8 horas o hasta que un administrador le quite el silencio (también puedes silenciar directamente desde el botón de la esquina de un mosaico de dispositivo).
- **Pegar:** Enviar texto, imágenes o archivos directamente a la app activa de un ordenador que tenga activado el pegado remoto ([Pegado remoto](remote-paste.md)).
- **Acciones rápidas:** Ejecutar acciones permitidas como bloquear o suspender un ordenador ([Acciones rápidas](quick-actions.md)).
- **Renombrar:** Cambiar el nombre del dispositivo en todo el grupo.
- **Hacerlo administrador** (solo dispositivo principal): Permitir que otro teléfono u ordenador añada y quite dispositivos. Los Mac con chip de Apple o chip T2 guardan las claves de administrador en el Secure Enclave, y los PC con Linux y Windows con TPM las guardan en el TPM. Si un ordenador guarda sus claves en un archivo, la app te avisa antes de hacerlo administrador ([Claves y atestación](keys.md#the-three-levels)).
- **Convertirlo en hub:** Convertir un ordenador administrador en un hub para sincronizar fuera de casa (un teléfono nunca es un hub).
- **Congelar / Descongelar:** Congelar un ordenador administrador robado para que nada de lo que firme cuente hasta que el dispositivo principal lo descongele o lo quite.
- **Quitar:** Quitar un dispositivo del grupo de inmediato.

Cada acción que cambia el grupo pide tu cara, huella, código o (en Aurora OS) tu PIN de administrador. En Aurora OS 5, el elemento seguro del teléfono verifica el PIN, y siete PIN incorrectos bloquean la clave de administrador de forma permanente (el teléfono sigue en el grupo como miembro). En el dispositivo principal, la app también pide renovar cada 30 días las credenciales de servidor del grupo para fuera de casa.

### Un segundo teléfono y un teléfono perdido

- **Añadir un segundo teléfono:** Toca **+** en tu teléfono principal, luego toca **Unirse a un grupo** en el segundo teléfono y escanea el código QR. El segundo teléfono se une como miembro. Ábrelo en **Inicio** en tu teléfono principal y toca **Hacerlo administrador** para tener un segundo teléfono administrador.
- **Si se pierde un teléfono:** Quítalo desde **Inicio** en otro teléfono administrador. Tus demás dispositivos siguen en el grupo. Si el teléfono perdido era el **dispositivo principal**, abre **Ajustes > Mover el grupo a este teléfono** en otro dispositivo del grupo, aporta tu clave de recuperación (hoja o YubiKey) y deja sin marcar el teléfono perdido para que el grupo lo rechace. Consulta [Si se pierde un dispositivo](lost-device.md).

### Ajustes

Los ajustes básicos aparecen primero en la pantalla **Ajustes**:

- **Apariencia y tema:** Elige apariencia **Sistema**, **Oscuro** o **Claro** y uno de **once temas** (Pizarra, Plano, Preciso, Cristal, Suave, Suizo, Hardware, Art déco, Cristal líquido, Terminal y Retro). Android 12 y posteriores también ofrecen **Material You** (colores del fondo de pantalla); Aurora OS sigue el ambiente del sistema.
- **Idioma:** Seguir el idioma del sistema o elegir entre ocho idiomas: inglés, chino (simplificado), español, ruso, árabe, suajili, hebreo e hindi. El árabe y el hebreo muestran la interfaz de derecha a izquierda.
- **Notificaciones:** Activa o desactiva interruptores individuales para dispositivos que se unen o salen, cambios de administrador, congelaciones, cambios del dispositivo principal y problemas de conexión del hub. En iPhone y Android, **Avisarme cuando la app esté cerrada** activa avisos push sellados que despiertan el teléfono sin revelar tus copias.
- **Clave de recuperación** (en el dispositivo principal) o **Mover el grupo a este teléfono** (en otros teléfonos).
- **Abandonar el grupo:** Borra las claves de este teléfono y los datos del grupo manteniendo tus preferencias.
- **Acerca de y detalles de errores:** Toca la fila **Versión** siete veces para mostrar **Mostrar detalles de los errores**, que muestra la causa subyacente debajo de los mensajes de error cortos cuando informas de un problema. En Android (APK completo de la versión), **Acerca de** también incluye comprobación de actualizaciones y ajustes de actualización automática.

Activa **Ajustes avanzados** para acceder a:

- **Por qué no se sincroniza:** Explica en palabras sencillas por qué este dispositivo no se sincroniza y qué hacer a continuación.
- **Fuera de casa** y **Relé ciego:** Muestra el estado del túnel y permite al dispositivo principal configurar un relé ciego para grupos sin hub ([Fuera de casa](away-from-home.md)).
- **Grupo** (solo administradores): Configura **Duración de una copia** (de 1 minuto a 1 hora; 5 minutos por defecto), **Duración de un secreto** (de 5 segundos a 1 minuto; 60 segundos por defecto) y **Claves de administrador** (el nivel de claves del grupo, en el dispositivo principal).
- **Laboratorio** (Android, Aurora OS y HarmonyOS): Funciones experimentales como el teclado Bluetooth ([El laboratorio](lab.md)).

### Tabletas y plegables

En pantallas anchas —iPads, tabletas Android, tabletas Aurora, tabletas HarmonyOS y plegables desplegados—, la app cambia automáticamente a una vista dividida con una barra lateral (secciones para **Todos los dispositivos**, **Requiere atención**, colecciones y ajustes), una opción de vista **Órbita**, un panel de detalles de dispositivo en paralelo, atajos de teclado y arrastrar y soltar (suelta texto o archivos sobre un mosaico de dispositivo para pegado remoto, o junto a los mosaicos para copiar al grupo). En una ventana estrecha, como el modo de pantalla dividida, vuelve a la disposición de teléfono.

### Android TV

Instalar el APK de Android en Android TV, Google TV o Fire OS ofrece una interfaz navegable con el mando direccional. Un televisor se une a un grupo escribiendo el código de emparejamiento de seis dígitos de un teléfono o un ordenador administrador y funciona como miembro de solo recepción.

## Relojes

Las apps para **Apple Watch**, **Wear OS** y **reloj HarmonyOS** funcionan a través de su teléfono emparejado y nunca guardan tu portapapeles. Cada app de reloj muestra:

- Cuántos dispositivos están en línea y la lista de dispositivos (organizada según las colecciones de tu teléfono)
- Los eventos recientes del grupo
- Los interruptores **Sincronizar** (casa) y **En todas partes** (globo) de tu teléfono

## Apps de escritorio

La **app para Mac** (barra de menús) y la **app de bandeja para Linux y Windows** (bandeja del sistema) se conectan al servicio en segundo plano que ya se ejecuta en tu ordenador. Tu portapapeles se sincroniza automáticamente tanto si la ventana de la app está abierta como cerrada, así que no hay botones manuales de Enviar ni de Obtener.

Ambas apps de escritorio ofrecen:

- **Icono en la bandeja del sistema o en la barra de menús:** Muestra el número de dispositivos en línea, **Sincronizar** (con duraciones de pausa), **En todas partes**, **Abrir CBB**, **Ajustes**, avisos de actualización y **Salir**.
- **Ventana principal:** Muestra los dispositivos como **Mosaicos**, **Lista** u **Órbita**, admite orden personalizado y **colecciones**, muestra avisos y alertas del grupo y abre el panel de detalles de un dispositivo junto a la lista.
- **Inicio y emparejamiento:** Cuando no estás en un grupo, ofrece **Crear un grupo**, **Unirse a un grupo**, **Unirse con una invitación** y **Mover el grupo a este ordenador** (usando una clave de recuperación). Cuando estás en un grupo como administrador, **+** abre una ventana de emparejamiento (código QR y seis dígitos) o envía una invitación.
- **Controles de administrador y hub:** Te permite renombrar, silenciar, congelar, quitar, hacer administradores, configurar el ordenador como hub (incluidos los ajustes de AmneziaWG, VLESS y reenviador) y ajustar las duraciones y los niveles de claves del grupo. Las acciones que cambian el grupo piden tu contraseña de administrador o la confirmación del sistema (Touch ID, Windows Hello o polkit).
- **Pegado remoto en macOS:** La app para Mac actúa como receptor de pegado remoto mientras está abierta, una vez que le concedes permiso de Accesibilidad en **Ajustes del Sistema > Privacidad y seguridad > Accesibilidad**.
- **Ajustes:** Apariencia, los once temas, ocho idiomas, **Abrir al iniciar sesión**, **Ajustes avanzados** (incluido **Por qué no se sincroniza**) y **Mostrar detalles de los errores** (siete clics en la versión).

Cuando algo no funciona como se esperaba, consulta [Solución de problemas](troubleshooting.md).
