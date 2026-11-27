<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 03894eb46cc0 -->
# Cómo funciona

Para cualquiera que quiera entender qué ocurre con lo que copia y cómo conecta Connect Beyond Borders sus dispositivos. Connect Beyond Borders comparte un único portapapeles entre tus propios dispositivos sin cuentas, sin servicios en la nube y sin un servidor central.

Para los pasos de configuración, consulta [Inicio rápido](quickstart.md). Para los detalles técnicos y el formato de transmisión, consulta [Diseño](../design.md) y [Protocolo](../protocol.md).

## Qué ocurre cuando copias

Cuando copias texto, una imagen o archivos en un dispositivo, Connect Beyond Borders cifra la copia para tus otros dispositivos y la envía por tu red doméstica, o por el túnel cifrado de tu grupo cuando estás fuera de casa.

La forma en que cada dispositivo envía y recibe copias depende de lo que permite su sistema operativo:

- **Ordenadores y dispositivos pequeños**: al copiar, la copia se envía automáticamente a tu grupo, y las copias entrantes pasan automáticamente a tu portapapeles mientras **Sincronizar** está activado.
- **Teléfonos Android**: la app recibe copias automáticamente en segundo plano. Para enviar copias, puedes activar su servicio de accesibilidad para el envío automático o tocar el botón de sincronización de la app.
- **iPhone y teléfonos con Aurora OS y HarmonyOS**: los sistemas operativos móviles restringen el acceso al portapapeles en segundo plano. Mientras la app está abierta en pantalla, escucha automáticamente igual que un ordenador. Cuando usas el botón o gesto de sincronización (como el botón de Acción o Tocar atrás en un iPhone), el teléfono intercambia su portapapeles con la última copia del grupo. Si el portapapeles de tu teléfono está vacío, recibe la copia del grupo sin sobrescribirla.

Connect Beyond Borders protege cada copia por capas:

- **Cifrado de extremo a extremo**: antes de que una copia salga del dispositivo donde la copiaste, ese dispositivo la cifra (la sella) únicamente para los dispositivos de tu grupo que leen copias y la firma con su propia clave. La copia sellada viaja dentro de una conexión cifrada (TLS 1.3) en la que ambos dispositivos verifican sus respectivas claves. Los dispositivos que solo reenvían copias y cualquier servidor ajeno a tu grupo no pueden leer, alterar ni falsificar una copia.
- **Texto, imágenes y archivos**: el texto sin formato viaja directamente dentro del mensaje de sincronización. Cuando copias una imagen, archivos o texto con formato, el dispositivo que copia envía primero un breve aviso; cada dispositivo receptor obtiene el contenido sellado hasta su propio límite de tamaño. Consulta [Imágenes, archivos y texto con formato](images-and-files.md) y [Límites y duraciones](../reference/limits.md#copies).
- **Contraseñas y secretos**: Connect Beyond Borders omite los elementos que un gestor de contraseñas marca como secretos. Los secretos que envías deliberadamente se mantienen solo en memoria, caducan tras una duración corta (60 segundos por defecto) y se borran de los portapapeles al acabarse su tiempo.
- **Sin historial del portapapeles**: Connect Beyond Borders no guarda historial de copias anteriores. Cada copia lleva una duración válida para todo el grupo (5 minutos por defecto para copias normales y 60 segundos para secretos). Una vez pasado ese tiempo, los dispositivos dejan de escribir esa copia en los portapapeles.
- **Pausar la sincronización**: cada dispositivo tiene un interruptor **Sincronizar**. Desactivar **Sincronizar** mantiene tu portapapeles privado en ese dispositivo mientras sigue conectado al grupo. Un administrador también puede silenciar un dispositivo cuyo portapapeles se comporte de forma anómala.

## El grupo

Tus dispositivos forman un **grupo** que comparte un único portapapeles. Cada dispositivo guarda una copia de los registros firmados de dispositivos del grupo, que enumeran todos los dispositivos del grupo, su función y los dispositivos quitados. Como cada dispositivo verifica por sí mismo esos registros firmados, tu grupo no necesita ningún servidor central.

Un grupo pertenece a una sola persona. Dos personas que quieran portapapeles separados crean dos grupos.

Solo los dispositivos que admites con un código de emparejamiento o un código QR pueden unirse a tu grupo. Si pierdes un dispositivo, quitarlo difunde un registro firmado de eliminación para que todos los demás dispositivos lo rechacen de inmediato. Consulta [Si se pierde un dispositivo](lost-device.md).

Cada dispositivo tiene una función en el grupo:

| Función | Qué dispositivos | Qué hace |
|---|---|---|
| **Dispositivo principal** (llamado *root* en las herramientas de línea de comandos) | El teléfono que crea el grupo, o un ordenador cuando funcionas [sin la app](without-app.md) | Guarda la clave principal del grupo, añade y quita dispositivos, elige administradores y fija las reglas del grupo |
| **Administrador** | Otro teléfono o un ordenador elegido por el dispositivo principal | Añade y quita dispositivos normales, congela un ordenador administrador robado y envía acciones de administración como el [pegado remoto](remote-paste.md); un teléfono administrador también puede quitar a otro administrador |
| **Miembro** | Cada ordenador, teléfono y dispositivo pequeño (como un router o una Raspberry Pi; consulta [dispositivos pequeños](../../member/README.md)) | Sincroniza el portapapeles |
| **Miembro sin root** | Un ordenador Linux instalado sin permisos de administrador (`sudo`) | Sincroniza como cualquier miembro, pero no puede ser el dispositivo principal, un administrador ni un hub ([miembros sin root](#rootless-members)) |
| **Hub** | Un ordenador, un router o una placa pequeña en casa | Conecta tus dispositivos cuando están fuera de casa; un hub que solo reenvía las copias no lee ninguna |

Un Apple Watch, un reloj Wear OS o un reloj HarmonyOS emparejado funciona a través de su teléfono para mostrar los dispositivos del grupo y activar o desactivar la sincronización fuera de casa; consulta [Las apps](apps.md).

El lugar donde un dispositivo guarda sus claves determina qué puede llevarse un ladrón si roba el dispositivo:

- **Los teléfonos** crean sus claves dentro de hardware de seguridad —el Secure Enclave en un iPhone, Android Keystore (StrongBox o TEE), el elemento seguro en Aurora OS o HUKS en HarmonyOS—, donde permanecen las claves. Firmar un cambio de administración pide tu cara, huella, código o (en Aurora OS) el PIN propio de la app; la sincronización diaria funciona sin preguntar.
- **Los ordenadores** guardan sus claves de miembro y de administrador en hardware cuando está disponible: el Secure Enclave en los Mac con chip de Apple o chip T2, y el chip de seguridad por hardware (TPM) en los PC con Linux y Windows; un ordenador que sea el dispositivo principal también guarda ahí su clave principal. Los ordenadores sin ese hardware y los dispositivos pequeños guardan las claves en archivos que solo Connect Beyond Borders puede leer.

Para conocer todos los detalles sobre el almacenamiento y la verificación de claves, consulta [Claves y atestación](keys.md).

### Miembros sin root

Una instalación normal en Linux pide permisos de administrador (`sudo`) una vez para que Connect Beyond Borders pueda ejecutarse bajo su propia cuenta del sistema en un entorno aislado estricto. Esa separación impide que tu navegador, tus juegos y otros programas lean las claves de tu dispositivo.

En un ordenador Linux donde no tienes `sudo` (como un ordenador del trabajo), una instalación sin root se ejecuta bajo tu propia cuenta de usuario. Sincroniza como cualquier miembro, pero cualquier programa que ejecutes puede copiar sus archivos de claves y hacerse pasar por ese dispositivo. Por ese motivo, un miembro sin root nunca puede ser el dispositivo principal, un administrador ni un hub. La lista de dispositivos lo etiqueta como **Miembro, sin root**.

Una Steam Deck admite la instalación normal porque su usuario tiene `sudo`; consulta [Instalación en SteamOS](install.md#steamos-steam-deck).

## Dos tipos de grupo

Un grupo puede incluir al menos un ordenador o dispositivo pequeño, o estar formado solo por teléfonos. Ambas configuraciones funcionan, y puedes añadir un ordenador a un grupo de solo teléfonos en cualquier momento.

| | Con un ordenador o dispositivo pequeño | Solo teléfonos |
|---|---|---|
| Dispositivo principal | Un teléfono (en su hardware de seguridad) o un ordenador [sin la app](without-app.md) | Un teléfono (en su hardware de seguridad) |
| Sincronización en casa | Conexiones cifradas directas en tu red doméstica | A través de un relé ciego mientras las apps funcionan |
| Sincronización fuera de casa | A través de un ordenador o dispositivo pequeño que actúa como hub | A través de un relé ciego mientras las apps funcionan |
| Dispositivo adicional necesario | Un ordenador, un router o una placa pequeña | Ninguno |

Los teléfonos solo abren conexiones salientes porque los sistemas operativos móviles no permiten que las apps esperen conexiones entrantes en segundo plano. Los ordenadores y los dispositivos pequeños sí escuchan conexiones entrantes.

Añadir un ordenador que permanezca encendido —como un sobremesa, un servidor doméstico, un router o una Raspberry Pi— te da sincronización local directa sin ningún servidor. También puedes convertir ese ordenador en un hub desde su página de dispositivo en la app para que la sincronización fuera de casa funcione incluso con las apps del teléfono cerradas.

## En casa

En una misma red doméstica, tus dispositivos se encuentran automáticamente mediante el descubrimiento de red local (mDNS) y se conectan directamente por conexiones cifradas TLS 1.3. Nada sale de tu red y no hay ningún servidor entre tus dispositivos. Puedes apagar cualquier dispositivo mientras los demás siguen sincronizando.

![En casa, un teléfono, un portátil, un sobremesa y una Raspberry Pi se conectan directamente entre sí mediante conexiones cifradas encontradas por mDNS, sin ningún servidor entre ellos](../images/at-home.svg)

La sincronización doméstica directa requiere al menos un ordenador o dispositivo pequeño en la red, porque los teléfonos solo inician conexiones salientes.

**Redes domésticas conocidas**: los ordenadores recuerdan las redes domésticas en las que coinciden con tu grupo (identificadas por la red y su router). En una red desconocida, como el Wi-Fi de una cafetería o de un hotel, un ordenador permanece en silencio: no se anuncia en la red local ni acepta conexiones entrantes.

**Redes separadas en casa**: el descubrimiento de red local (mDNS) no atraviesa routers entre redes locales separadas, como una red dedicada para dispositivos inteligentes. Puedes unir dos redes domésticas de tres maneras:

- Ejecutar Connect Beyond Borders en un router conectado a ambas redes.
- Dar a un ordenador o dispositivo pequeño la dirección de un ordenador de la otra red ([dispositivos pequeños](../../member/README.md#install)).
- Conectar ambas redes a través de un hub ([fuera de casa](#away-from-home-the-hub)).

## Fuera de casa: el hub

Cuando un portátil o un teléfono sale de tu red doméstica, no puede encontrar tus dispositivos de casa mediante descubrimiento local. Para seguir sincronizando, uno de tus ordenadores, routers o placas pequeñas en casa actúa como **hub**: tus dispositivos fuera de casa se conectan de vuelta a él a través del túnel cifrado propio de tu grupo (WireGuard), y el hub pasa las copias entre ellos y los dispositivos de casa.

![Fuera de casa, un portátil y un teléfono se conectan a través del túnel WireGuard del grupo a un hub en casa, que sincroniza con un sobremesa y una Raspberry Pi en la red doméstica](../images/hub.svg)

Dentro del túnel WireGuard, los dispositivos utilizan las mismas conexiones TLS mutuas y copias selladas de extremo a extremo que en casa. El túnel funciona dentro del propio Connect Beyond Borders: solo transporta tráfico de Connect Beyond Borders y no ocupa la ranura VPN de tu teléfono, de modo que tu propia VPN sigue funcionando.

Puedes elegir entre dos tipos de hub:

- **Un hub que lee las copias**: tu dispositivo principal (si es un ordenador) o un ordenador administrador. Tus dispositivos sellan las copias para él igual que para cualquier otro dispositivo lector, y el [nivel de claves](keys.md#the-three-levels) de tu grupo se aplica a sus claves.
- **Un hub que solo reenvía las copias**: un ordenador normal o una placa pequeña (como una Raspberry Pi o un NAS) que elige tu dispositivo principal. Tus dispositivos sellan las copias de extremo a extremo sin incluirlo, así que no lee ninguna, no hace copias propias y no necesita chip de seguridad por hardware.

Propiedades clave de un hub:

- **Llegar directamente al hub**: tu router redirige un puerto UDP (8764 por defecto) al hub, o tu hogar dispone de acceso directo por IPv6.
- **Cuando el hub está apagado**: la sincronización fuera de casa se detiene mientras el hub está apagado, y los dispositivos de casa siguen sincronizando directamente sin él.
- **Configuración en casa**: los dispositivos intercambian las claves del túnel con el hub mientras están en tu red doméstica, así que activa **En todas partes** (sincronizar fuera de casa) antes de salir.
- **Varios hubs**: un grupo puede tener varios hubs en un orden fijo de prioridad. Solo el hub en línea con mayor prioridad presta servicio cada vez; los hubs de reserva esperan sin túnel y toman el relevo automáticamente si el hub activo se detiene o permanece sin conexión durante más de un minuto.

Para los pasos de configuración, consulta [Fuera de casa](away-from-home.md).

## Tras el NAT del proveedor: un reenviador

Muchos proveedores de internet colocan los hogares tras una dirección pública compartida (NAT de operador), lo que impide que las conexiones entrantes lleguen a tu casa incluso con redirección de puertos. En ese caso, tu hub se registra en un **reenviador**, un servidor de internet que retransmite paquetes cifrados del túnel entre tus dispositivos fuera de casa y tu hub. Como tu hub abre una conexión saliente hacia el reenviador, no tienes que abrir ningún puerto en tu router.

![Un hub tras el NAT de un proveedor de internet abre una conexión saliente a un reenviador, que pasa paquetes cifrados del túnel entre el portátil y el teléfono fuera de casa y el hub en casa](../images/forwarder.svg)

Un reenviador no guarda ninguna clave del grupo y no puede leer tu portapapeles. Solo reenvía paquetes WireGuard cifrados entre tus dispositivos fuera de casa y tu hub.

Puedes usar cualquiera de dos reenviadores:

- **Tu propio reenviador** en cualquier servidor con dirección pública, como un pequeño servidor virtual ([Tus propios servidores](../admin/self-hosting.md#a-forwarder)).
- **El reenviador del proyecto** en `cbb.tools`, cuya dirección y clave vienen integradas en Connect Beyond Borders y se mantienen actualizadas mediante listas firmadas.

Los dispositivos prueban primero las direcciones directas de tu hub y usan el reenviador solo cuando las conexiones directas no responden.

## Redes que bloquean las VPN

Algunas redes Wi-Fi de hoteles y oficinas, operadores móviles y países bloquean el tráfico WireGuard estándar. Por defecto, un hub disfraza su túnel para que las conexiones logren pasar:

- **AmneziaWG**: aleatoriza las cabeceras de los paquetes y añade relleno para que el túnel no se parezca a WireGuard en la red.
- **VLESS** (cuando se usa un reenviador): transporta el túnel disfrazado dentro de lo que parece una conexión HTTPS normal al sitio web del reenviador.

Los dispositivos prueban primero AmneziaWG por UDP porque es más rápido, y cambian a VLESS por HTTPS cuando UDP está bloqueado. Cuando VLESS está activado, los dispositivos nunca recurren a WireGuard sin disfrazar, por lo que las redes con filtrado no ven tráfico VPN sin enmascarar.

Los ordenadores, los dispositivos pequeños (salvo los routers MIPS, que solo sincronizan en casa; consulta [Dispositivos, puertos y archivos](../reference/devices.md)) y todas las apps de teléfono admiten tanto AmneziaWG como VLESS. Sin importar cómo se disfrace el túnel, las copias siguen protegidas por WireGuard, TLS mutuo y cifrado de extremo a extremo. Para cambiar estos ajustes, consulta [Redes que bloquean las VPN](blocked-networks.md) y [Comandos](../reference/cli.md).

## Sin hub: un relé ciego

Un teléfono nunca es un hub: los teléfonos entran en reposo, cambian de red y no pueden aceptar conexiones en segundo plano de forma fiable. Cuando un grupo no tiene ningún ordenador, router o placa pequeña actuando como hub —por ejemplo, un grupo formado solo por teléfonos—, sus dispositivos se encuentran en un **relé ciego**.

![Un portátil fuera de casa y un Mac en casa se conectan a través de túneles a un relé ciego, con cifrado de extremo a extremo directo entre ambos dispositivos](../images/relay.svg)

Un relé ciego es un punto de encuentro, no un miembro del grupo. Cada dispositivo abre un túnel cifrado hacia el relé, y el relé une dos dispositivos del mismo grupo para que su TLS mutuo y sus copias selladas de extremo a extremo circulen directamente entre ellos. El relé no puede leer tu portapapeles ni hacerse pasar por un dispositivo.

Como un relé ciego no almacena nada, ambos dispositivos deben estar en línea al mismo tiempo para intercambiar una copia. Los ordenadores y todas las apps de teléfono pueden usar un relé ciego, ya sea el relé abierto del proyecto en `cbb.tools` o uno en tu propio servidor. El dispositivo principal activa un relé ciego para el grupo solo con tu consentimiento. Consulta [Fuera de casa](away-from-home.md#no-computer-for-a-hub) y [Tus propios servidores](../admin/self-hosting.md#a-blind-relay).

## Qué puede ver cada servidor

Ni un reenviador ni un relé ciego reciben nunca la lista de dispositivos de tu grupo, los nombres de tus dispositivos ni sus identificadores permanentes. En su lugar, tu grupo genera **credenciales de servidor** temporales —un juego distinto para cada servidor— y las reemplaza aproximadamente una vez al mes (y de inmediato cuando quitas un dispositivo). Cada servidor ve únicamente identificadores aleatorios temporales (seudónimos) durante ese periodo, y dos servidores no pueden vincular entre sí el tráfico de tu grupo.

| Servidor | Lee el portapapeles | Sabe qué dispositivos hablan y cuándo | Operado por |
|---|---|---|---|
| Hub que lee las copias | Sí (es tu propio dispositivo principal o un ordenador administrador) | Sí | Tú |
| Hub que solo reenvía las copias | No (las copias van selladas sin incluirlo) | Sí (ve el remitente, la hora y el tamaño redondeado) | Tú |
| Reenviador | No | No (ve las direcciones de red que intercambian paquetes cifrados con tu hub, la hora de los paquetes y su tamaño) | Tú, o el proyecto en `cbb.tools` |
| Relé ciego | No | Sí (ve seudónimos temporales de dispositivos en línea a la vez, sus direcciones de red, la hora y el volumen) | Tú, o el proyecto en `cbb.tools` |

Connect Beyond Borders no usa cuentas, ni almacenamiento en la nube, ni telemetría. Cuando la sincronización fuera de casa está desactivada, el servicio en un ordenador se comunica únicamente en tu red doméstica. Cuando la sincronización fuera de casa está activada, el servicio se comunica únicamente con tu red doméstica y con el hub, el reenviador y el relé de tu propio grupo. El programa aplica este límite en todos los sistemas, y Linux y Windows lo refuerzan además con reglas de red del sistema.

Cuando la app del teléfono está cerrada y las notificaciones están activadas, tus dispositivos pueden despertar el teléfono con un aviso sellado enviado a través de `cbb.tools` y el servicio de notificaciones push del teléfono. Solo tu teléfono puede abrir el aviso; ninguno de los dos servicios de notificaciones push puede leer tus copias.

Para ver una lista completa de qué pueden ver otras partes (como tu red Wi-Fi, las comprobaciones de actualizaciones y las tiendas de apps), lee [Privacidad: quién ve qué](privacy.md). Para la especificación técnica completa, consulta [Diseño](../design.md) y [Protocolo](../protocol.md).
