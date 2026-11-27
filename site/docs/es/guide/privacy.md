<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: ecfb35897e1b -->
# Privacidad: quién ve qué

Para cualquiera que quiera saber qué datos salen de sus dispositivos, qué puede observar cada servidor y plataforma y cómo limitar o desactivar cada exposición. Connect Beyond Borders no usa cuentas, ni almacenamiento del portapapeles en la nube, ni telemetría de análisis.

## Qué pasa con tus copias

Cada copia —texto sin formato, secretos, texto con formato, imágenes y archivos— se cifra de extremo a extremo antes de salir del dispositivo donde la copiaste:

1. El dispositivo que copia crea una clave nueva de 32 bytes para esa única copia y cifra el contenido con ChaCha20-Poly1305.
2. Envuelve esa clave de forma individual para cada dispositivo lector de tu grupo usando HPKE con **X-Wing** (combinando X25519 y el poscuántico ML-KEM-768) y firma la copia con su propia clave de miembro (ECDSA P-256).
3. La copia sellada viaja dentro de una conexión **TLS 1.3** mutua que usa las claves de dispositivo de tu grupo, y fuera de casa también dentro del túnel **WireGuard** de tu grupo.

Ningún servidor, red, proveedor de internet ni dispositivo intermedio sin una clave lectora puede leer, alterar ni falsificar una copia. Un dispositivo quitado no recibe copias futuras, y un dispositivo recién unido no puede descifrar copias hechas antes de unirse.

## Qué ven los dispositivos intermedios

Una copia puede pasar por otro dispositivo de tu grupo antes de llegar a su destino —por ejemplo, por tu hub fuera de casa o por otro miembro en tu red doméstica—. Un dispositivo que solo reenvía copias no puede abrir el sello, así que solo ve los metadatos del sobre necesarios para la entrega:

- **Remitente y marca de tiempo:** Qué dispositivo copió el elemento y cuándo (necesario para decidir qué copia es la más nueva).
- **Lista de destinatarios:** Para qué dispositivos está sellada la copia (algo que los miembros del grupo ya conocen por los registros de dispositivos del grupo).
- **Tamaño redondeado:** El tamaño del texto redondeado a escalones fijos (`1`, `4`, `16`, `64`, `256` KB, `1` MB y luego por megabyte), y si lleva una imagen o un archivo adjunto con su total redondeado a `64` KB. Todos los archivos de una copia viajan dentro de un único bloque sellado, así que el número de archivos queda oculto.

Los dispositivos intermedios nunca ven si una copia es texto sin formato, un secreto, una imagen o archivos; nunca ven el texto ni los nombres de los archivos; y nunca ven el tamaño exacto en bytes.

## Excepciones opcionales

Algunas funciones usan canales fuera del sello de extremo a extremo de Connect Beyond Borders. Cada una requiere tu elección explícita:

- **Mando de televisor Roku (`cbb remote add -roku -consent`):** El protocolo External Control Protocol de Roku usa HTTP sin cifrar en tu red doméstica. No envíes contraseñas a un Roku ([Teclados y televisores](keyboards-and-tvs.md#a-computer-as-the-tvs-remote)).
- **Hub que lee las copias:** Un dispositivo principal o un ordenador administrador que actúa como hub recibe copias selladas para él como cualquier otro dispositivo lector. Si tu hub siempre encendido guarda las claves en archivos (como una Raspberry Pi o un NAS), configúralo como un **hub que solo reenvía las copias** para que nunca se sellen copias para él ([Fuera de casa](away-from-home.md)). Las órdenes firmadas (como el pegado remoto y las acciones rápidas) siempre se sellan solo para su único dispositivo de destino.
- **Relojes emparejados (Apple Watch, Wear OS, reloj HarmonyOS):** Un reloj se comunica con su teléfono emparejado a través del canal cifrado propio del sistema operativo entre teléfono y reloj (WatchConnectivity, Wearable Data Layer o Wear Engine) y muestra el estado de los dispositivos, eventos e interruptores en lugar del contenido de tu portapapeles.
- **Teclados Bluetooth y USB:** El texto escrito mediante un teclado de teléfono, ordenador Linux o Arduino Nano ESP32 viaja por Bluetooth o USB directamente al dispositivo de destino emparejado.

## Todos los que están fuera de tu grupo

Cuando la sincronización fuera de casa está desactivada, el servicio en segundo plano se comunica solo en tu red doméstica. Cuando la sincronización fuera de casa está activada, el servicio se comunica solo con tu red doméstica y con el hub, el reenviador y el relé propios de tu grupo (aplicado en el código en todos los sistemas operativos y mediante reglas de cortafuegos/aislamiento del sistema en Linux y Windows).

Ni un reenviador ni un relé ciego ven nunca la lista de dispositivos de tu grupo, los nombres de los dispositivos ni los ID permanentes de los dispositivos. En su lugar, tu grupo genera **credenciales de servidor** temporales distintas para cada servidor y las rota cada 30 días (y cuando se quita un dispositivo), de modo que dos servidores no pueden vincular entre sí el tráfico de tu grupo.

La tabla siguiente enumera a todos los actores ajenos a tu grupo que pueden observar algún tráfico o metadato:

| Actor | Qué puede ver | Cómo evitarlo o limitarlo |
|---|---|---|
| **Otros dispositivos en tu red doméstica** | Anuncios mDNS que muestran que hay dispositivos ejecutando Connect Beyond Borders, sus ID de dispositivo aleatorios, la etiqueta del grupo y el puerto; qué direcciones IP locales se conectan y cuántos datos se mueven. Nunca nombres de dispositivos ni contenido del portapapeles | Los ordenadores solo se anuncian en redes domésticas conocidas y permanecen en silencio en redes Wi-Fi desconocidas |
| **Redes fuera de casa** (cafetería, hotel, operador móvil, proveedor de internet) | Paquetes UDP cifrados de WireGuard/AmneziaWG —o con VLESS, una conexión HTTPS al dominio del reenviador (visible en TLS SNI)— además de los momentos y el volumen de tráfico | Usa una VPN del sistema en tu dispositivo para ocultar destinos y momentos |
| **Reenviador** (el del proyecto en `cbb.tools`, o el tuyo propio) | Direcciones IP que intercambian paquetes WireGuard cifrados con tu hub, momentos de los paquetes y tamaños de los paquetes; solo etiquetas rotatorias de credenciales de servidor, nunca nombres de dispositivos, pertenencia al grupo ni contenido del portapapeles | Redirige el puerto UDP 8764 directamente a tu hub para no usar ningún reenviador, o [ejecuta tu propio reenviador](../admin/self-hosting.md#a-forwarder) |
| **Relé ciego** (el del proyecto en `cbb.tools`, o el tuyo propio) | Seudónimos rotatorios de dispositivos en línea al mismo tiempo, sus direcciones IP, qué seudónimos hablan entre sí, los momentos y el volumen (mantenidos solo en memoria, nunca escritos en registros). Nunca contenido del portapapeles ni nombres de dispositivos | Usa un hub propio en lugar de un relé ciego, o [ejecuta tu propio relé](../admin/self-hosting.md#a-blind-relay) |
| **Proveedor de alojamiento de un reenviador o relé** | Direcciones IP que se conectan al servidor, horas de conexión y volumen de tráfico | Usa una VPN del sistema en tus dispositivos, o aloja el servidor por tu cuenta en un proveedor que elijas |
| **Servicio de notificaciones push del proyecto** (`cbb.tools`) | Token push del teléfono, etiqueta externa rotatoria del grupo, dirección IP del remitente y marca de tiempo de la notificación al despertar una app de teléfono cerrada. Cada cuerpo push va sellado para el teléfono y rellenado hasta un tamaño fijo, así que el servicio no puede leerlo | Desactiva **Avisarme cuando la app esté cerrada** en **Ajustes** del teléfono |
| **Plataformas push de teléfonos** (Apple APNs, Google FCM o tu distribuidor de UnifiedPush como ntfy) | Que se envió una notificación push a Connect Beyond Borders en tu teléfono y cuándo; nunca el contenido sellado | Desactiva **Avisarme cuando la app esté cerrada** en **Ajustes** del teléfono, o usa la compilación F-Droid de Android con tu propio servidor UnifiedPush en lugar de Google FCM |
| **Servidores de actualizaciones** (GitHub Releases, `raw.githubusercontent.com`, `dl.cbb.tools` y `cbb.tools/openwrt` para el repositorio de OpenWrt) | Tu dirección IP y que comprobaste o descargaste una versión de Connect Beyond Borders; nada sobre tu grupo ni tus copias | Desactiva las actualizaciones automáticas (`sudo cbb update -auto off`, o en Android en **Ajustes > Acerca de**), o apunta las actualizaciones a tu propio espejo HTTPS (`sudo cbb update -mirror https://...`) |
| **Listas firmadas y espejo de atestación del proyecto** (`cbb.tools`) | Tu dirección IP al descargar listas firmadas de puntos de entrada de servidores, o cuando el dispositivo principal descarga la copia diaria firmada de la lista de Google de claves de atestación de Android revocadas (`https://cbb.tools/attest/`) | Se sirven los mismos archivos públicos a todo el mundo; el espejo evita contactar directamente con Google |
| **Receptor de informes de fallos del proyecto** (`https://bug.cbb.tools/`) | Nada en esta versión: las apps aún no envían informes de fallos porque la clave que los sella no está en la compilación. Cuando lo esté, un informe solo se enviará tras un fallo **y** tras tu **Permitir** (o **Permitir siempre**): tu dirección IP, versión de la app, huella del fallo y un informe sellado para el robot del mantenedor con registros de error filtrados, versiones y modelo del dispositivo; nunca texto del portapapeles, archivos, claves, códigos de emparejamiento, nombres de dispositivos ni direcciones IP | Toca **Cancelar** en el aviso de fallo; no se envía nada sin tu consentimiento |
| **Tiendas de apps y gestores de paquetes** (Apple App Store / TestFlight, Google Play, F-Droid, Homebrew, winget) | Que instalaste o actualizaste Connect Beyond Borders, como con cualquier app de esa tienda | Instala archivos firmados de la versión o APK directamente desde GitHub Releases |
| **Estadísticas del sitio web** (`cbb.tools`) | Visitas de páginas cuando navegas por `cbb.tools` en un navegador web, contadas por una instancia propia de GoatCounter sin cookies y sin compartir datos con terceros | Las apps y el servicio en segundo plano nunca cargan páginas del sitio web ni estadísticas |

Los registros permanecen locales en cada dispositivo. Activar los detalles de error (`CBB_DEBUG=1` o **Mostrar detalles de los errores** en los ajustes de la app) añade los detalles subyacentes del error localmente y nunca los envía a ningún sitio automáticamente.

## Más detalle

- Qué guardan en disco un reenviador y un relé ciego: [Tus propios servidores: qué guarda el servidor](../admin/self-hosting.md#what-the-server-keeps).
- Campos exactos de red que ven los servidores y los servicios push: [Protocolo](../protocol.md), secciones 13 y 14.
- Amenazas frente a las que protege y riesgos residuales: [Modelo de amenazas](../threat-model.md).
