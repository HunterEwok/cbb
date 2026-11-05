<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 8cc314e35203 -->
# Privacidad: quién ve qué

Para quien quiera saber qué sale de sus dispositivos. Copy Beyond Borders no tiene cuentas, ni
nube, ni telemetría: lo que copias va cifrado de extremo a extremo, sellado en el dispositivo que
lo copia para los dispositivos de tu grupo que leen copias, y nada más puede abrirlo: ni un
servidor, ni una red, ni un dispositivo intermedio. Esta página dice qué pueden ver aún los
dispositivos que pasan una copia, y todo lo que puede ver alguien fuera del grupo, y cómo
desactivarlo.

## Lo que copias

Los textos, las imágenes y los archivos van cifrados de extremo a extremo. El dispositivo que
copia cifra cada copia con una clave creada solo para ella, envuelve esa clave para cada
dispositivo del grupo que lee copias (X-Wing, que une X25519 y el poscuántico ML-KEM-768) y firma
la copia con su clave de miembro. Solo esos dispositivos pueden abrirla; cada dispositivo
comprueba la firma, así que ninguno puede cambiar una copia ni hacer una en nombre de otro. Luego
la copia sellada viaja dentro de TLS 1.3 con los certificados propios del grupo, y fuera de casa
también dentro de WireGuard, a través de tu hub y quizá de un reenviador o un relé. Ningún
servidor, red ni proveedor puede leerla, ni siquiera los servidores del proyecto. Un dispositivo
que se quita del grupo ya no recibe nada, y uno que se une lee las copias desde la siguiente, no
las hechas antes.

## Lo que ven los dispositivos intermedios

Una copia llega a menudo a un dispositivo a través de otro: a través del hub fuera de casa, o de
un ordenador que la pasa en casa. Esos dispositivos no leen nada de una copia que no esté sellada
para ellos, pero pasarla necesita un poco, que queda fuera del sello:

- **Qué dispositivo la envió, y cuándo.** La hora decide qué copia es la más nueva, lo que
  necesita cada dispositivo, incluido un hub que solo pasa las copias.
- **Para qué dispositivos está sellada.** Es la lista de dispositivos del grupo, que ya conocen.
- **Su tamaño por escalones** (1, 4, 16, 64 y 256 KB, 1 MB, y luego cada megabyte más), y si
  lleva una imagen o archivos, con su total redondeado a 64 KB. Todos los archivos de una copia
  son un solo trozo sellado, así que no se ve cuántos son.

Lo que nunca se ve: si es un texto, un secreto, una imagen o archivos; el texto; los nombres de
los archivos; el tamaño exacto.

## Excepciones

Las dos dependen de ti:

- Un **Roku** añadido con `cbb remote add -roku -consent` recibe su texto como HTTP sin cifrar en tu red doméstica ([teclados y televisores](keyboards-and-tvs.md#a-computer-as-the-tvs-remote)).
- Un **hub que lee las copias** es un administrador que tú elegiste, así que las copias se sellan
  para él como para tus otros dispositivos. Un ordenador siempre encendido cuyas claves están
  solo en un archivo, como una Raspberry Pi, conviértelo mejor en un **hub que solo pasa las
  copias**: no se sella ninguna copia para él, así que no lee ninguna
  ([fuera de casa](away-from-home.md)). Las órdenes, como un pegado remoto o una acción rápida,
  se sellan en ambos casos para el único dispositivo al que van ([pegado remoto](remote-paste.md)).
- Un **Apple Watch** o un reloj **Wear OS** recibe las copias de su teléfono por el canal que el
  propio sistema cifra entre los dos, no selladas por Copy Beyond Borders.

## Todos los demás

| Quién | Qué puede ver | Cómo evitarlo |
|---|---|---|
| Otros en tu red doméstica | que hay dispositivos que ejecutan Copy Beyond Borders, sus ID de dispositivo aleatorios y la etiqueta de tu grupo en mDNS, y cuáles se comunican y cuánto; nunca los nombres de los dispositivos ni los contenidos | nada que hacer; un ordenador publica solo en las redes domésticas que conoce (un miembro ligero, en todas las redes) |
| Otros en una red fuera de casa (una cafetería, un hotel) | que el dispositivo habla WireGuard, o que con VLESS abre una conexión TLS a tu hub o reenviador, cuándo y cuánto | una VPN del sistema oculta incluso eso |
| El reenviador (el tuyo, o el del proyecto en `cbb.tools`) | las direcciones de las que vienen los paquetes cifrados y que van a tu hub, cuándo y de qué tamaño; no a qué grupo o dispositivo pertenecen | ejecutar el tuyo, o redirigir un puerto a tu hub y no usar ninguno |
| Un relé ciego | cuáles de los dispositivos de un grupo están en línea ahora y se comunican entre sí, cuándo y cuánto; no guarda nada de ello | ejecutar el tuyo, o usar un hub |
| La empresa que aloja un reenviador o un relé | las direcciones que se comunican con él, cuándo y cuánto | una VPN del sistema en el dispositivo |
| GitHub, o `dl.cbb.tools` cuando GitHub no responde | tu dirección y que usas Copy Beyond Borders, en cada comprobación de actualizaciones y descarga; nada sobre el grupo | `sudo cbb update -auto off`, o un espejo propio (`-mirror`) |
| `cbb.tools` | la dirección de la raíz, una vez al día, cuando obtiene la copia firmada de la lista de claves de Android revocadas de Google (cuando esa copia empiece, con las claves de firma del proyecto) | no hace falta nada: es el mismo archivo para todos |
| Apple, Intel o AMD | que un dispositivo de ese tipo les pidió respaldar su clave, desde tu dirección | solo en el nivel de claves **estricto**; el nivel por defecto no pregunta a nadie ([claves](keys.md#the-three-levels)) |
| La App Store, Google Play, F-Droid, Homebrew, winget | que instalaste la app, como con cualquier app | instala en su lugar el archivo firmado de la versión |

Nada informa de fallos ni de uso. Los registros se quedan en cada dispositivo; con los detalles de error activados (`CBB_DEBUG=1`), contienen más información de la causa, también solo en ese dispositivo.

## El sitio web

`cbb.tools` cuenta las visitas con su propio GoatCounter, sin cookies y sin enviar nada a otra empresa. Las apps y el servicio nunca cargan nada de él aparte de los archivos mencionados arriba.

## Más detalle

- Qué guardan un reenviador y un relé, y qué ve su proveedor de alojamiento: [cómo ejecutar tus propios servidores](../admin/self-hosting.md#what-the-server-keeps).
- Qué aprende cada servidor, campo por campo: el [protocolo](../protocol.md), secciones 13 y 14.
- Los ataques frente a los que se defiende Copy Beyond Borders, y aquellos frente a los que no: el [modelo de amenazas](../threat-model.md).
