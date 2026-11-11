<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 6e12f051d6a2 -->
# Redes que bloquean las VPN

Fuera de casa, tus dispositivos llegan al hub por el túnel WireGuard del propio grupo. Algunas redes bloquean WireGuard: el Wi-Fi de hoteles y oficinas, algunos operadores móviles y países enteros que filtran las VPN. Copy Beyond Borders tiene dos formas de sortearlo. Ambas se activan en el hub, y los dispositivos las toman la próxima vez que se encuentran con el hub en casa.

| Forma | Lo que ve la red | Qué necesitas | Funciona en |
|---|---|---|---|
| WireGuard normal (por defecto) | paquetes WireGuard | el hub o un reenviador | ordenadores, teléfonos, miembro ligero |
| **AmneziaWG** (`-obfuscate`) | paquetes UDP que no se parecen a nada en particular | el hub o un reenviador | ordenadores, teléfonos |
| **VLESS** (`-vless`) | una conexión HTTPS a un sitio web | un reenviador con VLESS activado (el del proyecto lo tiene) | ordenadores, teléfonos |

Elijas lo que elijas, el portapapeles permanece dentro del túnel del grupo y del TLS propio de los dispositivos, así que nada entre tus dispositivos puede leerlo. El disfraz solo cambia el aspecto de los paquetes en la red.

## Cuál usar

1. Prueba primero **WireGuard normal**. Es el más rápido y funciona en la mayoría de las redes.
2. Si el túnel no se levanta en alguna red, o se corta pasado un rato, activa **AmneziaWG**. La mayoría de los filtros que buscan WireGuard ya no lo reconocen.
3. Si incluso eso está bloqueado, como en países que bloquean todo tipo de tráfico desconocido, usa **VLESS**. Necesita un reenviador que acepte VLESS en el puerto TCP 443: el del proyecto en cbb.tools lo hace, o el tuyo.

Nada sirve en una red que solo deja pasar una lista de direcciones aprobadas.

## AmneziaWG

En el hub:

```sh
sudo cbb global hub -obfuscate 203.0.113.7:8764
```

Con un reenviador, añade `-obfuscate` del mismo modo:

```sh
sudo cbb global hub -obfuscate -forwarder 198.51.100.9:8764 -forwarder-key <key>
```

El hub genera una sola vez, al azar, los ajustes del grupo y los mantiene mientras `-obfuscate` siga puesto. Después, lleva a casa una vez cada portátil y cada teléfono, o deja la app abierta en casa, para que tome los ajustes nuevos. El miembro ligero solo habla WireGuard normal: en un grupo con ofuscación sincroniza solo en casa.

## VLESS

VLESS funciona entre tus dispositivos y el reenviador, dentro de lo que para la red parece una conexión HTTPS normal a un sitio web.

1. **El reenviador.** El reenviador del proyecto en cbb.tools tiene VLESS activado: para la red, tus dispositivos visitan `cbb.tools`. Un reenviador propio lo ejecuta detrás del servidor web de un sitio tuyo:

   ```sh
   cbb forward -vless-xhttp vpn.example.org
   ```

   El servidor web, que tiene el certificado de tu sitio, le pasa la ruta que imprime el reenviador; cualquier otro recibe las páginas propias de tu sitio. Abre el TCP 443 en el cortafuegos del servidor, junto al UDP y el TCP 8764. La preparación del servidor está en [cómo ejecutar tus propios servidores](../admin/self-hosting.md#vless-on-the-forwarder).

2. **En el hub**: activa VLESS en la app (el túnel del hub: VLESS), o:

   ```sh
   sudo cbb global hub -forwarder default -vless
   ```

   (`-forwarder 198.51.100.9:8764 -forwarder-key <key>` para el tuyo.) El reenviador le dice al hub su sitio y su ruta. Añade también `-obfuscate` si quieres; entonces se aplican ambos.

3. **En los dispositivos**: encuéntrate una vez con el hub en casa, como tras cualquier cambio. Desde entonces solo llegan al reenviador mediante VLESS, nunca con WireGuard normal primero, así que la red de la que quieres ocultar el túnel nunca lo ve.

## Consejos para países que filtran

- **Deja todo configurado en casa, antes de viajar.** Los dispositivos toman los ajustes del hub solo en la red doméstica.
- Elige un reenviador fuera del país que filtra, en un proveedor de alojamiento que no esté bloqueado allí.
- La VPN propia del teléfono sigue funcionando: el túnel de la app es tráfico normal de la app y no ocupa el hueco de VPN del teléfono.
- Si el túnel deja de funcionar durante un viaje, `cbb global` en un portátil dice qué falla, y `CBB_DEBUG=1` muestra los detalles ([solución de problemas](troubleshooting.md#sync-away-from-home)).
