<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 5a06c8a1fa53 -->
# Redes que bloquean las VPN

Fuera de casa, tus dispositivos llegan al hub por el túnel WireGuard del propio grupo. Algunas redes bloquean WireGuard: el Wi-Fi de hoteles y oficinas, algunos operadores móviles y países enteros que filtran las VPN. Copy Beyond Borders tiene dos formas de sortearlo, y un hub usa ambas salvo que las desactives; los dispositivos toman un cambio la próxima vez que se encuentran con el hub en casa.

| Forma | Lo que ve la red | Qué necesitas | Funciona en |
|---|---|---|---|
| **AmneziaWG** (activado por defecto; `-no-obfuscate` junto con `-no-vless` lo desactiva) | paquetes UDP que no se parecen a nada en particular | el hub o un reenviador | ordenadores, teléfonos |
| **VLESS** (activado por defecto en un reenviador; `-no-vless` lo desactiva) | una conexión HTTPS a un sitio web | un reenviador con VLESS activado (el del proyecto lo tiene) | ordenadores, teléfonos |
| WireGuard normal (`-no-obfuscate -no-vless`) | paquetes WireGuard | el hub o un reenviador | ordenadores, teléfonos, dispositivos pequeños |

Elijas lo que elijas, el portapapeles permanece dentro del túnel del grupo y del TLS propio de los dispositivos, así que nada entre tus dispositivos puede leerlo. El disfraz solo cambia el aspecto de los paquetes en la red.

## Cómo eligen los dispositivos

Los dispositivos prueban primero **AmneziaWG** por UDP, que es lo más rápido donde la red lo deja pasar: la mayoría de los filtros que buscan WireGuard no lo reconocen. Donde incluso eso está bloqueado, como en países que bloquean todo tipo de tráfico desconocido, llegan al reenviador mediante **VLESS**, que necesita un reenviador que acepte VLESS en el puerto TCP 443: el del proyecto en cbb.tools lo hace, o el tuyo. Un hub sin reenviador ofrece solo AmneziaWG.

Nada sirve en una red que solo deja pasar una lista de direcciones aprobadas.

## AmneziaWG

Un hub habla AmneziaWG en cuanto lo es:

```sh
sudo cbb global hub 203.0.113.7:8764
```

Genera al azar los ajustes del grupo y los cambia más o menos una vez al mes, avisando de antemano a los dispositivos de los siguientes. En una red donde no se bloquea nada, WireGuard normal es un poco más rápido:

```sh
sudo cbb global hub -no-obfuscate -no-vless 203.0.113.7:8764
```

Tras un cambio, lleva a casa una vez cada portátil y cada teléfono, o deja la app abierta en casa, para que tome los ajustes nuevos.

## VLESS

VLESS funciona entre tus dispositivos y el reenviador, dentro de lo que para la red parece una conexión HTTPS normal a un sitio web.

1. **El reenviador.** El reenviador del proyecto en cbb.tools tiene VLESS activado: para la red, tus dispositivos visitan `cbb.tools`. Un reenviador propio lo ejecuta detrás del servidor web de un sitio tuyo:

   ```sh
   cbb forward -vless-xhttp vpn.example.org
   ```

   El servidor web, que tiene el certificado de tu sitio, le pasa la ruta que imprime el reenviador; cualquier otro recibe las páginas propias de tu sitio. Abre el TCP 443 en el cortafuegos del servidor, junto al UDP y el TCP 8764. La preparación del servidor está en [cómo ejecutar tus propios servidores](../admin/self-hosting.md#vless-on-the-forwarder).

2. **En el hub**: nada que hacer. Un hub en un reenviador pide VLESS:

   ```sh
   sudo cbb global hub -forwarder default
   ```

   (`-forwarder 198.51.100.9:8764 -forwarder-key <key>` para el tuyo.) El reenviador le dice al hub su sitio y su ruta; uno sin VLESS registra el hub solo para UDP. VLESS viene con AmneziaWG: dentro de VLESS oculta el tamaño de los paquetes de WireGuard, que de otro modo se notaría a través del HTTPS. `-no-vless` desactiva VLESS.

3. **En los dispositivos**: encuéntrate una vez con el hub en casa, como tras cualquier cambio. Desde entonces prueban primero AmneziaWG por UDP, que es más rápido donde la red lo deja pasar, y VLESS cuando no, y se quedan con la forma que funcionó. Nunca prueban WireGuard normal, así que la red de la que quieres ocultar el túnel nunca lo ve.

## Consejos para países que filtran

- **Deja todo configurado en casa, antes de viajar.** Los dispositivos toman los ajustes del hub solo en la red doméstica.
- Elige un reenviador fuera del país que filtra, en un proveedor de alojamiento que no esté bloqueado allí.
- El sitio del reenviador se ve en el primer paquete de cada conexión: una red que bloquea el sitio bloquea también el camino. Entonces la solución es un reenviador propio, en otro sitio.
- La VPN propia del teléfono sigue funcionando: el túnel de la app es tráfico normal de la app y no ocupa el hueco de VPN del teléfono.
- Si el túnel deja de funcionar durante un viaje, `cbb global` en un portátil dice qué falla, y `CBB_DEBUG=1` muestra los detalles ([solución de problemas](troubleshooting.md#sync-away-from-home)).
