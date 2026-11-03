<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 90564bcf632e -->
# Redes que bloquean las VPN

Fuera de casa, tus dispositivos llegan al hub por el túnel WireGuard del propio grupo. Algunas redes bloquean WireGuard: el Wi-Fi de hoteles y oficinas, algunos operadores móviles y países enteros que filtran las VPN. Copy Beyond Borders tiene dos formas de sortearlo. Ambas se activan en el hub, y los dispositivos las toman la próxima vez que se encuentran con el hub en casa.

| Forma | Lo que ve la red | Qué necesitas | Funciona en |
|---|---|---|---|
| WireGuard normal (por defecto) | paquetes WireGuard | el hub o un reenviador | ordenadores, teléfonos, miembro ligero |
| **AmneziaWG** (`-obfuscate`) | paquetes UDP que no se parecen a nada en particular | el hub o un reenviador | ordenadores, teléfonos |
| **VLESS con REALITY** (`-vless`) | una conexión HTTPS a un sitio web conocido | un reenviador con VLESS activado | ordenadores, teléfonos |

Elijas lo que elijas, el portapapeles permanece dentro del túnel del grupo y del TLS propio de los dispositivos, así que nada entre tus dispositivos puede leerlo. El disfraz solo cambia el aspecto de los paquetes en la red.

## Cuál usar

1. Prueba primero **WireGuard normal**. Es el más rápido y funciona en la mayoría de las redes.
2. Si el túnel no se levanta en alguna red, o se corta pasado un rato, activa **AmneziaWG**. La mayoría de los filtros que buscan WireGuard ya no lo reconocen.
3. Si incluso eso está bloqueado, como en países que bloquean todo tipo de tráfico desconocido, usa **VLESS con REALITY**. Necesita un reenviador (el tuyo o, más adelante, el del proyecto) que escuche en el puerto TCP 443.

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

## VLESS con REALITY

VLESS funciona entre tus dispositivos y el reenviador. REALITY hace que el reenviador responda como un sitio web real y conocido: quien se conecte a él sin las claves del grupo, un censor que lo sondee por ejemplo, recibe las páginas propias de ese sitio. Por eso hay que preparar primero el reenviador y después el hub.

1. **En el reenviador**, elige un sitio HTTPS grande que no esté bloqueado en el país al que viajas y que admita TLS 1.3, e inicia el reenviador con él:

   ```sh
   cbb forward -vless-site www.example.com
   ```

   El reenviador ahora también escucha en el TCP 443 (`-vless-listen` para otro puerto). Abre ese puerto en el cortafuegos del servidor, junto al UDP y el TCP 8764. La preparación del servidor está en [cómo ejecutar tus propios servidores](../admin/self-hosting.md#vless-on-the-forwarder).

2. **En el hub**:

   ```sh
   sudo cbb global hub -forwarder 198.51.100.9:8764 -forwarder-key <key> -vless
   ```

   Añade también `-obfuscate` si quieres; entonces se aplican ambos.

3. **En los dispositivos**: encuéntrate una vez con el hub en casa, como tras cualquier cambio. Desde entonces solo llegan al reenviador mediante VLESS, nunca con WireGuard normal primero, así que la red de la que quieres ocultar el túnel nunca lo ve.

## Consejos para países que filtran

- **Deja todo configurado en casa, antes de viajar.** Los dispositivos toman los ajustes del hub solo en la red doméstica.
- Elige un reenviador fuera del país que filtra, en un proveedor de alojamiento que no esté bloqueado allí.
- Para VLESS, elige un sitio que la gente de ese país use a diario, de modo que bloquearlo les perjudique; y que lo sirva un proveedor distinto del de tu reenviador.
- La VPN propia del teléfono sigue funcionando: el túnel de la app es tráfico normal de la app y no ocupa el hueco de VPN del teléfono.
- Si el túnel deja de funcionar durante un viaje, `cbb global` en un portátil dice qué falla, y `CBB_DEBUG=1` muestra los detalles ([solución de problemas](troubleshooting.md#sync-away-from-home)).
