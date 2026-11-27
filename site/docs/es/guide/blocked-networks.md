<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 6e944da2c5ca -->
# Redes que bloquean las VPN

Para cualquiera que sincronice fuera de casa en redes que filtran o bloquean WireGuard, como el Wi-Fi de hoteles, redes de oficinas, operadores móviles o países con un filtrado estricto del tráfico. En esta página compruebas o cambias cómo disfraza el túnel tu hub.

Fuera de casa, tus dispositivos llegan a tu hub por el túnel WireGuard de tu grupo. Por defecto, un hub usa tanto **AmneziaWG** como (cuando se usa con un reenviador compatible con VLESS) **VLESS** para que tu túnel atraviese redes con filtrado. Sea cual sea el disfraz, tus copias permanecen dentro de WireGuard, TLS 1.3 mutuo y cifrado de extremo a extremo; consulta [Cómo funciona](how-it-works.md#networks-that-block-vpns).

| Transporte | Qué ve la red | Requisitos | Dispositivos compatibles |
|---|---|---|---|
| **AmneziaWG** (activado por defecto) | Paquetes UDP con cabeceras y relleno aleatorios | Hub o reenviador | Ordenadores, dispositivos pequeños (salvo routers MIPS), teléfonos |
| **VLESS** (activado por defecto con un reenviador VLESS) | Una conexión HTTPS al sitio web del reenviador | Reenviador con VLESS activado (el reenviador del proyecto en `cbb.tools` lo tiene) | Ordenadores, dispositivos pequeños (salvo routers MIPS), teléfonos |
| **WireGuard normal** (`-no-obfuscate -no-vless`) | Paquetes UDP estándar de WireGuard | Hub o reenviador | Ordenadores, dispositivos pequeños (salvo routers MIPS), teléfonos |

## Cómo eligen los dispositivos

Cuando un hub usa un reenviador compatible con VLESS, los dispositivos fuera de casa prueban primero **AmneziaWG** por UDP, porque UDP es más rápido donde la red lo permite. Si UDP está bloqueado —como en redes que solo permiten tráfico web—, cambian automáticamente a **VLESS** por HTTPS (puerto TCP 443) hacia el reenviador y se quedan con el transporte que haya funcionado.

Cuando VLESS está activado, los dispositivos nunca retroceden a WireGuard normal, de modo que las redes con filtrado no ven tráfico VPN sin ocultar. Un hub sin reenviador ofrece solo AmneziaWG.

Ningún disfraz de túnel sirve en una red que solo permite conexiones a una lista fija de direcciones IP o dominios aprobados.

## Configurar el disfraz del túnel en la app de escritorio

En un hub que ejecute la app para Mac o la app de la bandeja para Linux y Windows:

1. Abre **CBB** y selecciona la página de dispositivo de este ordenador.
2. En **Redes estrictas**, activa o desactiva:
   - **Redes que bloquean las VPN (AmneziaWG)** para activar o desactivar AmneziaWG.
   - **Redes que solo dejan pasar la web (VLESS)** para activar o desactivar VLESS (requiere un reenviador compatible con VLESS).
3. Confirma con tu contraseña de administrador, Touch ID, Windows Hello o el aviso de polkit.
4. Conecta cada portátil y teléfono a tu red doméstica una vez para que reciba los ajustes actualizados del túnel del hub.

**Resultado:** El hub guarda los ajustes actualizados y los comparte con tus dispositivos la próxima vez que se encuentren en casa.

## AmneziaWG

Cada hub activa AmneziaWG por defecto en cuanto lo configuras:

```sh
sudo cbb global hub 203.0.113.7:8764
```

El hub genera parámetros aleatorios de AmneziaWG para tu grupo y los rota automáticamente con cada periodo de credenciales del servidor (más o menos una vez al mes), compartiendo el siguiente conjunto con antelación.

Para cambiar a WireGuard normal en redes donde nada bloquea las VPN (lo que reduce la sobrecarga de los paquetes):

1. Ejecuta en el hub (usa `-keep` para conservar las direcciones y el reenviador actuales del hub):

   ```sh
   sudo cbb global hub -keep -no-obfuscate -no-vless
   ```

2. Conecta cada portátil y teléfono de fuera de casa a tu red doméstica una vez (mantén la app del teléfono abierta brevemente) para que reciba los ajustes nuevos.

**Resultado:** Tus dispositivos usan WireGuard normal en cuanto recogen la oferta actualizada en casa.

## VLESS

VLESS transporta tu túnel disfrazado con AmneziaWG dentro de lo que para la red parece una conexión HTTPS normal al sitio web del reenviador. Mantener AmneziaWG dentro de VLESS oculta los tamaños de los paquetes de WireGuard, que de otro modo podrían destacar dentro de HTTPS.

1. **Elige un reenviador con VLESS:**
   - **El reenviador del proyecto en `cbb.tools`** ya tiene VLESS activado; para la red, tus dispositivos parecen visitar `cbb.tools`.
   - **Tu propio reenviador:** Ejecuta `cbb forward` detrás de un servidor web que tenga el certificado TLS de tu sitio:

     ```sh
     cbb forward -vless-xhttp vpn.example.org
     ```

     Configura tu servidor web para redirigir por proxy la ruta que imprime `cbb forward` hacia el oyente local del reenviador (`127.0.0.1:3276` por defecto), mientras sirve tus propias páginas web a todos los demás. Abre el **puerto TCP 443** en el cortafuegos del servidor junto a los puertos UDP y TCP 8764. Consulta [Tus propios servidores: VLESS en el reenviador](../admin/self-hosting.md#vless-on-the-forwarder).

2. **Apunta tu hub al reenviador:** En el hub, regístrate con el reenviador del proyecto o con el tuyo propio:

   ```sh
   sudo cbb global hub -forwarder default
   ```

   Para tu propio reenviador, pasa en su lugar su dirección y su clave:

   ```sh
   sudo cbb global hub -forwarder 198.51.100.9:8764 -forwarder-key KEY
   ```

   **Resultado:** El hub solicita VLESS automáticamente. Si el reenviador admite VLESS, envía al hub el nombre de su sitio y su ruta; de lo contrario, el hub se registra solo para UDP. Para desactivar VLESS manteniendo AmneziaWG, pasa `-no-vless` (por ejemplo, `sudo cbb global hub -keep -no-vless`).

3. **Sincroniza una vez en casa:** Trae cada portátil y teléfono a tu red doméstica (y abre la app del teléfono brevemente) después de cambiar los ajustes del hub.

   **Resultado:** Tus dispositivos reciben la oferta VLESS del hub y la usan automáticamente siempre que UDP esté bloqueado.

## Consejos para países que filtran el tráfico

- **Configura y prueba en casa antes de viajar.** Los dispositivos reciben los ajustes del túnel de un hub solo en tu red doméstica.
- **Aloja tu reenviador fuera del país que filtra**, en un proveedor cuyas direcciones IP no estén bloqueadas allí.
- **Cuenta con el bloqueo de dominios:** El nombre de dominio del reenviador aparece en el saludo TLS (SNI). Si una red bloquea `cbb.tools`, ejecuta tu propio reenviador detrás de otro nombre de dominio.
- **Conserva tu VPN del sistema:** El túnel de Connect Beyond Borders se ejecuta dentro de la app como tráfico ordinario y no ocupa el espacio de VPN de tu teléfono, así que tu propia VPN sigue funcionando al mismo tiempo.
- **Renueva puntos de entrada bloqueados:** Si cambian los puntos de entrada del reenviador del proyecto y un dispositivo no puede alcanzarlos, exporta puntos de entrada firmados desde un ordenador conectado con `cbb global entries export` (o `-qr`) e impórtalos en el ordenador afectado con `sudo cbb global entries import STRING`.
- **Inspecciona los fallos:** Ejecuta `cbb global` en un portátil para ver por qué falló el túnel, y activa `CBB_DEBUG=1` en el servicio para ver los registros del saludo de WireGuard ([Solución de problemas: sincronizar fuera de casa](troubleshooting.md#sync-away-from-home)).
