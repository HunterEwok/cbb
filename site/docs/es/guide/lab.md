<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 6f215e8c49c0 -->
# El laboratorio

Para cualquiera que tenga curiosidad por las funciones experimentales de Connect Beyond Borders más allá de la sincronización diaria del portapapeles.

Connect Beyond Borders se centra en una promesa principal: un único portapapeles cifrado compartido entre tus teléfonos y ordenadores. El laboratorio es donde se prueban otras formas de usar tu grupo. Todos los experimentos siguientes compilan y superan pruebas automáticas en CI, pero estas funciones son experimentales: pueden cambiar o eliminarse, y la mayoría tienen pruebas limitadas en hardware físico. Consulta [Paridad entre plataformas](../parity.md#on-real-devices) para ver el estado actual en hardware real.

## Experimentos

| Experimento | Qué hace | Guía |
|---|---|---|
| **Teclados Bluetooth y USB** | Un teléfono Android, Aurora OS o HarmonyOS, un ordenador Linux o un Arduino Nano ESP32 escribe texto en un televisor, una tableta, una consola de juegos o un ordenador que no ejecuta Connect Beyond Borders | [Teclados y televisores](keyboards-and-tvs.md) |
| **Mandos de televisor** | Un ordenador en tu red doméstica escribe directamente en un Android TV, Google TV, Apple TV o Roku por la red local como si fuera su mando | [Teclados y televisores](keyboards-and-tvs.md#a-computer-as-the-tvs-remote) |
| **Arduino Nano ESP32** | Firmware de microcontrolador económico que ejecuta Wi-Fi, una autocomprobación del protocolo TLS 1.3 y un teclado USB y Bluetooth LE (unirse a un grupo y sincronizar el portapapeles están en la [hoja de ruta](../roadmap.md)) | [Firmware ESP32](../../esp32/README.md) |
| **ZX Spectrum Next** | Copia texto y secretos, pega texto, muestra imágenes del grupo en Layer 2 y recibe pegado remoto a través de la Raspberry Pi dentro de un Accelerated Next | [`.cbb` para el Next](../../apps/zxnext/README.md) |

## Dónde encontrar las funciones del laboratorio

- **Apps de teléfono (Android, Aurora OS y HarmonyOS):** Abre **Ajustes**, activa **Ajustes avanzados** y desplázate hasta **Laboratorio** (contiene los controles de **Teclado Bluetooth**).
- **Ordenadores:** Usa `cbb keyboard` (Linux) y `cbb remote` (Linux, macOS, Windows y FreeBSD) en una terminal; consulta [Comandos](../reference/cli.md).
- **ESP32 y ZX Spectrum Next:** Sigue las instrucciones de configuración de cada dispositivo enlazadas en la tabla anterior.

## Comparte tu opinión

Si pruebas un experimento en hardware real, cuéntanos cómo funciona en una [incidencia en GitHub](https://github.com/HunterEwok/cbb/issues). Los experimentos que demuestren ser fiables en dispositivos reales pueden salir del laboratorio y convertirse en funciones con soporte.
