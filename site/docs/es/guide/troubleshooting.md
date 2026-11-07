<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 18b8e122d883 -->
# Cuando algo no funciona

Empieza con `cbb status` en el dispositivo que falla: dice si el servicio está en marcha, en qué grupo está, qué miembros están conectados y el estado de la sincronización fuera de casa. Cada mensaje es corto; `CBB_DEBUG=1 cbb status` (en Windows, antes `$env:CBB_DEBUG = "1"`) muestra debajo el error subyacente. El registro del servicio siempre tiene los detalles: en Linux `journalctl -u cbb`, y el del conector de escritorio está en el diario de la sesión, `journalctl --user`; los demás sistemas están en [archivos y registros](../reference/devices.md#files-and-logs). El interruptor de detalles de cada parte, incluidas las apps y los instaladores, está en [mensajes de error y detalles](../reference/errors.md).

## Comandos

**"the CBB service is not running"**: inícialo (`sudo systemctl start cbb` en Linux; `sudo launchctl kickstart -k system/tools.cbb` en un Mac; `Start-Service cbb` en Windows) y mira su registro.

**"permission denied" en el socket de control, justo después de instalar**: el instalador te añadió al grupo `cbb`, y un grupo cuenta solo desde el siguiente inicio de sesión. Cierra la sesión y vuelve a abrirla (en Windows, abre una terminal nueva); hasta entonces, `sudo cbb ...` funciona.

## Los dispositivos no se ven entre sí

- **Cortafuegos.** Los miembros necesitan TCP 8764 (o tu puerto) y UDP 5353 (mDNS) desde la red doméstica. Los instaladores los añaden cuando respondes Sí; qué cortafuegos conocen, y los comandos para los demás, están en [el cortafuegos](install.md#the-firewall). Si activas un cortafuegos más tarde, ejecuta el instalador de nuevo. Si `cbb status` avisa de que los demás no pueden conectarse a este ordenador, su cortafuegos está bloqueando el puerto de miembros.
- **Otra subred o VLAN.** mDNS no cruza los routers, así que los dispositivos en, por ejemplo, 192.168.0.x y 192.168.20.x no se encuentran. Activa la [sincronización fuera de casa](away-from-home.md) con un hub en un lado o, para un miembro ligero, indica un ordenador con `-peer` en su servicio ([miembro ligero](../../member/README.md#install)).
- **El Wi-Fi de invitados o el aislamiento de clientes** del router impide que los dispositivos hablen entre sí; ponlos en la red principal.
- **Otro grupo.** `cbb status` muestra el grupo; los dispositivos de dos grupos nunca se sincronizan. Para pasar un ordenador al grupo correcto, ejecuta `sudo cbb leave` en él, luego emparéjalo con el grupo correcto y quítalo del equivocado desde ese grupo.
- **Quitado del grupo.** `cbb status` lo dice, y sus miembros lo rechazan. Ejecuta `sudo cbb leave` en él (en las apps: Salir del grupo) y luego empareja de nuevo.

## El emparejamiento falla

- **"wrong code"**: cada ventana de emparejamiento admite tres intentos; ejecuta `cbb pair` de nuevo para obtener un código nuevo.
- **El teléfono no llega al ordenador tras escanear su código QR**: el teléfono y el ordenador deben estar en la misma red, y el puerto del ordenador debe estar abierto (arriba). En iOS, permite la red local para la app (Ajustes, Privacidad y seguridad, Red local).

## Sincronización fuera de casa

`cbb global` en el dispositivo y en el hub dice qué falla. Las causas habituales: el router no reenvía al hub el puerto UDP del hub, el cortafuegos del hub lo descarta, o la dirección dada a `cbb global hub` no es la que alcanza internet. Un dispositivo que no ha encontrado al hub en casa desde que se activó la sincronización fuera de casa, o desde que el hub cambió sus ajustes (`-obfuscate`, `-vless`), no sabe cómo llegar a él: llévalo a casa una vez. Una red que bloquea las VPN necesita [AmneziaWG o VLESS](blocked-networks.md). Con `CBB_DEBUG=1` en el entorno del servicio, el registro muestra también los saludos de WireGuard. En Linux:

```sh
sudo systemctl edit cbb     # add the two lines below, save
# [Service]
# Environment=CBB_DEBUG=1
sudo systemctl restart cbb
```

## Android

- **El servicio de accesibilidad no se puede activar** («ajuste restringido»): en Android 13 y posterior, abre la Información de la app, ⋮, «Permitir ajustes restringidos», y luego actívalo.
- **Dejan de llegar las copias de los ordenadores**: puede que un ahorrador de batería haya detenido el servicio en primer plano; deja que la app se ejecute sin restricciones en sus ajustes de batería.

## Sigue sin funcionar

Abre una [incidencia](https://github.com/HunterEwok/cbb/issues) con la salida de `CBB_DEBUG=1 cbb status`, la parte relevante del registro y los sistemas implicados. Quita todo lo privado que hayas copiado. Los problemas de seguridad van a [SECURITY.md](../../SECURITY.md).
