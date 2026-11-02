<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: ce6e8f0e4357 -->
# Acciones rápidas

Para quien quiere bloquear, suspender o reiniciar un ordenador desde un teléfono u otro ordenador del grupo. Un administrador ejecuta la acción con una pulsación o un comando; el dispositivo solo la ejecuta si su propio usuario activó esa acción allí.

## Las acciones

| Acción | Qué hace | Dónde |
|---|---|---|
| `lock` | bloquea la pantalla | ordenadores |
| `sleep` | suspende el ordenador | ordenadores |
| `reboot` | reinicia el ordenador un minuto después | ordenadores, el miembro ligero |
| `shutdown` | apaga el ordenador un minuto después | ordenadores |
| `cancel-shutdown` | cancela un reinicio o apagado pendiente | ordenadores, el miembro ligero |
| `restart` | reinicia el servicio de Clipboard Bridge | ordenadores, el miembro ligero |
| `keyboard-layout` | cambia la distribución en la que escribe su [teclado Bluetooth](keyboards-and-tvs.md) a la siguiente, después de que cambies la del propio dispositivo | ordenadores Linux con el teclado activado |
| la tuya | ejecuta un programa que tú elijas, como el usuario con sesión iniciada | ordenadores |

Un minuto de aviso antes de un reinicio o un apagado da a quien esté ante el ordenador tiempo para guardar su trabajo o ejecutar `cancel-shutdown`. Windows además avisa a los usuarios con sesión iniciada.

## Activa una acción

En el dispositivo, como administrador (`sudo` en Linux, macOS y FreeBSD):

```sh
cbb action                     # lists the actions and who may run each
sudo cbb action enable lock    # says what it allows and asks you to type yes
sudo cbb action enable reboot -by root,phone
sudo cbb action disable lock
```

`-by` limita quién puede ejecutarla: `root`, `phone` (teléfonos administradores), `computer` (ordenadores administradores), `watch` (un reloj con una clave de administrador). Sin él, puede cualquier administrador. `reboot` y `shutdown` solo aceptan administradores cuyas claves estén en hardware, un teléfono o un ordenador con TPM, a menos que añadas `-any-key`.

En Linux, activar escribe la regla de polkit que da al servicio exactamente los derechos que necesitan las acciones activadas, y desactivar los retira.

## Una acción propia

```sh
sudo cbb action add backup -by phone -- /usr/local/bin/backup.sh --quick
sudo cbb action remove backup
```

El agente del usuario con sesión iniciada ejecuta el programa por su ruta completa, exactamente con esos argumentos y sin shell. El remitente recibe solo su código de salida. Debe terminar en 15 segundos; lo que dure más, ponlo en segundo plano.

## Ejecuta una acción

En un ordenador administrador: `cbb action -on DEVICE NAME`, que dice si se ejecutó o por qué no.

En un teléfono administrador, abre la página del dispositivo mientras está en línea y pulsa la acción en «Quick actions»; Face ID o la huella la confirma, y reiniciar y apagar piden una confirmación más. Un reloj administrador puede ejecutar las acciones permitidas para `watch`.

## Desactívalas todas

`sudo cbb action off` en el dispositivo desactiva allí todas las acciones. Desde un administrador, `cbb action off -on DEVICE` o `-all` lo hace en otro dispositivo o en todos, y «Turn all off» en un teléfono hace lo mismo; solo el usuario de cada dispositivo vuelve a activarlas.

Cada dispositivo guarda un registro de las últimas 100 acciones que se le pidió ejecutar, con quién las pidió y cuándo.
