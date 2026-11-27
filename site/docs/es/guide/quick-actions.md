<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- source: 2424dc0d0064 -->
# Acciones rápidas

Para cualquiera que quiera bloquear, suspender, reiniciar, apagar o ejecutar un programa fijo en un ordenador desde un teléfono administrador u otro ordenador administrador del grupo.

Un **administrador** ejecuta una acción rápida con un toque o un comando, y el ordenador de destino solo la ejecuta si el propio usuario de ese ordenador activó esa acción localmente. Todas las acciones rápidas empiezan desactivadas por defecto, y nadie puede activar una acción a distancia.

## Acciones integradas

| Acción | Qué hace | Dispositivos compatibles |
|---|---|---|
| `lock` | Bloquea la pantalla | Ordenadores, dispositivos pequeños |
| `sleep` | Pone el ordenador en reposo | Ordenadores, dispositivos pequeños |
| `reboot` | Reinicia el ordenador tras un aviso de 1 minuto | Ordenadores, dispositivos pequeños |
| `shutdown` | Apaga el ordenador tras un aviso de 1 minuto | Ordenadores, dispositivos pequeños |
| `cancel-shutdown` | Cancela un reinicio o apagado pendiente | Ordenadores, dispositivos pequeños |
| `restart` | Reinicia el servicio de Connect Beyond Borders | Ordenadores, dispositivos pequeños |
| `keyboard-layout` | Cambia la distribución activa del [teclado Bluetooth](keyboards-and-tvs.md) del ordenador a la siguiente distribución | Ordenadores Linux con el teclado Bluetooth activado |

Una espera de 1 minuto antes de `reboot` o `shutdown` da a quien esté ante el ordenador tiempo para guardar su trabajo o ejecutar `cancel-shutdown`. En Windows, los usuarios con sesión iniciada también ven un aviso del sistema.

En macOS y Windows, las acciones de sesión (`lock`, `sleep` y las acciones propias) se ejecutan mediante el agente del portapapeles del usuario con sesión iniciada, así que alguien debe tener la sesión abierta. En macOS, `lock` requiere que **Ajustes del Sistema > Pantalla de bloqueo > Solicitar contraseña tras iniciarse el salvapantallas o apagarse la pantalla** esté configurado en **Inmediatamente**.

## 1. Activa una acción integrada

Ejecuta estos comandos en el ordenador de destino (usa `sudo` en Linux, macOS y FreeBSD; usa una terminal de administrador sin `sudo` en Windows):

1. Lista todas las acciones y comprueba quién tiene permiso para ejecutar cada una:

   ```sh
   cbb action
   ```

2. Activa una acción:

   ```sh
   sudo cbb action enable lock
   ```

   Lee lo que permite la acción y escribe `yes` (o pasa `-yes` en scripts).

   **Resultado:** La acción se activa para todos los administradores de tu grupo. En Linux, Connect Beyond Borders escribe `/etc/polkit-1/rules.d/60-cbb.rules`, otorgando al servicio solo los permisos de polkit necesarios para las acciones activadas.

3. Opcionalmente, restringe qué administradores pueden ejecutar una acción:
   - Limita por tipo de firmante con `-by` (`root` para el dispositivo principal, `phone` para teléfonos administradores, `computer` para ordenadores administradores, `watch` para un reloj firmante):

     ```sh
     sudo cbb action enable reboot -by root,phone
     ```

   - Por defecto, `reboot` y `shutdown` solo aceptan administradores cuyas claves vivan en hardware (un teléfono, un Mac con Secure Enclave o un PC con TPM 2.0). Para permitir también administradores con claves en archivos, añade `-any-key`:

     ```sh
     sudo cbb action enable reboot -any-key
     ```

Para volver a desactivar una acción:

```sh
sudo cbb action disable lock
```

**Resultado:** La acción se desactiva de inmediato. En Linux, desactivarla actualiza o elimina la regla de polkit para revocar los permisos que ya no se usan.

## 2. Añade una acción propia

Puedes definir hasta 32 acciones personalizadas por ordenador (los nombres deben tener de 1 a 32 letras minúsculas, dígitos o guiones, empezando por una letra).

1. Registra el comando en el ordenador de destino, indicando el programa con su ruta completa después de `--`:

   ```sh
   sudo cbb action add backup -by phone -- /usr/local/bin/backup.sh --quick
   ```

2. Lee el resumen de lo que permite la acción y escribe `yes`.

**Resultado:** Connect Beyond Borders guarda el comando en tus ajustes de usuario (`own-actions.json`) para que solo el agente del usuario con sesión iniciada pueda ejecutar exactamente ese ejecutable y esa lista de argumentos sin shell. El remitente recibe solo el código de salida. Los comandos deben terminar en un plazo de 15 segundos; inicia las tareas más largas en segundo plano.

Para quitar una acción personalizada:

```sh
sudo cbb action remove backup
```

## 3. Ejecuta una acción desde un administrador

- **Desde un ordenador administrador (terminal):**

  ```sh
  cbb action -on DEVICE NAME
  ```

  Sustituye `DEVICE` por el nombre del destino o su ID de dispositivo según `cbb status`, y `NAME` por el nombre de la acción.

  **Resultado:** `cbb` imprime si la acción se ejecutó o por qué la rechazó el destino.

- **Desde un teléfono administrador:**
  1. Abre **CBB** y toca en **Inicio** el ordenador de destino que esté en línea.
  2. En **Acciones rápidas**, toca la acción que quieras ejecutar.
  3. Confirma con tu cara, huella, código o (en Aurora OS) tu PIN de administrador. `reboot` y `shutdown` piden una segunda confirmación.

  **Resultado:** El destino ejecuta la acción y el teléfono muestra **Hecho.**

## 4. Desactiva todas las acciones

- **Localmente en el ordenador de destino:**

  ```sh
  sudo cbb action off
  ```

- **A distancia desde cualquier ordenador administrador:**

  ```sh
  sudo cbb action off -on DEVICE     # one computer
  sudo cbb action off -all           # every computer in the group
  ```

- **A distancia desde un teléfono administrador:** Abre la página del dispositivo en **Inicio** y toca **Desactivar todo**.

**Resultado:** Todas las acciones rápidas de los ordenadores afectados se desactivan de inmediato. Solo el propio usuario de cada ordenador puede volver a activarlas localmente.

Cada ordenador de destino guarda un registro de auditoría (`actions-log.json`) de las últimas 100 solicitudes de acciones, registrando quién pidió cada acción y cuándo. Para consultar los límites exactos, consulta [Límites y duraciones](../reference/limits.md#remote-paste-and-quick-actions).
