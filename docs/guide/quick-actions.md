<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Quick actions

For anyone who wants to lock, sleep, restart, shut down, or run a fixed program on a computer from
an admin phone or another admin computer in the group.

An **admin** runs a quick action with one tap or one command, and the target computer runs it only
if that computer's own user turned that action on locally. Every quick action starts off by
default, and nobody can turn an action on remotely.

## Built-in actions

| Action | What it does | Supported devices |
|---|---|---|
| `lock` | Locks the screen | Computers, small devices |
| `sleep` | Puts the computer to sleep | Computers, small devices |
| `reboot` | Restarts the computer after a 1-minute warning | Computers, small devices |
| `shutdown` | Shuts the computer down after a 1-minute warning | Computers, small devices |
| `cancel-shutdown` | Cancels a pending reboot or shutdown | Computers, small devices |
| `restart` | Restarts the Connect Beyond Borders service | Computers, small devices |
| `keyboard-layout` | Switches the active layout of the computer's [Bluetooth keyboard](keyboards-and-tvs.md) to the next layout | Linux computers with the Bluetooth keyboard on |

A 1-minute delay before `reboot` or `shutdown` gives anyone at the computer time to save work or
run `cancel-shutdown`. On Windows, signed-in users also see a system warning.

On macOS and Windows, session actions (`lock`, `sleep`, and custom actions) run through the
signed-in user's clipboard agent, so someone must be signed in. On macOS, `lock` requires
**System Settings > Lock Screen > Require password after screen saver begins or display is turned
off** to be set to **Immediately**.

## 1. Turn a built-in action on

Run these commands on the target computer (use `sudo` on Linux, macOS, and FreeBSD; use an
administrator terminal without `sudo` on Windows):

1. List all actions and see who is allowed to run each one:

   ```sh
   cbb action
   ```

2. Enable an action:

   ```sh
   sudo cbb action enable lock
   ```

   Read what the action allows and type `yes` (or pass `-yes` in scripts).

   **Result:** The action turns on for every admin in your group. On Linux, Connect Beyond Borders
   writes `/etc/polkit-1/rules.d/60-cbb.rules` granting the service only the polkit rights needed
   for the enabled actions.

3. Optionally restrict which admins can run an action:
   - Limit by signer kind with `-by` (`root` for the main device, `phone` for admin phones,
     `computer` for admin computers, `watch` for a watch signer):

     ```sh
     sudo cbb action enable reboot -by root,phone
     ```

   - By default, `reboot` and `shutdown` accept only admins whose keys live in hardware (a phone,
     a Mac with Secure Enclave, or a PC with TPM 2.0). To allow admins with file keys too, add
     `-any-key`:

     ```sh
     sudo cbb action enable reboot -any-key
     ```

To turn one action off again:

```sh
sudo cbb action disable lock
```

**Result:** The action turns off immediately. On Linux, disabling updates or removes the polkit
rule so unused rights are revoked.

## 2. Add an action of your own

You can define up to 32 custom actions per computer (names must be 1 to 32 lowercase letters,
digits, or hyphens, starting with a letter).

1. Register the command on the target computer, giving the program by its full path after `--`:

   ```sh
   sudo cbb action add backup -by phone -- /usr/local/bin/backup.sh --quick
   ```

2. Read the summary of what the action allows and type `yes`.

**Result:** Connect Beyond Borders saves the command in your user settings (`own-actions.json`) so
only the signed-in user's agent can run that exact executable and argument list without a shell.
The sender receives only the exit status. Commands must finish within 15 seconds; start longer
jobs in the background.

To remove a custom action:

```sh
sudo cbb action remove backup
```

## 3. Run an action from an admin

- **From an admin computer (terminal):**

  ```sh
  cbb action -on DEVICE NAME
  ```

  Replace `DEVICE` with the target's name or device ID from `cbb status`, and `NAME` with the
  action name.

  **Result:** `cbb` prints whether the action ran or why the target refused it.

- **From an admin phone:**
  1. Open **CBB** and tap the online target computer on **Home**.
  2. Under **Quick actions**, tap the action you want to run.
  3. Confirm with your face, fingerprint, passcode, or (on Aurora OS) your admin PIN. `reboot`
     and `shutdown` ask for a second confirmation.

  **Result:** The target runs the action and the phone shows **Done.**

## 4. Turn all actions off

- **Locally on the target computer:**

  ```sh
  sudo cbb action off
  ```

- **Remotely from any admin computer:**

  ```sh
  sudo cbb action off -on DEVICE     # one computer
  sudo cbb action off -all           # every computer in the group
  ```

- **Remotely from an admin phone:** Open the device page on **Home** and tap **Turn all off**.

**Result:** Every quick action on the affected computers turns off immediately. Only each
computer's own user can turn them on again locally.

Each target computer keeps an audit log (`actions-log.json`) of the last 100 action requests,
recording who requested each action and when. For exact limits, see
[Limits and lifetimes](../reference/limits.md#remote-paste-and-quick-actions).
