<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Quick actions

For anyone who wants to lock, put to sleep or restart a computer from a phone or another
computer of the group. An admin runs the action with one tap or one command; the device runs
it only if its own user turned that action on there.

## The actions

| Action | What it does | Where |
|---|---|---|
| `lock` | locks the screen | computers, the lite member |
| `sleep` | puts the computer to sleep | computers, the lite member |
| `reboot` | restarts the computer a minute later | computers, the lite member |
| `shutdown` | shuts the computer down a minute later | computers, the lite member |
| `cancel-shutdown` | cancels a pending reboot or shutdown | computers, the lite member |
| `restart` | restarts the Copy Beyond Borders service | computers, the lite member |
| `keyboard-layout` | switches the layout its [Bluetooth keyboard](keyboards-and-tvs.md) types in to the next one, after you switch the device's own | Linux computers with the keyboard on |
| your own | runs a program you chose, as the user signed in | computers, the lite member with CBB's agent |

A minute's warning before a reboot or a shutdown gives anyone at the computer time to save
their work or run `cancel-shutdown`. Windows also warns the users signed in.

## Turn an action on

On the device, as administrator (`sudo` on Linux, macOS and FreeBSD):

```sh
cbb action                     # lists the actions and who may run each
sudo cbb action enable lock    # says what it allows and asks you to type yes
sudo cbb action enable reboot -by root,phone
sudo cbb action disable lock
```

`-by` limits who may run it: `root`, `phone` (admin phones), `computer` (admin computers),
`watch` (a watch with an admin key). Without it every admin may. `reboot` and `shutdown`
take only admins whose keys are in hardware, a phone or a computer with a TPM, unless you
add `-any-key`.

On Linux, enabling writes the polkit rule that gives the service exactly the rights the
actions that are on need, and disabling takes them back.

## An action of your own

```sh
sudo cbb action add backup -by phone -- /usr/local/bin/backup.sh --quick
sudo cbb action remove backup
```

The agent of the user signed in runs the program by its full path, with exactly these
arguments and no shell. The sender gets only its exit status. It must end within 15 seconds;
start anything longer in the background.

## Run an action

On an admin computer: `cbb action -on DEVICE NAME`, which says whether it ran or why not.

On an admin phone, open the device's page while it is online and tap the action under
"Quick actions"; Face ID or the fingerprint confirms it, and reboot and shut down ask once
more. An admin watch can run the actions allowed for `watch`.

## Turn them all off

`sudo cbb action off` on the device turns every action off there. From an admin,
`cbb action off -on DEVICE` or `-all` does it on another device or on every one, and "Turn
all off" on a phone does the same; only each device's own user turns them on again.

Each device keeps a log of the last 100 actions it was asked to run, with who asked and when.
