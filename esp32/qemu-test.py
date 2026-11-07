#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

"""Drives the QEMU test build's console over UART0, as qemu-test.sh asks:
boots the flash image three times and checks that the settings typed in
one boot are there in the next, and that the self-test passes.

    qemu-test.py QEMU FLASH_IMAGE WORK_DIR
"""

import os
import socket
import subprocess
import sys
import time

QEMU, FLASH, WORK = sys.argv[1:4]
TIMEOUT = float(os.environ.get("TIMEOUT", "300"))
# How long a line may wait for its first echo before it is sent again, and
# how many times it is sent.
ECHO_WAIT = float(os.environ.get("ECHO_WAIT", "20"))
SENDS = 3
PROMPT = b"cbb> "
transcript = []


class Board:
    def __init__(self, n):
        self.sock = os.path.join(WORK, f"uart{n}.sock")
        self.log = open(os.path.join(WORK, f"qemu{n}.log"), "wb")
        self.qemu = subprocess.Popen(
            [QEMU, "-nographic", "-machine", "esp32s3",
             "-drive", f"file={FLASH},if=mtd,format=raw",
             "-chardev", f"socket,id=uart,path={self.sock},server=on,wait=on",
             "-serial", "chardev:uart", "-monitor", "none"],
            stdin=subprocess.DEVNULL, stdout=self.log, stderr=subprocess.STDOUT)
        deadline = time.time() + 30
        while not os.path.exists(self.sock):
            if time.time() > deadline or self.qemu.poll() is not None:
                fail("QEMU did not start")
            time.sleep(0.1)
        self.uart = socket.socket(socket.AF_UNIX)
        self.uart.connect(self.sock)
        self.uart.settimeout(0.5)
        self.out = b""
        self.expect(PROMPT)

    def expect(self, want, timeout=TIMEOUT):
        """Reads until want, and then the next prompt, have come."""
        deadline = time.time() + timeout
        while want not in self.out or not self.out.rstrip().endswith(PROMPT.rstrip()):
            if b"PANIC" in self.out:
                fail("the firmware panicked")
            if time.time() > deadline:
                fail(f"no {want!r}")
            try:
                data = self.uart.recv(4096)
            except socket.timeout:
                continue
            if not data:
                fail("QEMU closed the UART")
            self.out += data
        transcript.append(self.out.decode(errors="replace"))
        self.out = b""

    def send(self, line):
        """Sends a line, and sends it again while the board answers
        nothing at all: right after a boot, QEMU's UART has been seen to
        drop what came before the firmware read it, though the prompt was
        out. A board that hangs answers none of the copies either, and a
        line it began to echo is never sent twice."""
        data = line.encode() + b"\r"
        for attempt in range(SENDS):
            self.uart.sendall(data)
            deadline = time.time() + ECHO_WAIT
            while not self.out and time.time() < deadline:
                try:
                    got = self.uart.recv(4096)
                except socket.timeout:
                    continue
                if not got:
                    fail("QEMU closed the UART")
                self.out += got
            if self.out:
                return
            note = f"no echo of {line!r} in {ECHO_WAIT:.0f} s; sending it again"
            transcript.append(f"({note})")
            # Loud on purpose: a line the board dropped must not pass unseen.
            # GitHub shows ::warning:: on the job and the pull request.
            print(f"::warning title=qemu-test::{note}", file=sys.stderr, flush=True)
        fail(f"no echo of {line!r}")

    def type(self, line, want, timeout=TIMEOUT):
        self.send(line)
        self.expect(want.encode(), timeout)

    def answer(self, line, question):
        """Types a line that the board answers with another question."""
        self.send(line)
        deadline = time.time() + TIMEOUT
        while question.encode() not in self.out:
            if time.time() > deadline:
                fail(f"no {question!r}")
            try:
                self.out += self.uart.recv(4096)
            except socket.timeout:
                pass

    def stop(self):
        self.qemu.kill()
        self.qemu.wait()
        self.uart.close()
        os.remove(self.sock)


def fail(why):
    sys.stdout.write("\n".join(transcript))
    sys.exit(f"qemu-test: {why}")


b = Board(1)
b.type("status", "group: none, type pair")
b.type("pair", "the QEMU build has no network to join a group over")
b.answer("wifi", "Wi-Fi network name: ")
b.answer("Test Net", "Password (empty for an open network): ")
b.type("password1", "Saved. Joining Test Net.")
b.type("debug on", "Error details are on.")
b.type("selftest", "self-test passed")
b.type("layout ru", "The keyboard types for the layout ru now")
# "Wi-Fi: dom" (house), and "Privet, mir!" (hello, world) in Cyrillic.
b.type("type Wi-Fi: \u0434\u043e\u043c", "The layout ru has no keys for: WiF")
b.type("type \u041f\u0440\u0438\u0432\u0435\u0442, \u043c\u0438\u0440!", "the QEMU build has no keyboard")
b.type("ble pair", "the QEMU build has no Bluetooth")
b.type("rate 30", "The keyboard types 30 characters a second now.")
b.type("rate 100", "A rate is 5 to 60 characters a second.")
b.stop()

# The settings stay in flash across a restart.
b = Board(2)
b.type("status", "Wi-Fi network: Test Net")
assert "error details: on" in transcript[-1], "debug mode was not kept"
assert "USB port: console; layout ru, 30 characters a second" in transcript[-1], "the keyboard's settings were not kept"
assert "Bluetooth keyboard: not in the QEMU build; paired with 0 host(s)" in transcript[-1], "status lacks the Bluetooth keyboard"
b.type("wifi forget", "Forgot the Wi-Fi network.")
b.stop()

b = Board(3)
b.type("status", "Wi-Fi network: none set")
b.stop()

sys.stdout.write("\n".join(transcript))
print("\nqemu-test: passed")
