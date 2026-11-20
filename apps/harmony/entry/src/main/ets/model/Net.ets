// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The home network as the other phones' apps see it: which addresses are
// on it, and this phone's own for the QR code.

import { connection } from '@kit.NetworkKit';
import { socket } from '@kit.NetworkKit';
import { Errors } from '../core/Errors';

// The member port, which the QR code names.
export const MEMBER_PORT: number = 8764;

// Whether an address is on the home network, as mDNS would publish it:
// private IPv4, unique-local IPv6, or link-local.
export function isHome(address: string): boolean {
  const a = address.toLowerCase();
  if (a.includes(':')) {
    const mapped = a.startsWith('::ffff:') ? a.substring(7) : '';
    if (mapped.length > 0 && !mapped.includes(':')) {
      return isHome(mapped);
    }
    return a.startsWith('fc') || a.startsWith('fd') || a.startsWith('fe8') || a.startsWith('fe9') ||
      a.startsWith('fea') || a.startsWith('feb');
  }
  const p = a.split('.').map((s: string) => Number.parseInt(s, 10));
  if (p.length !== 4 || p.some((n: number) => Number.isNaN(n))) {
    return false;
  }
  return p[0] === 10 || (p[0] === 172 && p[1] >= 16 && p[1] < 32) || (p[0] === 192 && p[1] === 168) ||
    (p[0] === 169 && p[1] === 254);
}

// This phone's private IPv4 addresses with the member port, at most four,
// for the QR code.
export function qrAddresses(): string[] {
  const out: string[] = [];
  try {
    for (const net of connection.getAllNetsSync()) {
      const props = connection.getConnectionPropertiesSync(net);
      for (const link of props.linkAddresses) {
        const ip = link.address.address;
        if (ip.includes(':') || !isHome(ip) || ip.startsWith('169.254.') || out.includes(`${ip}:${MEMBER_PORT}`)) {
          continue;
        }
        out.push(`${ip}:${MEMBER_PORT}`);
        if (out.length === 4) {
          return out;
        }
      }
    }
  } catch (e) {
    Errors.log(`net: the phone's addresses: ${String(e)}`);
  }
  return out;
}

// An "ip:port" or "[ip6]:port" address as the system's address.
export function netAddress(hostPort: string): socket.NetAddress | undefined {
  let host = '';
  let port = '';
  if (hostPort.startsWith('[')) {
    const end = hostPort.indexOf(']');
    if (end < 0) {
      return undefined;
    }
    host = hostPort.substring(1, end);
    port = hostPort.substring(end + 2);
  } else {
    const colon = hostPort.lastIndexOf(':');
    if (colon < 0) {
      return undefined;
    }
    host = hostPort.substring(0, colon);
    port = hostPort.substring(colon + 1);
  }
  const n = Number.parseInt(port, 10);
  if (host.length === 0 || Number.isNaN(n) || n <= 0 || n > 65535) {
    return undefined;
  }
  const address: socket.NetAddress = { address: host, port: n, family: host.includes(':') ? 2 : 1 };
  return address;
}

// A TCP connection the app dials: the bytes it gets go to onData, its end to
// onClose, once.
export class Dialed {
  private conn: socket.TCPSocket = socket.constructTCPSocketInstance();
  private closed: boolean = false;
  onData: (data: ArrayBuffer) => void = () => {};
  onClose: (why: string) => void = () => {};

  async dial(address: socket.NetAddress, timeoutMs: number): Promise<void> {
    const local: socket.NetAddress = { address: address.family === 2 ? '::' : '0.0.0.0', port: 0, family: address.family };
    await this.conn.bind(local);
    this.conn.on('message', (m: socket.SocketMessageInfo) => {
      this.onData(m.message);
    });
    this.conn.on('close', () => {
      this.end('closed');
    });
    this.conn.on('error', (e: Error) => {
      this.end(String(e.message));
    });
    const options: socket.TCPConnectOptions = { address: address, timeout: timeoutMs };
    await this.conn.connect(options);
  }

  send(data: ArrayBuffer): void {
    if (this.closed || data.byteLength === 0) {
      return;
    }
    const options: socket.TCPSendOptions = { data: data };
    this.conn.send(options).catch((e: Error) => {
      this.end(`send: ${e.message}`);
    });
  }

  close(): void {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.conn.close().catch(() => {});
  }

  private end(why: string): void {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.conn.close().catch(() => {});
    this.onClose(why);
  }
}
