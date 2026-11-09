# Getting help

Copy Beyond Borders is developed by one maintainer, in the open, without paid support.

## Look first

- The [quick start](docs/guide/quickstart.md) and the [guide](docs/README.md) answer most
  questions about installing, pairing and using CBB.
- [Troubleshooting](docs/guide/troubleshooting.md) covers the logs, the firewall, pairing
  and networks that block CBB.
- `cbb status` on a computer shows the state of its service and its group.
- Search the [issues](https://github.com/HunterEwok/cbb/issues?q=is%3Aissue), open and closed:
  someone may have asked already.

## Ask

| You have | Go to |
|---|---|
| A question, or an idea | an issue with the **Feature request** form |
| A bug | an issue with the **Bug report** form, with the version and the steps |
| A security problem | a private report, never a public issue: see [SECURITY.md](SECURITY.md) |
| A use the AGPL does not allow | an issue with the **Commercial license** form |

Answers come when the maintainer has time; there is no promised response time, except for
security reports, whose times SECURITY.md gives.

## If the maintainer is gone

Your group needs nothing from the project to keep working: at home the devices talk
directly, and away from home they use your own hub. The project's servers at `cbb.tools`
(the forwarder, the relay, the update mirror) are a convenience. If they go away, run your
own: the forwarder `cbb-forward` and the relay `cbb-relay` on any server with a public address, as
[running your own servers](docs/admin/self-hosting.md) shows. The code is under the AGPL and
the [protocol](docs/protocol.md) under CC BY 4.0, so anyone may carry the project on, build
the programs and sign their own releases.
