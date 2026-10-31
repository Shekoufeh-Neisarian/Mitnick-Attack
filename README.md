# Mitnick Attack

**Project by Shekoufeh Neisarian · 31 October 2026**

This repository documents a controlled reproduction of the classic Mitnick TCP spoofing attack, using the SEED Labs Docker environment. It is designed as a practical learning reference: the commands, observed packet behavior, screenshots, errors, and fixes are explained in the accompanying report.

[**Read the complete illustrated report (PDF)**](Mitnick_Attack_Project_Report.pdf)

## What was demonstrated?

The target X-Terminal used legacy `rsh` authentication based on a trusted host listed in `.rhosts`. The test demonstrated that an attacker in the **isolated** network could forge the trusted source address, establish the two TCP connections required by `rsh`, execute a harmless marker-file command, and demonstrate the danger of an unrestricted trusted-host configuration. The original `.rhosts` file was restored and the containers were shut down after the exercise.

| Test | Observed outcome |
|---|---|
| Legitimate trusted-host access | `rsh 10.9.0.5 date` ran without a password. |
| Simulated trusted-host silencing | Trusted-server container stopped; X-Terminal retained a static ARP entry. |
| First TCP handshake (port 514) | Spoofed SYN, server SYN-ACK, and final ACK seen in Wireshark. |
| RSH application request | Wireshark decoded the remote-shell request and its fields. |
| Second TCP handshake (port 9090) | SYN, spoofed SYN-ACK, and ACK observed. |
| Harmless command execution | `/tmp/xyz` appeared on X-Terminal, owned by `seed`. |
| Trust configuration weakness | `.rhosts` became `+ +`; a subsequent `rsh ... id` worked without a password. |
| Cleanup | Original `.rhosts` was restored; the Docker environment was shut down. |

> **Important distinction:** The SEED exercise models the historical attack. Instead of sending an actual SYN flood, we stopped the trusted-server container. Instead of predicting a modern randomized TCP initial sequence number, our Scapy scripts observed the server's ISN. The TCP acknowledgment was then calculated as `(ISN + 1) mod 2^32`. These are not equivalent to successful blind ISN prediction [1].

## Prerequisites

- A Linux VM with `sudo` (Kali was used for this run).
- Docker Engine and Docker Compose.
- Wireshark, Python 3, and the Scapy-based utilities supplied in or used with the training environment.
- Official SEED Mitnick Attack `Labsetup.zip` and its `docker-compose.yml` [1].
- A **contained and authorized** network: do not attach the vulnerable services to a production or public network.

## Environment used

| Component | Address / value |
|---|---|
| Kali VM main interface | `eth0`, `10.10.10.129/24` |
| Docker bridge | `br-6514365f0955`, `10.9.0.1/24` |
| Target X-Terminal | `10.9.0.5`, remote shell TCP `514` |
| Trusted server | `10.9.0.6` |
| Attacker | `seed-attacker` container (host networking in this configuration) |
| Secondary RSH connection | Destination port `9090` |

Docker-generated bridge interface names may differ between installations.

## Project walkthrough

**1. Prepare Docker.** On Kali, install the Docker packages and enable the daemon:

```bash
sudo apt update
sudo apt install -y docker.io docker-compose unzip curl
sudo systemctl enable --now docker
docker --version
docker compose version
```

**2. Extract and launch the official environment.** Download `Labsetup.zip` from the official SEED lab page, extract it into a local (non-shared) directory, then run from the directory containing `docker-compose.yml`:

```bash
cd ~/Labsetup
sudo docker compose config
sudo docker compose up -d --build
sudo docker compose ps
```

**3. Confirm baseline trust.** The target user's `.rhosts` was configured to trust `10.9.0.6`. A legitimate `rsh` request from the trusted-server container executed `date` without a password.

**4. Simulate silencing the trusted host.** The target learned the trusted server's MAC address, the ARP mapping was made static, and the trusted-server container was stopped. The complete report explains why a responding RST would otherwise disrupt spoofing.

**5. Inspect the TCP handshakes.** Wireshark on the Docker bridge showed the original spoofed SYN, the SYN-ACK, the final ACK, the RSH payload, and the secondary callback handshake. The complete report explains each TCP field and the important Python snippets.

**6. Verify harmless execution and trust weakness.** The target contained `/tmp/xyz` with a real timestamp. The final exercise demonstrated the impact of overly permissive `.rhosts` trust. All changes were limited to the SEED test containers.

**7. Restore and shut down.** Restore the original `.rhosts` content and ownership, preserve captures as evidence, and run:

```bash
cd ~/Labsetup
sudo docker compose down
```

The report includes intermediate screenshots, failed attempts, and troubleshooting, including name resolution after stopping the trusted-server container, ARP cache persistence, missing RSH payload data, and second-channel connection behavior.

## What the results teach

- **IP addresses alone are not credentials.** Legacy trust mechanisms can be defeated when the network identity is forged.
- **TCP transport and application authentication are different.** A successful handshake does not automatically mean a remote command will run.
- **The `rsh` error channel matters.** The second TCP connection had to complete before the marker-file command executed.
- **Packet sequence-number prediction is not ACK arithmetic.** The experiment observed the randomized ISN and computed the acknowledgment from it.
- **Avoid `.rhosts` trust in real systems.** Replace `rsh`/`rlogin` with SSH and cryptographic authentication; restrict ingress and monitor for unexpected legacy service use.

## Repository files

- `README.md` — This short project overview and reproduction guide.
- `Mitnick_Attack_Project_Report.pdf` — Illustrated, step-by-step report with screenshots and code explanations.

The original `Labsetup.zip`, Docker images, container data, personal files, and any authentication material should **not** be committed to this repository. The original Scapy files are on the Kali VM; review them and remove environment-specific or sensitive information before deciding whether to publish them.

## References

[1] W. Du, *The Mitnick Attack Lab*, SEED Labs. https://seedsecuritylabs.org/Labs_20.04/Files/Mitnick_Attack/Mitnick_Attack.pdf

[2] SEED Labs, *SEED Manual for Containers*. https://github.com/seed-labs/seed-labs/blob/master/manuals/docker/SEEDManual-Container.md

[3] IETF, *RFC 9293: Transmission Control Protocol (TCP)*. https://www.rfc-editor.org/rfc/rfc9293
