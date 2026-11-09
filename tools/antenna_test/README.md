# Antenna test

Scores how well a radio's antenna reaches the repeaters around it, so two antennas (or two mounting spots) can be
compared with one number.

1. **Discovery, 10 minutes.** A zero-hop repeater discovery goes out every minute. Every repeater that answers is
   added to the list.
2. **Traces, 20 rounds, 10 s apart.** Each round traces every listed repeater once, one at a time (the next trace
   goes out when the last one comes back or after 5 s). Each trace that comes back scores 0.05, so a repeater
   scores between 0.0 and 1.0.
3. **Final score** = the sum of the repeater scores. Two repeaters that always answered score 2.0; five that
   answered half the time score 2.5.

The web page has a **Start** button, a console with what is happening, and a table of the repeaters that answered at
least one trace:

| Column | Meaning |
| --- | --- |
| Avg TX SNR | how well the repeater heard us (the SNR it adds to the trace) |
| Avg RX SNR | how well we heard the repeater's reply |
| Success rate | traces that came back / traces sent |
| Score | 0.05 per trace that came back |

Each run's results are also saved as JSON in `tools/antenna_test/results/`.

## Running it

The tool opens the KISS modem itself, so stop the room first if it uses the same radio (only one program can have
the serial port open):

```sh
sudo systemctl stop meshroom          # or scripts/stop-pymeshroom.sh
.venv/bin/python tools/antenna_test/antenna_test.py      # or python3, with pyserial and cryptography installed
```

Then open `http://localhost:8095/` on the Pi (or through an SSH tunnel: `ssh -L 8095:localhost:8095 pi@<pi address>`, then the same address on your computer) and press **Start**. To open it from another machine directly, add `--host 0.0.0.0`: anyone on the network can then start a test. Start the room again when you are done.

By default the serial port and radio settings (frequency, bandwidth, SF, CR, TX power) come from the room's
`meshroom/meshroom.json`. Any of them can be overridden:

```sh
python3 tools/antenna_test/antenna_test.py --serial /dev/ttyUSB0 --freq 910.525 --bw 62.5 --sf 7 --cr 5 --tx-power 22
```

Other options: `--port` (web UI, default 8095), `--host` (default `127.0.0.1`, this machine only: the UI has no login and makes the radio transmit; `0.0.0.0` to reach it from the network), `--discover-minutes` (10),
`--rounds` (20), `--interval` (10 s between rounds), `--trace-timeout` (5 s), `--results-dir`.

The web page has no password: anyone who can reach the port can start a test.
