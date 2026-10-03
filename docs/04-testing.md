# 04. Testing

Phone systems fail in ways that are hard to reproduce: a phone does something
weird at the wrong moment, a call dies and the trace is gone. The test strategy
is built around one idea: **every failure must be reproducible from a fixed
seed.**

## 1. Layers

| Layer | What it covers |
| --- | --- |
| Unit tests | Pure functions: SIP parsing, routing rule matching, call state transitions |
| Simulation tests (`engine-sim`) | Whole calls driven through a deterministic test bed — the main test surface |
| Real-phone smoke tests | A handful of manual (later scripted) runs against actual softphones |
| Fuzzing | The SIP parser must survive arbitrary garbage input |

## 2. The simulation test bed (`engine-sim`)

A slim **deterministic simulation**: no real sockets, no real clock, no real
sleeping.

- **Virtual clock.** Time only moves when the test says so (`advance(20 ms)`).
  Nothing depends on wall-clock time, so no flaky timing tests.
- **Event queue.** Everything — incoming SIP messages, timers, RTP packets —
  is an event in one queue, processed one at a time in a defined order.
- **Fake phones.** Small in-process SIP endpoints: a phone that registers and
  answers, a phone that rejects, a phone that hangs up at the wrong moment.
  They speak real SIP messages; only the transport is virtual.
- **Fixed seed.** Any randomness (e.g. simulated packet loss) comes from a
  seeded generator. Same seed ⇒ same run.

**What we deliberately do NOT simulate:** fax machines, modems, analog
gateways, or a full network-loss model. Those features are deferred, and
simulating hardware we haven't chosen would be guesswork.

**Determinism assertion:** a test run produces an event trace (who sent what,
when, in which order). Running the same scenario with the same seed must
produce the *identical trace*. This catches "works usually, fails sometimes"
bugs at the source: nondeterminism.

## 3. What the simulation suite must prove (first milestone)

Adapted from the original M0 acceptance list, trimmed to what calls need:

1. **Registration** — two phones register; a wrong password is rejected.
2. **Basic call** — Alice calls Bob, Bob's phone rings, answering connects both
   directions of audio; the call shows as active.
3. **Audio** — a 60-second call carries G.711 packets both ways with zero loss
   and zero reordering on a clean path.
4. **Teardown** — Alice hangs up: Bob is told, audio stops, resources are
   released (no leaks), one line lands in the call log.
5. **Concurrency** — 20 registered phones, 10 simultaneous calls, all healthy;
   the process stays responsive.
6. **Robustness** — garbage SIP input (broken headers, huge bodies, partial
   messages) is rejected cleanly and never panics.
7. **Determinism** — the same seed produces the identical event trace and call
   log, byte for byte.

## 4. Real phones

The simulation bed proves *our* logic; real phones prove the *world*. Roadmap
step 2 is deliberately "run it against actual softphones and fix what breaks" —
a test bed we wrote ourselves can only tell us we implemented our own
assumptions.

## 5. Fuzzing

The SIP parser (`sip-syntax`) is the attack surface and the panic risk. It gets
a fuzz target run in CI for a short time on every change, longer runs weekly.
Findings are frozen into fixed test cases.

## 6. CI

On every change: format check, lint, unit tests, simulation tests (fixed
seeds), parser fuzz smoke. Nothing exotic. The simulation suite is fast enough
to run fully on every push — that is the point of a virtual clock.
