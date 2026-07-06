---
title: "FortiSwitch MCLAG Pair / FortiGate HA Cluster (FortiLink, FortiOS 7.6)"
date: 2026-07-06T00:00:00-05:00
draft: false
tags:
  - FortiSwitch
  - FortiGate
  - MCLAG
  - FortiLink
  - FortiOS 7.6
  - HA cluster
  - ICL
  - auto-ISL
  - FS-424E
  - FortiGate 121G
  - split-brain detection
  - OT segmentation
  - NERC CIP
  - networking
  - Fortinet
categories:
  - Networking
  - Fortinet
summary: "Standing up two FortiSwitches as an active-active MCLAG pair behind an HA FortiGate over FortiLink, including the firmware-skew and hidden mclag-icl CLI gotchas the official docs skip."
---

A field guide to standing up two FortiSwitches as an active-active MCLAG pair behind an HA FortiGate, with the gotchas the official docs gloss over.

## Why this writeup exists

This details the struggles I had creating an MCLAG pair under my HA FortiGate. As with everything I do, its a trial by fire learning experience, diving in head first. I started having trouble parsing the exact steps I needed to take setting up the MCLAG from online documentation, and had to revert a couple of times after coming to dead ends. The breakdown below is generated from my troubleshooting, note taking and AI conversations on the matter. 

I use Claude to work through things like this, keep track of my notes and generate a "lessons learned" after the fact. I find it extremely handy and efficient. This is by no means an answer to everyones problem, and there may be a different way to accomplish this setup, or even a better way. This is simply more information to place on the web to help someone along who may be stuck on any given point. From this point forward the post will read a little more like AI, because much of it is generated from the aformentioned note taking sesh... 

1. **Firmware skew silently breaks auto-ICL formation** even when everything looks healthy.
2. **Promoting the inter-switch link to an MCLAG-ICL is a switch-CLI step that the FortiGate deliberately hides**, and by the time you need it, getting onto the switch CLI is painful.

This is written from a real deployment: two FS-424E-Fiber switches under a FortiGate 121G HA pair (a-p) on FortiOS 7.6.6, building an OT segmentation boundary.

## The mental model (read this first)

FortiLink MCLAG is not traditional switch stacking. There are no stack cables, no stack master election among the switches, and you do not hand-build LACP uplinks the old way. Instead:

- The **FortiGate is the control plane.** It manages both switches over FortiLink.
- The **two switches are active-active peers.** Both forward traffic simultaneously. There is no standby switch.
- The **ICL (inter-chassis link)** is the peer link between the two switches. It carries sync and failover traffic, not bulk data.
- **Downstream MCLAG trunks** are the dual-homed LAGs to hosts, one leg to each switch.

Active-active is the goal and the default. The only place active/standby language appears is split-brain handling, which is a failure-mode protection, not the normal operating mode.

### ICL bandwidth reality

The ICL does not need to be your fastest ports. In steady state with everything dual-homed, very little traffic crosses it. A 2-port LAG is recommended for redundancy, but it can be 1G ports on an OT segment without issue. Do not burn your only 10G ports on the ICL if you need them for uplinks. (In the reference deployment the SFP+ ports were used for both uplinks and ICL because 10G was only needed at the head end, which is a valid choice when you have the port budget.)

## The single biggest gotcha: do your switch-side config BEFORE adoption

Here is the lesson that will save you the most pain.

Once a FortiSwitch is FortiLink-managed:

- It does **not** inherit your FortiGate admin credentials.
- The FortiLink interface will **not** accept `https` or `ssh` in `allowaccess` (only `fabric` and `ping` are permitted), so the FortiGate proxy-SSH (`execute switch-controller ssh`) frequently fails with "not FortiLink HTTPS managed."
- Several switch-global settings you need (`mclag-stp-aware`, `auto-network`, and the `mclag-icl` trunk flag) are **not exposed** through the FortiGate's managed-switch object. They only exist on the switch's own CLI.

The combination means that after adoption, you can find yourself needing to run commands on the switch CLI while having no reliable way to log in.

**Do this before you adopt the switches:**

1. Console into each switch out of the box.
2. **Set up a local admin user** on the switch front-end. This is worth the five minutes. It guarantees you can always get back in regardless of FortiLink credential behavior.
3. Upgrade firmware to match the FortiGate (see next section).
4. Knock out the MCLAG/ICL-related switch-global and port settings while you have easy CLI access.

Doing the config up front turns the post-adoption process into "cable it and verify" instead of "fight to get onto a switch I can't log into."

## Step 1: Match firmware first, before anything else

This is the gotcha that looks like a config problem but isn't.

FortiSwitches frequently ship on an older train (e.g. 7.2.x) than your FortiGate (e.g. 7.6.6). The switches will adopt, show **Authorized/Up**, and pass traffic perfectly, while auto-ICL formation silently does not work the way the 7.6 docs describe. The auto-MCLAG mechanism is exactly the kind of newer switch-controller functionality that gets limited under version skew.

Check the FortiLink Compatibility matrix for your FortiOS release and match the FortiSwitchOS train. For FortiOS 7.6.6, run the switches on a 7.6.x FortiSwitchOS.

Verify after upgrade:

```
execute switch-controller get-conn-status
```

Both switches should show the matched version and Authorized/Up. Do not proceed to MCLAG until the versions line up. Chasing MCLAG on mismatched firmware is wasted effort.

## Step 2: Adopt to FortiLink

Standard FortiLink onboarding. Split-interface can be **on** at this stage; you turn it off later. Authorize both switches and confirm they come up.

```
execute switch-controller get-conn-status
```

## Step 3: Cable the inter-switch link and let the auto-ISL trunk form

Pick two ports on each switch for the ICL and cable them straight across (e.g. sw1 port27 -> sw2 port27, sw1 port28 -> sw2 port28).

The inter-switch ports need the auto-ISL LLDP profile. If you did the pre-adoption config, this is already set. The profile is `default-auto-isl`:

```
config switch physical-port
    edit "port27"
        set lldp-profile default-auto-isl
    next
    edit "port28"
        set lldp-profile default-auto-isl
    next
end
```

With matched firmware, the profile set, and the cable up, the switch **auto-forms an ISL trunk on its own**. Verify on the switch CLI:

```
diagnose switch trunk summary
```

You are looking for a trunk named after the peer switch serial (last 13 characters) plus `-0`, with both ICL ports as members and status `up(2/2)`:

```
4EI************-0    lacp-active(isl)    src-dst-ip   ...   up(2/2)   ...
```

If the trunk shows up here, the hard part of detection is done. The ports are correct and the link is healthy. **This is still just an ISL, not yet an MCLAG-ICL.** That distinction is the next gotcha.

## Step 4: Disable FortiLink split-interface

MCLAG and split-interface are mutually exclusive redundancy models. Split-interface is the simpler "no ICL" mode; MCLAG is the "with ICL" mode. You cannot run both.

```
config system interface
    edit fortilink
        set fortilink-split-interface disable
    next
end
```

## Step 5: Enable mclag-stp-aware at the global switch level

This must be enabled (it is on by default, but confirm it, especially after firmware changes). It is a **switch-global** setting, run on the switch CLI, not on the FortiGate:

```
config switch global
    set mclag-stp-aware enable
end
```

STP must also be enabled on the ICL trunks (default).

## Step 6: Promote the ISL trunk to an MCLAG-ICL (the hidden step)

This is the command that the FortiGate's managed-switch object does **not** expose, and it is the single most-missed step. The auto-ISL trunk from Step 3 has to be flagged as an MCLAG-ICL, and that flag lives under `config switch trunk` on the switch itself.

On **switch 1**, find the ISL trunk name from `diagnose switch trunk summary`, then:

```
config switch trunk
    edit "4EI*********-0"
        set mclag-icl enable
    next
end
```

On **switch 2**, the reciprocal trunk is named after switch 1's serial (last 13 + `-0`):

```
config switch trunk
    edit "4EI********-0"
        set mclag-icl enable
    next
end
```

**Both ends must have `mclag-icl enable`.** A one-sided ICL is an unstable, asymmetric state and is worse than not enabling it at all.

Expect a brief connectivity blip on each switch as the trunk reinitializes into its ICL role. If your management session is riding the inter-switch link, it may drop momentarily. This is normal. Do both ends in reasonably quick succession so you are not sitting in the asymmetric state for long.

If you only manage to set one side and cannot reach the other, revert the side you set (`unset mclag-icl` on that trunk) to return to a stable plain-ISL state, then do both together once you have access to both.

## Step 7: Verify

On the switch CLI:

```
diagnose switch mclag icl
diagnose switch mclag peer-consistency-check
```

On the FortiGate:

```
diagnose switch-controller switch-info mclag icl
diagnose switch-controller switch-info mclag peer-consistency-check
```

A healthy result shows:

- The ICL up on both ends with the ICL ports listed (e.g. `icl-ports 27-28`).
- `egress-block-ports` showing the FortiGate uplink ports (the MCLAG logic handling them correctly).
- peer-consistency-check all OK across every trunk: `peer-config OK`, `lacp-state UP`, `stp-state OK`, with matching local and remote ports.
- Reciprocal config that matches on both switches (each lists the other as peer by serial/MAC).

Example of a good ICL output:

```
4EITF25000672-0
    icl-ports            27-28
    egress-block-ports   25-26
    local-serial-number  S424EI**********
    peer-serial-number   S424EI**********
    split-brain          Disabled
```

## Step 8 (hardening): consider split-brain detection

By default split-brain detection is disabled. It forces one peer dormant if the ICL fails while both switches stay up, preventing duplicate forwarding. On a regulated/OT segment heading toward NERC CIP, this is worth enabling once the MCLAG has been stable for a few days. On both switches:

```
config switch global
    set mclag-split-brain-detect enable
end
```

Optionally pair it with `mclag-split-brain-priority` to control which switch goes dormant, and `mclag-split-brain-all-ports-down` if you want the dormant switch to shut its ports. Test in a window; enabling it can cause brief LACP renegotiation.

## The condensed runbook

For the next time, the whole thing in order:

1. **Before adoption (console access, while it's easy):**
   - Set up a local admin user on each switch.
   - Upgrade FortiSwitchOS to match the FortiGate train. Verify with `get-conn-status`.
   - Set `mclag-stp-aware enable` under `config switch global`.
   - Set `lldp-profile default-auto-isl` on the intended ICL ports.
2. **Adopt** both switches to FortiLink (split-interface on is fine to start).
3. **Cable the ICL** between the switches. Confirm the auto-ISL trunk forms: `diagnose switch trunk summary`.
4. **Disable** FortiLink split-interface.
5. **Promote** the ISL trunk to ICL on each switch: `set mclag-icl enable` under `config switch trunk`. Both ends. Expect a blip.
6. **Verify** with `peer-consistency-check` on both the switches and the FortiGate.
7. **Harden** later with split-brain detection if the environment warrants it.

## The two things to tattoo on your hand

1. **Match firmware first.** Skew makes auto-ICL fail while everything looks fine.
2. **`set mclag-icl enable` is a per-switch CLI command under `config switch trunk`.** The FortiGate hides it. The ISL forms automatically; the ICL promotion does not.

And the meta-lesson: **do the switch-side config before adoption**, because logging into a FortiLink-managed switch afterward is its own ordeal.
