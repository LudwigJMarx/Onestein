# Gaps

Two lists, kept apart on purpose.

**Silences** are places where the specification does not say, and two
implementations can therefore disagree without either being wrong. They are
settled by measurement against the Java implementation, not by argument.

**Limits** are places where the specification does say, and the answer is
unsatisfying. No implementation can fix those. They are the only honest input
to the question of whether a different protocol is worth designing, and this
file exists so that question gets answered from a list rather than from a
feeling.

Nothing here is a plan. Entries are added when they are hit, with the section
of the specification and the evidence.

## Silences

| Gap | Layer | Our choice | How it gets settled |
|---|---|---|---|
| No nesting limit for containers | BDF | `MAX_NESTING = 64`, refused rather than recursed into | Feed the Java reader progressively deeper input and find where it stops |
| "Lexicographic order" for dictionary keys is not defined | BDF §canonical form | UTF-8 byte order | Java compares UTF-16 code units. Construct two keys that sort differently under the two orders and hash both sides |
| No record type for "I no longer have that message" | BSP 3.2 | not reached yet | Delete a message on the Java side after an OFFER, then REQUEST it and watch the wire |

## Limits

| Limit | Layer | Why no implementation fixes it | Versioned extension enough? |
|---|---|---|---|
| No post-quantum key agreement | BQP, BHP, BRP (X25519) | Contact relationships are long-lived and traffic is recordable today | A new handshake version, yes. But not a swapped constant: the protocols are written around `DH(pri, pub)`, and a KEM is encapsulate/decapsulate, so the message flow changes |
| Identity is bound to one device | BTP keys and BSP state are per device | A second device is a second identity, and group membership does not follow | Partly. A device can treat its own second device as a peer and replicate; a real answer touches the key hierarchy |
| Delivery needs both peers online at once | nothing in the stack stores and forwards | Briar Mailbox sits above the stack and needs a spare Android device | Yes, and BTP is built for it: it tolerates very high latency and transports where one side can only send |
| A group floods to every member that shares it | BSP 1.1, 4.2 | Every member stores and forwards everything, so a group cannot outgrow its smallest device | No. This is BSP's model, not an implementation choice |
| Contacts see each other's contact graph through introductions and sharing | BSP sharing, Introduction Client | Metadata resistance is against outsiders, not against contacts | No |

## What stays either way

- **BDF.** A compact, unambiguous encoding with nothing to improve at this
  scale.
- **BTP.** No plaintext headers, no handshake, no timeouts, forward secrecy
  even where one peer can only send and the other only receive, usable from
  kilobits to gigabits and from milliseconds to days. It is at version 4,
  which is three redesigns of experience, and it is the part of the stack a
  green-field project would most likely get wrong.
