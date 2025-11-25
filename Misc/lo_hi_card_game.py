from functools import total_ordering
from Crypto.Random import random
from pwn import *
import json


io = remote('socket.cryptohack.org', 13383)

VALUES = ['Ace', 'Two', 'Three', 'Four', 'Five', 'Six',
          'Seven', 'Eight', 'Nine', 'Ten', 'Jack', 'Queen', 'King']
SUITS = ['Clubs', 'Hearts', 'Diamonds', 'Spades']


@total_ordering
class Card:
    def __init__(self, value, suit):
        self.value = value
        self.suit = suit

    def __str__(self):
        return f"{self.value} of {self.suit}"

    def __eq__(self, other):
        return self.value == other.value

    def __gt__(self, other):
        return VALUES.index(self.value) > VALUES.index(other.value)


def smart_pick(card_str, deck):
    idx = deck.index(card_str)
    val = idx % 13
    return 'l' if val > 6 else 'h'


def reconstruct_rng_state(card_indexes):
    state = 0
    for index in card_indexes:
        state = state * 52 + index
    return state


def collect_cards():
    deck = [str(Card(v, s)) for s in SUITS for v in VALUES]
    shuffle_states, current_shuffle = [], []
    hand = None

    for _ in range(34):
        pick = smart_pick(hand, deck) if hand else random.choice(['l', 'h'])

        if _ == 0:
            result = json.loads(io.recvline().decode())
        else:
            io.sendline(json.dumps({'choice': pick}).encode())
            result = json.loads(io.recvline().decode())

        hand = result['hand']
        msg = result['msg']
        card_idx = deck.index(hand)

        if "reshuffle" in msg and 'Welcome' not in msg:
            current_shuffle.append(card_idx)
            shuffle_states.append(current_shuffle)
            current_shuffle = []
            continue

        current_shuffle.append(card_idx)

        if len(shuffle_states) == 3:
            return shuffle_states


def recover_mul_inc(shuffles):
    a, b, c = map(reconstruct_rng_state, shuffles)
    mod = 2**61 - 1
    mul = ((c - b) % mod) * pow(b - a, -1, mod) % mod
    inc = (b - mul * a) % mod
    return mul, inc, c


def rng(mul, inc, s):
    return (mul * s + inc) % (2**61 - 1)


def rebase(n, base=52):
    out = []
    while n:
        out.append(n % base)
        n //= base
    return out if out else [0]


deck = [str(Card(v, s)) for s in SUITS for v in VALUES]

mul, inc, state = recover_mul_inc(collect_cards())
next_state = rng(mul, inc, state)
shuffled = rebase(next_state)

current = shuffled.pop()

for _ in range(200 - 34):
    cur_val = current % 13
    nxt = shuffled.pop()
    nxt_val = nxt % 13

    print("Current card:", deck[current], "Next card:", deck[nxt])

    io.sendline(json.dumps({'choice': 'l' if nxt_val < cur_val else 'h'}).encode())
    print(io.recvline().decode())

    current = nxt

    if not shuffled:
        state = next_state
        next_state = rng(mul, inc, next_state)
        shuffled = rebase(next_state)

io.sendline(json.dumps({'choice': 'l'}).encode())
io.interactive()
