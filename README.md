# VANISSH - Vanity SSH key generator

## on the origin of vanissh
I was importing some public keys into an authorized_keys file manually for a small side project and noticed that about half of them were rsa2048 and the rest were ed25519, and that the Base64-encoded ed25519 keys were much shorter in length than the RSA keys, and then realized I knew nothing about the current state of recommended keysize and cipher and thought I should take a moment to learn. 

A quick search lead me to [Brandon Checketts' blog](https://www.brandonchecketts.com/archives/ssh-ed25519-key-best-practices-for-2025) page on the topic (in which he pokes a little fun about his *older* version of a similar article ranking highly with the search engines, making him apparently feel somewhat obligated to write an updated version of an "SSH Key Best Practices" post. It's a good read and touches on things like "department keys", key rotation, and some other good stuff; check it out.

But the reason I mention his blog post is neat the bottom he writes:
>Obsessive/Compulsive Tip
This may be taking it too far, but I like to have a memorable few digits at the end of the key so that I can confirm the key got copied correctly. One of my keys ends in 7srus, so I think of it as my “7’s ‘R’ Us” key. You can do that over and over again until you find a key that you like with this one-liner:
```bash
rm newkey; rm newkey.pub; ssh-keygen -t ed25519 -f ./newkey -C "brandon+2025@roundsphere.com" -N ''; cat newkey.pub;
```
>That creates a key without a passphrase, so you can do it over and over quickly until you find a public key that you “like”. Then protect it with a passphrase with the command
```bash
ssh-keygen -p -f newkey
```
>And obviously, then you rename it from newkey and to newkey.pub a more meaningful name.

I chuckled at this notion that brought forth vague impressions of BTC vanity addresses, intentional hash collisions and the like. My first fully-realized thought immediately upon reading it though was "oh no.. that should be automated in a loop. And those "memorable few digits" should be checked for, and when found the loop should exit, and rename your file for you."

So naturally a tool started taking shape in my mind that would take a string, or perhaps a wordlist, and maybe even allow the user to specify where they would like to see the string... hmmm.

There were several _almost there_ iterations, allowing for a "prefix" or "suffix" or "anywhere" placement of the target string, and various ideas that turns out not so great along the way, eventually settling on letting the user supply a regex instead of just a string or wordlist, and re-implementing the "where to match" arguments in a sort of convoluted way for flexibility. In the process of some trial-and-error learning and attempts at optimization (I'm sure there's lots that can still be done to make it more performant) I ended up learning in one night things I had never known about ssh keys in the previous 30 years so a portion of this README will share that journey. But first...

# Usage

usage: vanishh.py [-h] --email EMAIL [--anywhere-pattern ANYWHERE_PATTERN]
                  [--start-pattern START_PATTERN] [--end-pattern END_PATTERN]
                  [--exact-pattern EXACT_PATTERN] [--case-sensitive-anywhere]
                  [--case-sensitive-start] [--case-sensitive-end]
                  [--case-sensitive-exact] [--key-type {ed25519,rsa}]
                  [--key-bits KEY_BITS] [--output OUTPUT]
vanishh.py: error: the following arguments are required: --email/-e

# Options

optional arguments:
  -h, --help            show this help message and exit
  --email EMAIL, -e EMAIL
                        Email address for key comment
  --anywhere-pattern ANYWHERE_PATTERN, -ap ANYWHERE_PATTERN
                        Pattern to match anywhere in the key
  --start-pattern START_PATTERN, -sp START_PATTERN
                        Pattern that must match at start of key
  --end-pattern END_PATTERN, -ep END_PATTERN
                        Pattern that must match at end of key
  --exact-pattern EXACT_PATTERN, -xp EXACT_PATTERN
                        Pattern that must match exactly (both start and end)
  --case-sensitive-anywhere, -ca
                        Make anywhere patterns case-sensitive
  --case-sensitive-start, -cs
                        Make start patterns case-sensitive
  --case-sensitive-end, -ce
                        Make end patterns case-sensitive
  --case-sensitive-exact, -cx
                        Make exact patterns case-sensitive
  --key-type {ed25519,rsa}, -t {ed25519,rsa}
                        Type of key to generate
  --key-bits KEY_BITS, -b KEY_BITS
                        Bits for RSA key (ignored for ed25519)
  --output OUTPUT, -o OUTPUT
                        Output file for benchmark results (JSON)

# Examples

You may wonder about the awkwardly-man specific command-line arguments, so I'll explain simple that they are there to enable flexibility on a single command invocation, in order to save time by increasing the chances *something* will match that you'll be please with. (Though there's still room for improvement such as allowing for ANDing multiple arguments or negative patterns. Of course, if you're determined enough since your patterns can be a valid regex, you can roll your own ANDing and negatives and anything else your regex-fu might enable.)

## This example below is a way to generate a public key that matches
- any of "31337", "leet", "l33t", "elite" anywhere in the key's Base64-encoded string
- "el8" either as the first or last three characters of the key's Base64-encoded string
```bash
python ssh-key-mem-bench-v2.py -e you@example.com \
    -ap "31337|leet|l33t|elite" \
    -ep "el8" \
    -sp "el8"
```

## Mix and match with position-specific case sensitivity (again, regex could handle this for you if you care to roll your own)
```bash
python ssh-key-mem-bench-v2.py -e you@example.com \
    -ap "l33t|elite" -ca \
    -ep "cool" \
    -sp "HACK" -cs
```

## Multiple patterns per position
```bash
python ssh-key-mem-bench-v2.py -e you@example.com \
    -ap "l33t" -ap "elite" \
    -ep "er" -ep "or" \
    -xp "ABCD"
```
and again, since it's all "OR" logic of terms at this point, the first example with the pipe-separated terms would be another way to accomplish the same.
Also, with the power of regex you could do something like this:
`-ap "\b(\w)[ \t,'"]*(?:(\w)[ \t,'"]*(?:(\w)[ \t,'"]*(?:(\w)[ \t,'"]*(?:(\w)[ \t,'"]*(?:(\w)[ \t,'"]*(?:(\w)[ \t,'"]*(?:(\w)[ \t,'"]*(?:(\w)[ \t,'"]*(?:(\w)[ \t,'"]*(?:(\w)[ \t,'"]*\11?[ \t,'"]*\10|\10?)[ \t,'"]*\9|\9?)[ \t,'"]*\8|\8?)[ \t,'"]*\7|\7?)[ \t,'"]*\6|\6?)[ \t,'"]*\5|\5?)[ \t,'"]*\4|\4?)[ \t,'"]*\3|\3?)[ \t,'"]*\2|\2?))?[ \t,'"]*\1\b"` 
and be assured that at some point, some day, given enough time, you'd have an ssh public key that was a palindrome!

# some output examples
```bash
# python src/vanissh.py -e foo@bar.baz -ap 13
Starting benchmark with 1 processes...

Benchmark Results:
Found matching key in 0.56 seconds
Total attempts: 96
Keys per second: 170.31
Keys per second per worker: 170.31

CPU Frequency (MHz):
  Min: 2300
  Max: 2300
  Avg: 2300

Matching Key:
Public key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILEYnLgpraYTF/Wq+zxSs+fpuOfxSwJ9krpfext13uzX test@test.com
Matched pattern '13' at position (63, 65)
Found by worker 0 (PID: 28494)
```

Here's an example of searching for a three-letter pattern:
```bash
Found matching key in 12.18 seconds after 1974 attempts!
Key files saved as: /home/scottvr/ssh-key-mem/memorable_key_1740283444
Public key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINEl80DxH5FI+IMP2Xdf4AHu8I/YZ209Vf+5Dstd4YXf foo@bar.baz
Matched pattern 'El8' at position (26, 29)
```

That didn't take long at all. It was quite surprising to me.

Of course, the more characters in your pattern and the more constraints you specify (position, case-sensitivity) the longer the average time for you to generate a winning vanity key will be.

But, that's an average, over time, given enough generations.. I'm not a statistician and *I* know why; perhaps you will all soon know why as well as I try to explain some things. 


# Some Thoughts and Learnings along the way.

These examples above are from a very old T2.micro instance, and its single core generates, then does the strings matching, etc consistently at a rate of about 170 keys/second.
The tool has benchmarking code, but I've yet to run it on any other machines as I still haven't even finished this initial documentation. 

But something occurred to me, that seemed obvious and intuitive at first: "Hey, an RSA key has a lot more Base64-encoded text; it's much longer - surely that would vastly increase our chances of finding an "anywhere" match and thus speed this sucker up. I should add rsa2048 support"

I did add the support. But what I did not consider before trying was that (although I having added support for both types of key to have been worthwhile, inasmuch as this tool is worth any while at least) an RSA key takes a substantially greater amount of time to generate than the ed25519 keys do.

The public key format shows the modulus (n) of the RSA key pair, but finding specific patterns in that modulus isn't as simple as generating new keys rapidly because:

Each RSA key generation requires finding large prime numbers and performing relatively expensive mathematical operations
ED25519 key generation is much faster (often by orders of magnitude)

In my testing, ED25519 key generation is typically 5-10x faster than RSA-2048 for this purpose. I didn't even try with RSA4096 but I'd imagine the obvious.
