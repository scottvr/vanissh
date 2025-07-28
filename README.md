# VANISSH - Vanity SSH key generator

![If they can't tell how l33t you are by having a vanity public key, make it explicit](https://github.com/scottvr/vanissh/raw/f1cad4023864831e3ea8e4a099ee30525ce34f23/vanisshex.png)

## on the origin of vanissh
I was importing some public keys into an authorized_keys file manually for a small side project and noticed that about half of them were rsa2048 and the rest were ed25519, and that the Base64-encoded ed25519 keys were much shorter in length than the RSA keys, and then realized I knew nothing about the current state of recommended keysize and cipher and thought I should take a moment to learn. 

A quick search lead me to [Brandon Checketts' blog](https://www.brandonchecketts.com/archives/ssh-ed25519-key-best-practices-for-2025) page on the topic (in which he pokes a little fun about his *older* version of a similar article ranking highly with the search engines, making him apparently feel somewhat obligated to write an updated version of an "SSH Key Best Practices" post.) It's a good read and touches on things like "department keys", key rotation, and some other good stuff; check it out.

But the reason I am mentioning his blog post is that near the bottom of his article he writes:
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

I chuckled at the notion of running the command over and over again until you get one that you "like", but it brought forth vague impressions of BTC vanity addresses, intentional hash collisions and the like. My first fully-realized thought immediately upon reading it though was "oh no.. that should be automated in a loop. And those *memorable few digits* should be *specified beforehand* and then checked for, and when found the loop should exit, and rename your file for you."

So naturally a tool started taking shape in my mind that would take a string, or perhaps a wordlist, and maybe even allow the user to specify where they would like to see the string... hmmm.

# Usage

```bash
usage: vanissh.py [-h] [-e email/comment] [-ap vanity_str] [-sp vanity_str]
                  [-ep vanity_str] [-ca] [-cs] [-ce] [-rp vanity_str] [-O]
                  [-st {0.0,1.0}] [-pl {0,22} | -ps vanity_str] [-ui] [-pc]
                  [-t {ed25519,rsa}] [-b bits] [-n numproc] [-l logfile]
```
# Options

```bash
optional arguments:
  -h, --help            show this help message and exit
  -e email/comment, --email email/comment
                        Email address for key comment
  -n numproc, --processes numproc
                        Number of worker processes to use
  -l logfile, --logfile logfile
                        Output file for generation results (JSON)

Vanity Pattern options:
  -ap vanity_str, --anywhere-pattern vanity_str
                        Pattern to match anywhere in the key
  -sp vanity_str, --start-pattern vanity_str
                        Pattern that must match at start of key
  -ep vanity_str, --end-pattern vanity_str
                        Pattern that must match at end of key
  -ca, --case-sensitive-anywhere
                        Make anywhere patterns case-sensitive
  -cs, --case-sensitive-start
                        Make start patterns case-sensitive
  -ce, --case-sensitive-end
                        Make end patterns case-sensitive

RSA Vanity Injection:
  -rp vanity_str, --rsa-vanity vanity_str
                        Generate RSA key with specific vanity text injected at
                        start of key
  -O, --optimize        Suggest optimized variations of the vanity text for
                        faster generation
  -st {0.0,1.0}, --similarity {0.0,1.0}
                        Minimum visual similarity for optimized variations
                        (0.0-1.0)

Palindrome options:
  -pl {0,22}, --palindrome-length {0,22}
                        Generate any palindrome of this total length
  -ps vanity_str, --palindrome-start vanity_str
                        Generate a palindrome starting with these characters
  -ui, --use-free-i     Use the guaranteed "I" character as part of the
                        palindrome
  -pc, --palindrome-case-sensitive
                        Make palindrome matching case-sensitive

Key Generation options:
  -t {ed25519,rsa}, --key-type {ed25519,rsa}
                        Type of key to generate
  -b bits, --key-bits bits
                        Bits for RSA key (ignored for ed25519)

```
# Examples

You may wonder about the awkwardly-specific command-line arguments relating to the pattern you'd like to see, so I'll explain simply that they are there to enable flexibility on a single command invocation, in order to save time by increasing the chances *something* will match that you'll be pleased with. (Though there's still room for improvement such as allowing for ANDing multiple arguments or negative patterns. Of course, if you're determined enough since your patterns can be a valid regex, you can roll your own ANDing and negatives and anything else your regex-fu might enable.)

## This example below is a way to generate a public key that matches
- any of "31337", "leet", "l33t", "elite" anywhere in the key's Base64-encoded string OR
- "el8" either as the first or last three characters of the key's Base64-encoded string
whichever comes first.*
```bash
python src/vanissh.py -e you@example.com \
    -ap "31337|leet|l33t|elite" \
    -ep "el8" \
    -sp "el8"
```

## Mix and match with position-specific case sensitivity (again, regex could handle this for you if you care to roll your own)
```bash
python src/vanissh.py -e you@example.com \
    -ap "l33t|elite" -ca \
    -ep "cool" \
    -sp "HACK" -cs
```

## Multiple patterns per position
```bash
python src/vanissh.py -e you@example.com \
    -ap "l33t" -ap "elite" \
    -ep "er" -ep "or" \
    -xp "ABCD"
```
and again, since it's all "OR" logic of terms at this point, the first example with the pipe-separated terms would be another way to accomplish the same.
Also, with the power of regex you could do something like this:
`-ap "(.)(.)(.).?\3\2\1"` and be assured that, given enough time, you'd have an ssh public key that contained a palindrome! (continue that up to \22 (so you'll have a total of 44 characters after the Base64-encoded ssh-ed25519 prefix) and your entire public key is a palindrome! Maybe that's something to tackle in the "stuff I learned" section when we talk about probabilities.
## EDIT
Where there was just the above silly-but-true comment about palindromes, there is now a built-in palindromic keyfinder. 
Just playin' around on an old i5 laptop:
```bash
(.venv) C:\Users\scottvr\source\vanissh>python src\vanissh.py  -e ia.mamai@iamam.ai --palindrome-length 7
Generated palindrome pattern: (.)(.)(.)(.)\3\2\1
Starting generation with 4 processes...

Generation Results:
Found matching key in 13.66 seconds
Total attempts: 513
Keys per second: 37.56
Keys per second per worker: 9.39

CPU Frequency (MHz):
  Min: 2400
  Max: 2400
  Avg: 2400

Matching Key:
Public key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICZKa/n6RbGXwMwXGdNiUUiB2gc8t1SC
nCBHf1YTgoBa meem@ten.net
Matched pattern 'GXwMwXG' at position (34, 41)
Found by worker 2 (PID: 9780)
```
lulz. It doesn't look like much hiding in the key but you gotta admit that 
### GXwMwXG
looks pretty cool on its own.

The new options are, btw:
```
Palindrome options:
  --palindrome-length PALINDROME_LENGTH
                        Generate any palindrome of this total length
  --palindrome-start PALINDROME_START
                        Generate a palindrome starting with these characters
  --use-free-i          Use the guaranteed "I" character as part of the
                        palindrome
```
ok.. back to what you were reading before...
----

*there is a bit of post-match checking for  magic that occurs in the unlikely event that you specified a pattern in such a way where say a five-letter pattern is specified as well as a three-letter pattern that is found within that longer pattern. If it is about to declare a winning three-letter pattern, it will check just in case you get lucky and alert you if surrounding characters mean you also matched the five-letter pattern. I'm working on allowing the known characters of the pre-amble (I'll talk about this in a later section) to be checked in the event you have a `start` or `anywhere` pattern where the "AI" at the start of the Base64-encoded 32-byte key of your new ed25519 key can be used to save two characters of generation. A FREE 'i' or FREE 'AI' even!

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
Public key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILEYnLgpraYTF/Wq+zxSs+fpuOfxSwJ9krpfext13uzX foo@bar.baz
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

But, that's an average, over time, given enough generations.. I'm not a statistician and *I* know why*; perhaps you will all soon know why as well as I try to explain some things. (*know why I am not a statistician, that is.) 


## Some Thoughts and Learnings along the way.

These examples above are output from running vanissh on a very old T2.micro instance, and its single core generates, then does the strings matching, etc consistently at a rate of about 170 keys/second.
The tool has benchmarking code, but I've yet to run it on any other machines as I still haven't even finished this initial documentation. 

But something occurred to me, that seemed obvious and intuitive at first: "Hey, an RSA key has a lot more Base64-encoded text; it's much longer - surely that would vastly increase our chances of finding an "anywhere" match and thus speed this sucker up. I should add rsa2048 support"

I did add the support. But what I did not consider before trying was that (although I having added support for both types of key to have been worthwhile, inasmuch as this tool is worth any while at least) an RSA key takes a substantially greater amount of time to generate than the ed25519 keys do.

The public key format shows the modulus (n) of the RSA key pair, but finding specific patterns in that modulus isn't as simple as generating new keys rapidly because:

Each RSA key generation requires finding large prime numbers and performing relatively expensive mathematical operations
ED25519 key generation is much faster (often by orders of magnitude)

In my testing, ED25519 key generation is typically 5-10x faster than RSA-2048 for this purpose. I didn't even try with RSA4096 but I'd imagine the obvious.

----
### this section is still being written

According to [RFC8709](https://datatracker.ietf.org/doc/html/rfc8709):
```
4. Public Key Format
The "ssh-ed25519" key format has the following encoding:

string
"ssh-ed25519"
string
key
Here, 'key' is the 32-octet public key described in [RFC8032](https://datatracker.ietf.org/doc/html/rfc8032), Section 5.1.5.
```

