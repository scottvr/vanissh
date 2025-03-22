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

>Yeah, and now after sharing this tool I have learned about the long-existing vanity_rsa, about seven years late to that party. *shrug* Well, I can take some influence from his magic math trick for rsa, and my value add is um... palindromes?

# Usage

```bash
usage: vanissh.py [-h] [-e email/comment] [-ap vanity_str] [-sp vanity_str]
                  [-ep vanity_str] [-ca] [-cs] [-ce] [-rp vanity_str] [-O]
                  [-st {0.0,1.0}] [-pl {0,22} | -ps vanity_str] [-ui] [-pc]
                  [-t {ed25519,rsa}] [-b bits] [-n numproc] [-l logfile]
```
# Options
```bash

Note: For 10x performance, install gmpy2: pip install gmpy2
usage: vanissh.py [-h] [-e email/comment] [-ap vanity_str] [-sp vanity_str]
                  [-ep vanity_str] [-ca] [-cs] [-ce] [-rp vanity_str] [-O]
                  [-st {0.0,1.0}] [-pl {0,22} | -ps vanity_str] [-ui] [-pc]
                  [-t {ed25519,rsa}] [-b bits] [-n numproc] [-l logfile]

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

## Security Considerations

After I made the Ed25519 version of this tool, I found that an equivalent tool for RSA keys pre-exists vanissh by years. It takes a neat approach (which I have borrowed the premise of when adding RSA key functionality to vanissh) where we modify a valid key to contain our text. This will dramatically reduce the amount of time taken since we aren't (as in our ed25519 approach) generating and checking for match and repeating until a match happens to be found. In the case of RSA, the modulus N = P\*Q forms the basis of our security, where P and Q are two random large prime numbers. The security comes from the fact that while a single multiplication is very fast for modern computers to perform, factoring the product to find *which* very large prime numbers were multiplied is a very computationally-expensive task, with time and resources required  growing exponentially with number size.

The author of the aforementioned [vanity_rsa tool](https://github.com/kvdveer/vanity_rsa) said this in an accompanying blog post:

> We start out with a freshly generated public key. We take the base64 representation and replace a part of it with our injected text. Of course, now the key is no longer valid. Also, it’s just a public key, and we also need a private key. To obtain those, we read the (now invalid) N from the public key. Remember that we need multiply two primes, P and Q to form N. To build the private key, we also need to know what those two primes are. One of these (P) primes can chosen at random, as long as it’s a prime number. The other (Q) can be estimated by dividing N over P. The result of this division is not likely to be prime, but if we can find a prime close to it, the value of P*Q is probably close enough to our N, that the injected text still remains there.

In other words:

### In standard RSA key generation:

- Two large random primes p and q are generated independently
- The modulus n = p×q forms the basis of the key's security
- The effective security comes from the computational difficulty of factoring n

### In our vanity key approach:

- We generate an initial random key (p and q are truly random)
- We modify the encoded public key (thereby changing n to n')
- We keep p from the original key and find a new q' such that p×q' ≈ n'
- We rebuild the key using p and q'

The author of `vanity_rsa` also wrote:
>I believe this tool produces keys that are as hard to crack as any other well-generated key.

Over on the `lobste.rs` list we see some are [dubious about this claim](https://lobste.rs/s/bnkjvt/vanity_rsa_public_key)

I, like the author of vainty_rsa do not claim to be a cryptography expert, but I also found his claim intuitively "wrong", but maybe what he actually meant was "of course we're compromising *some* entropy here, but really hard is still really hard", but I don't know this. I do know I wanted to quantify that trade-off and allow for compensation by the informed user within the tool itself.

So that there is no vagueness or ambiguity in my claims, here is what you should know:

1. **Ed25519 Keys**: The generate-and-check method doesn't reduce security beyond limiting the keyspace to those containing your pattern.

2. **RSA Keys**: The modify-and-repair approach involves more significant tradeoffs:
- Reduced Prime Selection Space: Instead of selecting q from the entire space of primes of appropriate size, we're selecting q' from a much smaller set of primes near n'/p.
- Potential for Non-Uniform Distribution: Standard RSA implementations go to great lengths to ensure p and q are chosen with proper randomness and appropriate properties (not too close to each other, not having certain structures, etc.). Our approach might introduce biases.
- Information Leakage: The vanity pattern itself might reveal that the key was generated using this technique, which tells an attacker they might be able to exploit the restricted keyspace.

### Quantifying the Security Reduction

- For a standard k-bit RSA key, there are approximately 2^(k/2) primes of size k/2 bits. But when we're looking for a prime q' that makes p×q' close to a specific target n', we're essentially searching in a small window - maybe only examining a few thousand candidate primes near n'/p.
- If we estimate that we examine, say, 10^4 potential values for q', then we've reduced the effective keyspace by a factor of roughly 2^(k/2) / 10^4. For a 2048-bit key, that's approximately 2^1024 / 10^4 ≈ 2^1024 / 2^13 = 2^1011.
- So that's an entropy reduction of approximately 2^1011 for 2048-bit keys which  suggests a security reduction of around 13 bits, which is actually not catastrophic for a 2048-bit key (which has an estimated security level of ~112 bits to begin with).
- An RSA key can have at *most* 2022 bits of entropy, but usually much less and in our case at least 1011 bits less *entropy* (not security)
- NIST (National Institute of Standards and Technology) recommends using keys with a minimum strength of 112 bits of security to protect data until 2030, and 128 bits of security thereafter. (a 2048-bit assymetric RSA key is considered to have equivalent protection to a 112-bit symmetric key cipher, and 3072-bit RSA is considered equivalent to 128-bit symmetric cipher.) 
- While experimenting with different ways to find the closest primes (for perlooking formance gains) I ended up keeping a few in as part of a larger benchmark stats collection effort where I am hoping may develop some heuristics about finding optimal injection points and so on based on logging different results with different keysizes, vanity strings, etc. If you use the deterministic prime finding strategy, this reduces entropy by an additional ~3.32 bits
- For maximum security, use the `--prime-selection exact` option (but be prepared to wait)
- Further on that note, if an attacker knows exactly which algorithm was used to find q', they might be able to narrow down their search space slightly; they would know that q' is either the nearest prime above n'/p or the nearest prime below it. This could theoretically save them a small amount of work in a factoring attack, but in practice, the "really hard is still really hard" quote that I said might possibly be what the vanity_rsa author *meant* by "as hard to crack" rather than "exactly as hard to crack" holds true here too.
 
 I won't pretend this is easily comprehensible to me, but [The General Number field sieve](https://en.wikipedia.org/wiki/General_number_field_sieve) is apparently the most efficient method for classical computing for integer factorization, and using it apparently would still take somewhere between a billion and 300 trillion years to crack a 2048-bit RSA key.

### That said...
**Compensation Strategies**:
- Assuming you need *at least* 112 bits of security and not *exactly 112 bits of security (which is a safe assumption) then the simplest mitigation if you want to use a vanity RSA key and still have "normal" 2048-bit key protection, generate a 3072-bit keypair, which even after our entropy losses yields ~112 bits of security.
- So for vanity RSA keys:
  - If you would normally use a 2048-bit RSA key (112 bits of security)
  Use a 3072-bit vanity key (128 - 16 = 112 bits of effective security)
  - If you would normally use a 3072-bit RSA key (128 bits of security)
  Use a 4096-bit vanity key (approximately 140 - 16 = 124 bits of effective security)

- Since Ed25519 starts with 256 bits of entropy, even a relatively long vanity string leaves you with substantial security. For comparison, a 12-character vanity string would reduce entropy by ~72 bits, leaving ~184 bits, which is still much stronger than the ~112 bits that a 2048-bit RSA key provides.

Each character in your vanity pattern reduces key entropy by approximately 6 bits:
- 1-character pattern: 250 bits of entropy (reduction of 6 bits)
- 4-character pattern: 232 bits of entropy (reduction of 24 bits)
- 8-character pattern: 208 bits of entropy (reduction of 48 bits)

Even with substantial vanity patterns, Ed25519 keys remain cryptographically strong.

