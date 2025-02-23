# vanissh
Vanity SSH key generator

### Origin
I was importing some public keys into an authorized_keys file manually for a small side project and noticed that about half of them were rsa2048 and the rest were ed25519, and that the Base64-encoded ed25519 keys were much shorter in length than the RSA keys, and then realized I knew nothing about the current state of recommended keysize and cipher and thought I should take a moment to learn. 

A quick search lead me to [Brandon Checketts' blog]https://www.brandonchecketts.com/archives/ssh-ed25519-key-best-practices-for-2025) page on the topic (in which he pokes a little fun about his *older* version of a similar article ranking highly with the search engines, making him apparently feel somewhat obligated to write an updated version of an "SSH Key Best Practices" post. It's a good read and touches on things like "department keys", key rotation, and some other good stuff; check it out.

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

I chuckled at this notion that brought forth vague impressions of BTC vanity addresses, intentional hash collisions and the like. My first fully-realized thought immediately upon reaing it though was "oh no.. that should be automated in a loop. And those "memorable few digits" should be checked for, and when found the loop should exit, and rename your file for you."

So naturally a tool started taking shape in my mind that would take a string, or perhaps a wordlist, and maybe even allow the user to specify where they would like to see the string... hmmm.

Had several _almost there_ iterations, allowing for a "prefix" or "suffix" or "anywhere" placement of the target string, eventually letting the user supply a regex instead of just a string or wordlist, and re-implementing the "where to match" arguments. (Note, I learned more than about ssh keys in one night than I had in the previous 30 years, and for the interested, there will be a section of this README that covers what I have learned, just to pass it on.)

# Usage
