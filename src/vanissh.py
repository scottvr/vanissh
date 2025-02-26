#!/usr/bin/env python3
import re
import argparse
from pathlib import Path
import threading
import multiprocessing
import queue
import time
import psutil
import json
from datetime import datetime
import platform
import random
import os

from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Try to import gmpy2 for faster prime operations
try:
    import gmpy2
    HAVE_GMPY2 = True
except ImportError:
    HAVE_GMPY2 = False
    print("Note: For 10x performance, install gmpy2: pip install gmpy2")

class KeyParser:
    ED25519_HEADER = 'AAAAC3NzaC1lZDI1NTE5AAAA'
    RSA_HEADER = 'AAAAB3NzaC1yc2E'
    # Known RSA exponent patterns
    RSA_EXPONENTS = {
        3: 'AAAABAQ',
        17: 'AAAABEQ',
        257: 'AAAACAQE',
        65537: 'AAAADAQAB'
    }
    
    # Known RSA modulus length indicators
    RSA_MODULUS_PREFIXES = {
        1024: 'AAAAg',
        2048: 'AAABAQ',
        4096: 'AAACAQ'  
    }

    @staticmethod
    def get_header_length(key_type):
        """Return the length of the header for the given key type"""
        if key_type == 'ed25519':
            return (len(KeyParser.ED25519_HEADER) + 1)  # +1 for the mystery I
        elif key_type == 'rsa':
            return len(KeyParser.RSA_HEADER)
        return None

    @staticmethod
    def extract_matchable_portion(pubkey, key_type='ed25519'):
        """Extract only the meaningful portion of the key for pattern matching"""
        parts = pubkey.split()
        if len(parts) < 2:
            return None, None

        base64_part = parts[1]
        base64_part = base64_part.rstrip('=')

        # Find where the actual key material starts
        offset = KeyParser.get_header_length(key_type)

        if key_type == 'ed25519':
            if not base64_part.startswith(KeyParser.ED25519_HEADER):
                return None, None
            # For ed25519, everything after header is fair game
            return (
                base64_part[offset:], offset
            )

        elif key_type == 'rsa':
            if not base64_part.startswith(KeyParser.RSA_HEADER):
                return None, None

            # Try to identify the exponent portion
            for exp_encoding in KeyParser.RSA_EXPONENTS.values():
                if base64_part[offset:].startswith(exp_encoding):
                    offset += len(exp_encoding)
                    break

            # Try to identify the modulus length indicator
            for mod_prefix in KeyParser.RSA_MODULUS_PREFIXES.values():
                if base64_part[offset:].startswith(mod_prefix):
                    offset += len(mod_prefix)
                    break

            return base64_part[offset:], offset

        return None, None

    @staticmethod
    def get_matchable_length(key_type='ed25519'):
        """Return the expected length of the matchable portion"""
        if key_type == 'ed25519':
            return 43  # 32 bytes in base64 =~ 43 chars
        elif key_type == 'rsa':
            # This varies by key size, return None to indicate variable length
            return None
        return None


class PatternSpec:
    """Specification for a pattern to match in a key"""
    
    def __init__(self, pattern, anchor='anywhere', case_sensitive=False, key_type='ed25519'):
        self.pattern = pattern
        self.anchor = anchor
        self.case_sensitive = case_sensitive
        self.key_type = key_type
        self._compiled = None

        # Validate pattern against key constraints
        self._validate_pattern()

    def _validate_pattern(self):
        """Validate pattern against key type constraints"""
        if self.key_type == 'ed25519':
            max_length = KeyParser.get_matchable_length('ed25519')
            if max_length and len(self.pattern) > max_length:
                raise ValueError(
                    f"Pattern '{self.pattern}' is too long for ed25519 key",
                    f"(max {max_length} chars)"
                )

    def compile(self):
        """Compile the pattern with appropriate anchors"""
        pattern = self.pattern
        
        # Add anchors if needed
        if self.anchor == 'start':
            pattern = '^' + pattern
        elif self.anchor == 'end':
            pattern = pattern + '$'
            
        # Only group if we're not starting with a group
        if not pattern.startswith('('):
            pattern = f'({pattern})'
            
        flags = 0 if self.case_sensitive else re.IGNORECASE
        self._compiled = re.compile(pattern, flags)
        return self._compiled

    def match(self, text):
        """Try to match the pattern against text"""
        if not self._compiled:
            self.compile()
        return self._compiled.search(text)


def generate_palindrome_pattern(length):
    """
    Generate a regex pattern that matches palindromes of specified length.
    Length must be at least 2.
    """
    if length < 2:
        raise ValueError("Length must be at least 2")
        
    half_length = length // 2
    middle_char = length % 2  # 1 if odd length, 0 if even
    
    # First, construct all the capture groups
    pattern = ''
    for i in range(half_length):
        pattern += f'(.)'
        
    # Add middle character if odd length - no longer optional!
    if middle_char:
        pattern += '(.)'
        
    # Now add backreferences in reverse order
    for i in range(half_length, 0, -1):
        pattern += f'\\{i}'
        
    return pattern

class CryptoKeyGenerator:
    """Generate keys using the cryptography library"""
    
    def __init__(self, email, key_type='ed25519', key_bits=2048):
        self.email = email
        self.key_type = key_type
        self.key_bits = key_bits
        
    def generate_key(self):
        """Generate a key pair using the cryptography library"""
        if self.key_type == 'ed25519':
            private_key = ed25519.Ed25519PrivateKey.generate()
        else:  # rsa
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.key_bits
            )
            
        # Get private key PEM
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        # Get public key in OpenSSH format
        public_ssh = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        ).decode()
        
        # Add comment to public key if not already present
        if not public_ssh.endswith(self.email):
            public_ssh = f"{public_ssh} {self.email}"
            
        return private_pem, public_ssh


# Base64 characters used in SSH/PEM encoding
BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+"


class RSAVanityKeyGenerator:
    """Generate RSA keys with vanity strings at specified positions"""
    def __init__(self, email, vanity_text, key_bits=2048, optimize=False, similarity=0.7, injection_pos=None):
        self.email = email
        self.vanity_text = vanity_text
        self.key_bits = key_bits
        self.optimize = optimize
        self.similarity = similarity
        self.injection_pos = injection_pos if injection_pos is not None else calculate_injection_position(key_bits)

    def is_valid_vanity(self, text=None):
        """Check if vanity text contains only valid base64 characters"""
        if text is None:
            text = self.vanity_text
        return all(c in BASE64_CHARS for c in text)
        
    def generate_key(self):
        """Generate a valid RSA key with the vanity text"""
        # Check if vanity is valid
        if not self.is_valid_vanity():
            raise ValueError(f"Vanity text '{self.vanity_text}' contains invalid characters")
            
        # If optimization is enabled, find a better variation
        if self.optimize:
            original = self.vanity_text
            candidates = self.generate_optimized_candidates(original)
            print(f"Original vanity: {original}")
            print("Optimized candidates (estimated performance boost):")
            for i, (candidate, score) in enumerate(candidates[:5], 1):
                print(f"{i}. '{candidate}' (approx. {score:.1f}x faster)")
                
            # Ask user which candidate to use
            choice = input("Enter number of candidate to use (or 0 for original): ")
            try:
                choice = int(choice)
                if 1 <= choice <= len(candidates):
                    self.vanity_text = candidates[choice-1][0]
                    print(f"Using optimized vanity: '{self.vanity_text}'")
                else:
                    print(f"Using original vanity: '{original}'")
            except ValueError:
                print(f"Using original vanity: '{original}'")
        
        # Start with a normal RSA key
        print("Generating initial RSA key...")
        priv_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_bits
        )
        
        # Inject vanity string
        print(f"Injecting vanity string: {self.vanity_text}")
        pub_key = self.inject_vanity_ssh(priv_key)
        
        # Fix the key to make it valid
        print("Making the key mathematically valid (this may take a while)...")
        start_time = time.time()
        valid_key = self.make_valid_rsa_key(priv_key, pub_key)
        elapsed = time.time() - start_time
        print(f"Key validation completed in {elapsed:.2f} seconds")
        
        # Encode the key in OpenSSH format
        priv_pem = valid_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        pub_ssh = valid_key.public_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        ).decode()
        
        # Add comment to public key if not already present
        if not pub_ssh.endswith(self.email):
            pub_ssh = f"{pub_ssh} {self.email}"
            
        return priv_pem, pub_ssh

    def calculate_injection_position(key_bits=2048, exponent=65537):
        """Calculate the exact injection position based on key parameters"""
        # Get the appropriate header components
        header = KeyParser.RSA_HEADER
        exponent_encoding = KeyParser.RSA_EXPONENTS.get(exponent)
        modulus_prefix = KeyParser.RSA_MODULUS_PREFIXES.get(key_bits)
        
        # The injection position is right after all these components
        # Start with 'ssh-rsa ' length (8 characters)
        position = 8
        if header:
            position += len(header)
        if exponent_encoding:
            position += len(exponent_encoding)
        if modulus_prefix:
            position += len(modulus_prefix)
            
        return position

    def inject_vanity_ssh(self, priv_key):
        """Embed the vanity text in an SSH-format public key"""
        vanity = self.vanity_text.encode()
        
        # Generate the SSH format public key
        public_key_repr = priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        )

        # Public keys with 65537 exponent all have the same prefix:
        # 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAg'
        # USE THE RSA_HEADER VARS.. cuz that's only good for a 1024-bit key
        # For 2048 it would look like this:
        # 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ' so we need to be sure and adjust injection_pos_start in test loop
        # also, clean this all up and consistently use the same constants and methods
        # We inject the vanity right after this prefix
        # The exact position might need adjustment based on key size
        pos = self.injection_pos
        
        # Inject the vanity text
        public_key_repr = (
            public_key_repr[:pos] +
            vanity +
            public_key_repr[pos + len(vanity):]
        )

        # Load the modified (but likely invalid) key back
        pub_key = serialization.load_ssh_public_key(public_key_repr)
        return pub_key
        
    def make_valid_rsa_key(self, priv_key, pub_key):
        """Generate a valid private key, with N close to the N from pub_key"""
        # Extract components from the keys
        n = pub_key.public_numbers().n
        e = pub_key.public_numbers().e
        p = priv_key.private_numbers().p
        
        # Find a prime q such that p*q is close to n
        q = self.close_prime(n // p)
        
        # Compute the private key from p, q, and e
        phi = (p - 1) * (q - 1)
        d = self.mod_inverse(e, phi)
        iqmp = self.mod_inverse(p, q)
        dmp1 = d % (p - 1)
        dmq1 = d % (q - 1)
        
        # Create a new private key with these values
        private_numbers = rsa.RSAPrivateNumbers(
            p=p,
            q=q,
            d=d,
            dmp1=dmp1,
            dmq1=dmq1,
            iqmp=iqmp,
            public_numbers=rsa.RSAPublicNumbers(e=e, n=p*q)
        )
        
        return private_numbers.private_key()
        
    def close_prime(self, n):
        """Find a prime number close to n."""
        if self.is_prime(n):
            return n  # If already prime - return it as-is.

        if not (n % 2):
            n += 1

        offset = 2
        near_primes = []

        # Find 10 primes near the provided number
        while len(near_primes) < 10:
            if self.is_prime(n + offset):
                near_primes.append(n + offset)
            if self.is_prime(n - offset):
                near_primes.append(n - offset)
            offset += 2

        return random.choice(near_primes)
        
    def is_prime(self, n, k=10):
        """Check if a number is prime."""
        if HAVE_GMPY2:
            return gmpy2.is_prime(n)
        else:
            # Miller-Rabin primality test
            if n == 2 or n == 3:
                return True
            if n <= 1 or n % 2 == 0:
                return False
                
            # Find r and s such that n-1 = 2^s * r
            r, s = n - 1, 0
            while r % 2 == 0:
                r //= 2
                s += 1
                
            # Witness loop
            for _ in range(k):
                a = random.randrange(2, n - 1)
                x = pow(a, r, n)
                if x != 1 and x != n - 1:
                    j = 1
                    while j < s and x != n - 1:
                        x = pow(x, 2, n)
                        if x == 1:
                            return False
                        j += 1
                    if x != n - 1:
                        return False
            return True
            
    def mod_inverse(self, a, m):
        """Calculate the modular inverse of a mod m."""
        if HAVE_GMPY2:
            return int(gmpy2.invert(a, m))
        else:
            # Extended Euclidean Algorithm
            g, x, y = self.extended_gcd(a, m)
            if g != 1:
                raise ValueError("Modular inverse does not exist")
            else:
                return x % m
                
    def extended_gcd(self, a, b):
        """Extended Euclidean Algorithm"""
        if a == 0:
            return b, 0, 1
        else:
            gcd, x, y = self.extended_gcd(b % a, a)
            return gcd, y - (b // a) * x, x
            
    def generate_optimized_candidates(self, original):
        """Generate optimized candidates for the vanity string"""
        candidates = []
        
        # 1. Case variations (if original has mixed case)
        candidates.append((original.lower(), 1.2))
        candidates.append((original.upper(), 1.3))
        
        # 2. Leet speak substitutions
        leet_map = {
            'a': '4', 'A': '4',
            'e': '3', 'E': '3',
            'i': '1', 'I': '1',
            'o': '0', 'O': '0',
            'l': '1', 'L': '1',
            's': '5', 'S': '5',
            't': '7', 'T': '7'
        }
        
        leet_version = original
        for char, replacement in leet_map.items():
            leet_version = leet_version.replace(char, replacement)
        
        if leet_version != original:
            candidates.append((leet_version, 1.5))
            
        # 3. Position optimizations
        # For now, just assign different scores based on theoretical position impact
        candidates.append((original + "==", 1.8))  # End padding often easier to accommodate
        
        # 4. Simple repetition patterns
        if len(original) <= 4:
            candidates.append((original + original, 1.4))
            
        # 5. Combinations of the above
        leet_lower = leet_version.lower()
        if leet_lower != leet_version:
            candidates.append((leet_lower, 1.7))
            
        # Remove any invalid candidates
        candidates = [(c, s) for c, s in candidates if self.is_valid_vanity(c)]
        
        # Sort by score (highest first)
        return sorted(candidates, key=lambda x: x[1], reverse=True)


class VanityKeyGeneration:
    """Generate and check keys for vanity patterns"""
    
    def __init__(self, email, patterns, key_type='ed25519', key_bits=2048):
        self.email = email
        self.patterns = patterns  # List of PatternSpec objects
        self.key_type = key_type
        self.key_bits = key_bits
        self.found_key = multiprocessing.Event()
        self.result_queue = multiprocessing.Queue()
        self.stats = GenerationStats()
        
    def _key_worker(self, worker_id):
        """Worker process to generate and test keys"""
        generator = CryptoKeyGenerator(self.email, self.key_type, self.key_bits)
        
        while not self.found_key.is_set():
            # Generate key in-process
            privkey, pubkey = generator.generate_key()
            
            # Extract only the meaningful portion for matching
            key_part, offset = KeyParser.extract_matchable_portion(pubkey, self.key_type)
            if not key_part:
                continue  # Invalid or unexpected key format
            
            self.stats.increment_attempts()
            
            full_key_part = pubkey.split()[1]
            
            # Check all patterns against the meaningful portion
            for pattern_spec in self.patterns:
                match = pattern_spec.match(key_part)
                if match:
                    # Use the offset returned from extract_matchable_portion
                    match_start = match.span()[0] + offset
                    match_end = match.span()[1] + offset
                    
                    # Save the winning key
                    safe_pattern = re.sub(r'[^a-zA-Z0-9]', '_', match.group(0))
                    keyfile = f"vanity_key-{safe_pattern}_{int(time.time())}"
                    with open(keyfile, 'w') as f:
                        f.write(privkey)
                    with open(f"{keyfile}.pub", 'w') as f:
                        f.write(pubkey)
                    
                    self.result_queue.put({
                        'public': pubkey,
                        'private': privkey,
                        'matched_part': full_key_part,
                        'match': match.group(0),
                        'match_position': (match_start, match_end),
                        'worker_id': worker_id,
                        'process_id': os.getpid(),
                        'pattern': pattern_spec.pattern,
                        'anchor': pattern_spec.anchor,
                        'keyfile': keyfile
                    })
                    self.found_key.set()
                    break

    def _metrics_recorder(self):
        """Thread to record performance metrics"""
        while not self.found_key.is_set():
            self.stats.record_metrics()
            time.sleep(self.stats.sampling_interval)
    
    def run_generation(self, num_processes=None):
        """Run the generation with multiple processes"""
        if num_processes is None:
            num_processes = multiprocessing.cpu_count()
            
        processes = []

        # Start metrics recording thread
        metrics_thread = threading.Thread(target=self._metrics_recorder, daemon=True)
        metrics_thread.start()

        # Start worker processes
        for i in range(num_processes):
            p = multiprocessing.Process(
                target=self._key_worker,
                args=(i,),
                daemon=True
            )
            processes.append(p)
            p.start()

        # Wait for a result
        result = self.result_queue.get()
        duration = time.time() - self.stats.start_time

        for p in processes:
            p.terminate()

        # Calculate final statistics
        generation_stats = self.stats.calculate_statistics(duration)

        system_info = {
            'cpu_model': platform.processor(),
            'cpu_count': multiprocessing.cpu_count(),
            'physical_cores': psutil.cpu_count(logical=False),
            'logical_cores': psutil.cpu_count(logical=True),
            'memory_gb': psutil.virtual_memory().total / (1024**3),
            'platform': platform.platform()
        }

        generation_results = {
            'timestamp': datetime.now().isoformat(),
            'system_info': system_info,
            'generation_config': {
                'patterns': [
                    {
                        'pattern': p.pattern,
                        'anchor': p.anchor,
                        'case_sensitive': p.case_sensitive
                    }
                    for p in self.patterns
                ],
                'key_type': self.key_type,
                'key_bits': self.key_bits
            },
            'performance_metrics': generation_stats,
            'winning_key': {
                'worker_id': result['worker_id'],
                'process_id': result['process_id'],
                'pattern': result['pattern'],
                'anchor': result['anchor'],
                'match': result['match'],
                'match_position': result['match_position']
            }
        }

        return result, generation_results


class GenerationStats:
    """Track key generation statistics"""
    
    def __init__(self):
        self.start_time = time.time()
        self.attempts = multiprocessing.Value('i', 0)
        self.keys_per_second = []
        self.cpu_freqs = []
        self.cpu_temps = []
        self.sampling_interval = 0.5  # seconds
        
    def increment_attempts(self):
        with self.attempts.get_lock():
            self.attempts.value += 1
            
    def get_attempts(self):
        return self.attempts.value
    
    def record_metrics(self):
        """Record current CPU metrics"""
        cpu_freqs = []
        for cpu in range(psutil.cpu_count()):
            try:
                freq = psutil.cpu_freq(percpu=True)
                if freq:
                    cpu_freqs.append(freq[cpu].current)
            except Exception:
                pass
                
        self.cpu_freqs.append(cpu_freqs)
        
        # Try to get CPU temperatures if available
        try:
            temps = psutil.sensors_temperatures()
            if 'coretemp' in temps:
                self.cpu_temps.append([t.current for t in temps['coretemp']])
        except Exception:
            pass
            
    def calculate_statistics(self, duration):
        """Calculate final statistics"""
        total_attempts = self.get_attempts()
        keys_per_second = total_attempts / duration
        
        # Calculate CPU frequency statistics
        freq_stats = {
            'min': min(min(f) for f in self.cpu_freqs if f),
            'max': max(max(f) for f in self.cpu_freqs if f),
            'avg': sum(sum(f)/len(f) for f in self.cpu_freqs if f) / len(self.cpu_freqs)
        } if self.cpu_freqs and any(f for f in self.cpu_freqs) else {}
        
        # Calculate temperature statistics if available
        temp_stats = {
            'min': min(min(t) for t in self.cpu_temps if t),
            'max': max(max(t) for t in self.cpu_temps if t),
            'avg': sum(sum(t)/len(t) for t in self.cpu_temps if t) / len(self.cpu_temps)
        } if self.cpu_temps and any(t for t in self.cpu_temps) else {}
        
        return {
            'total_attempts': total_attempts,
            'duration': duration,
            'keys_per_second': keys_per_second,
            'keys_per_second_per_worker': keys_per_second / multiprocessing.cpu_count(),
            'cpu_frequency_mhz': freq_stats,
            'cpu_temperature_c': temp_stats
        }

def handle_rsa_vanity(args):
    """Handle RSA vanity key generation"""
    print(f"Generating RSA vanity key with text: {args.rsa_vanity}")
    
    try:
        generator = RSAVanityKeyGenerator(
            args.email, 
            args.rsa_vanity, 
            args.key_bits,
            args.optimize,
            args.similarity
        )
        
        privkey, pubkey = generator.generate_key()
        
        # Save the key
        safe_vanity = re.sub(r'[^a-zA-Z0-9]', '_', args.rsa_vanity)
        keyfile = f"vanity_key-rsa-{safe_vanity}_{int(time.time())}"
        with open(keyfile, 'w') as f:
            f.write(privkey)
        with open(f"{keyfile}.pub", 'w') as f:
            f.write(pubkey)
            
        print(f"\nGenerated RSA key with vanity text: {args.rsa_vanity}")
        print(f"Key saved as: {keyfile}")
        print(f"Public key: {pubkey}")
        
        # Test the key to make sure it's valid
        print("\nTesting key validity...")
        test_key(privkey, pubkey)
        print("Key successfully validated!")
        
        return True
    except Exception as e:
        print(f"Error generating RSA vanity key: {str(e)}")
        return False

def test_key(priv_pem, pub_ssh):
    """Test that the generated key is valid and works for encryption/signing"""
    # Load the private key
    priv_key = serialization.load_pem_private_key(
        priv_pem.encode(),
        password=None
    )
    
    # Load the public key
    pub_key = serialization.load_ssh_public_key(
        pub_ssh.split()[0:2].encode()  # Remove comment part
    )
    
    # Test encryption/decryption
    test_message = b"Test message for encryption"
    ciphertext = pub_key.encrypt(
        test_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    plaintext = priv_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    if plaintext != test_message:
        raise ValueError("Encryption/decryption test failed")
    
    # Test signing/verification
    signature = priv_key.sign(
        test_message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    try:
        pub_key.verify(
            signature,
            test_message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except Exception:
        raise ValueError("Signature verification failed")

def add_rsa_vanity_arguments(parser):
    rsa_vanity_group = parser.add_argument_group('RSA Vanity Injection')
    rsa_vanity_group.add_argument(
        '-rp', '--rsa-vanity', metavar='vanity_str',
        help='Generate RSA key with specific vanity text injected at start of key'
    )
    rsa_vanity_group.add_argument(
        '-O', '--optimize',
        action='store_true',
        help='Suggest optimized variations of the vanity text for faster generation'
    )
    rsa_vanity_group.add_argument(
        '-st', '--similarity', metavar="{0.0,1.0}",
        type=float,
        default=0.7,
        help='Minimum visual similarity for optimized variations (0.0-1.0)'
    )
    

def add_palindrome_arguments(parser):
    """Add palindrome-related arguments to the argument parser"""
    palindrome_group = parser.add_argument_group('Palindrome options')
    
    # Main palindrome options - mutually exclusive
    pal_type = palindrome_group.add_mutually_exclusive_group()
    pal_type.add_argument(
        '-pl', '--palindrome-length', metavar="{0,22}",
        type=int,
        help='Generate any palindrome of this total length'
    )
    pal_type.add_argument(
        '-ps', '--palindrome-start', metavar="vanity_str",
        help='Generate a palindrome starting with these characters'
    )
    
    # Additional palindrome options
    palindrome_group.add_argument(
        '-ui', '--use-free-i',
        action='store_true',
        help='Use the guaranteed "I" character as part of the palindrome'
    )
    palindrome_group.add_argument(
        '-pc', '--palindrome-case-sensitive', 
        action='store_true',
        help='Make palindrome matching case-sensitive'
    )


def collect_patterns(args):
    """Collect all patterns from arguments including palindromes"""
    patterns = []
    
    # Handle regular patterns
    if args.anywhere_pattern:
        for p in args.anywhere_pattern:
            patterns.append(PatternSpec(p, 'anywhere', args.case_sensitive_anywhere, args.key_type))
            
    if args.start_pattern:
        for p in args.start_pattern:
            patterns.append(PatternSpec(p, 'start', args.case_sensitive_start, args.key_type))
            
    if args.end_pattern:
        for p in args.end_pattern:
            patterns.append(PatternSpec(p, 'end', args.case_sensitive_end, args.key_type))
    
    # Handle palindrome patterns
    if args.palindrome_length:
        if args.use_free_i:
            length = args.palindrome_length - 2
            if length < 1:
                raise ValueError("Palindrome length must be at least 3 when using guaranteed I")
            pattern = 'I' + generate_palindrome_pattern(length) + 'I'
        else:
            pattern = generate_palindrome_pattern(args.palindrome_length)
        patterns.append(PatternSpec(pattern, 'anywhere', args.palindrome_case_sensitive, args.key_type))
            
    elif args.palindrome_start:
        start_chars = args.palindrome_start
        if args.use_free_i and not start_chars.startswith('I'):
            start_chars = 'I' + start_chars
            
        # Generate captures for the start characters
        pattern = ''.join(f'({c})' for c in start_chars)
        # Add backreferences in reverse
        pattern += ''.join(f'\\{i}' for i in range(len(start_chars), 0, -1))
        patterns.append(PatternSpec(pattern, 'anywhere', args.palindrome_case_sensitive, args.key_type))
    
    if not patterns:
        raise ValueError("At least one pattern or palindrome must be specified")
        
    return patterns

def test_injection_position(vanity_text, injection_positions, iterations=10):
    results = {}
    for pos in injection_positions:
        timings = []
        for _ in range(iterations):
            generator = RSAVanityKeyGenerator(
                email="test@example.com",
                vanity_text=vanity_text,
                key_bits=2048,
                injection_pos=pos
            )
            start = time.time()
            try:
                # Only timing the generation (which includes key validation)
                generator.generate_key()
            except Exception as e:
                print(f"Error at injection position {pos}: {e}")
                continue
            timings.append(time.time() - start)
        if timings:
            avg_time = statistics.mean(timings)
            results[pos] = avg_time
            print(f"Injection position {pos}: average time = {avg_time:.2f} seconds over {len(timings)} runs")
    return results


def main():
    parser = argparse.ArgumentParser(
#        description="Vanity SSH key generation with complex pattern matching",
#        usage='%(prog)s [options]'
    )
    parser.add_argument(
        '-e', '--email', metavar="email/comment",
        #required=True,
        help='Email address for key comment'
    )
    
    pattern_group = parser.add_argument_group('Vanity Pattern options')
    # Pattern group arguments
    pattern_group.add_argument(
        '-ap', '--anywhere-pattern',  metavar='vanity_str',
        action='append',
        help='Pattern to match anywhere in the key'
    )
    pattern_group.add_argument(
        '-sp', '--start-pattern',  metavar='vanity_str',
        action='append',
        help='Pattern that must match at start of key'
    )
    pattern_group.add_argument(
        '-ep', '--end-pattern', metavar='vanity_str',
        action='append',
        help='Pattern that must match at end of key'
    )
    
    # Case sensitivity can be specified per pattern group
    pattern_group.add_argument(
        '-ca', '--case-sensitive-anywhere', 
        action='store_true',
        help='Make anywhere patterns case-sensitive'
    )
    pattern_group.add_argument(
        '-cs', '--case-sensitive-start', 
        action='store_true',
        help='Make start patterns case-sensitive'
    )
    pattern_group.add_argument(
        '-ce', '--case-sensitive-end',
        action='store_true',
        help='Make end patterns case-sensitive'
    )
    
    add_rsa_vanity_arguments(parser)
    add_palindrome_arguments(parser)
    
    keygen_group = parser.add_argument_group('Key Generation options')
    # Key generation options
    keygen_group.add_argument(
        '-t', '--key-type',
        choices=['ed25519', 'rsa'],
        default='ed25519',
        help='Type of key to generate'
    )
    keygen_group.add_argument(
        '-b', '--key-bits', metavar="bits",
        type=int,
        default=2048,
        help='Bits for RSA key (ignored for ed25519)'
    )

    parser.add_argument(
        '-n', '--processes', metavar="numproc",
        type=int,
        default=None,
        help='Number of worker processes to use'
    )
    parser.add_argument(
        '-l', '--logfile', type=ascii, metavar="logfile",
        help='Output file for generation results (JSON)'
    )
    
    args = parser.parse_args()
    
    # Check if we're in RSA vanity injection mode
    if args.rsa_vanity:
        success = handle_rsa_vanity(args)
        return 0 if success else 1
    
    # Normal pattern matching mode
    try:
        patterns = collect_patterns(args)
    except ValueError as e:
        parser.error(str(e))
    
    generation = VanityKeyGeneration(
        args.email,
        patterns,
        args.key_type,
        args.key_bits
    )
    
    print(f"Starting generation with {args.processes or multiprocessing.cpu_count()} processes...")
    
    result, generation_results = generation.run_generation(args.processes)

    # Print summary
    print("\nGeneration Results:")
    print(f"Found matching key in {generation_results['performance_metrics']['duration']:.2f} seconds")
    print(f"Total attempts: {generation_results['performance_metrics']['total_attempts']}")
    print(f"Keys per second: {generation_results['performance_metrics']['keys_per_second']:.2f}")
    print(f"Keys per second per worker: {generation_results['performance_metrics']['keys_per_second_per_worker']:.2f}")
    
    if generation_results['performance_metrics']['cpu_frequency_mhz']:
        freq = generation_results['performance_metrics']['cpu_frequency_mhz']
        print(f"\nCPU Frequency (MHz):")
        print(f"  Min: {freq['min']:.0f}")
        print(f"  Max: {freq['max']:.0f}")
        print(f"  Avg: {freq['avg']:.0f}")
        
    if generation_results['performance_metrics']['cpu_temperature_c']:
        temp = generation_results['performance_metrics']['cpu_temperature_c']
        print(f"\nCPU Temperature (°C):")
        print(f"  Min: {temp['min']:.1f}")
        print(f"  Max: {temp['max']:.1f}")
        print(f"  Avg: {temp['avg']:.1f}")
    
    print(f"\nMatching Key:")
    print(f"Public key: {result['public']}")
    print(f"Matched pattern '{result['match']}' at position {result['match_position']}")
    print(f"Found by worker {result['worker_id']} (PID: {result['process_id']})")
    
    if args.logfile:
        with open(args.logfile, 'w') as f:
            json.dump(generation_results, f, indent=2)
        print(f"\nDetailed generation results saved to: {args.logfile}")


if __name__ == '__main__':
#    main()
    import time
    import statistics
    positions = list(range(40, 60))  # for example, testing positions 40 through 59
    test_vanity = "AB"
    results = test_injection_position(test_vanity, positions, iterations=20)
