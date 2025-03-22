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
import statistics
import base64
import logging
import math

from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('vanissh')

# Try to import gmpy2 for faster prime operations
try:
    import gmpy2
    HAVE_GMPY2 = True
except ImportError:
    HAVE_GMPY2 = False
    logger.info("Note: For 10x performance, install gmpy2: pip install gmpy2")

# Base64 characters used in SSH/PEM encoding
BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

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

    @staticmethod
    def calculate_injection_position(key_bits=2048, exponent=65537):
        """Calculate the exact injection position based on key parameters"""
        # only for rsa keys
        # Base position includes 'ssh-rsa ' (8 characters)
        position = 8
        
        # Add header length
        position += len(KeyParser.RSA_HEADER)
        
        # Add exponent encoding length
        exponent_encoding = KeyParser.RSA_EXPONENTS.get(exponent)
        if exponent_encoding:
            position += len(exponent_encoding)
        else:
            logger.warning(f"Unknown exponent {exponent}, injection position may be incorrect")
        
        # Add modulus prefix length
        modulus_prefix = KeyParser.RSA_MODULUS_PREFIXES.get(key_bits)
        if modulus_prefix:
            position += len(modulus_prefix)
        else:
            logger.warning(f"Unknown key size {key_bits}, injection position may be incorrect")
        
        logger.info(f"Calculated injection position for {key_bits}-bit RSA key with e={exponent}: {position}")
        return position


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
                print(f"pattern {self.pattern}")
                raise ValueError(
                    f"Pattern '{self.pattern}' is too long for ed25519 key"
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
    
def calculate_key_entropy(key_type, key_bits, vanity_method=None, prime_candidates=10):
    """
    Calculate the approximate entropy of a key based on its type, size, and generation method.
    Try to implement the learnings done for the README as useful code
    
    Args:
        key_type (str): Either 'ed25519' or 'rsa'
        key_bits (int): Key size in bits
        vanity_method (str, optional): For RSA, the method of prime selection ('closest', 'random', 'exact')
        prime_candidates (int, optional): Number of prime candidates for 'random' method
    """
    # Base entropy of standard keys
    if key_type == 'ed25519':
        standard_entropy = 256  # Ed25519 offers 128 bits of security (256 bits of entropy)
        security_bits = 128
    else:  # RSA
        # Approximate entropy of RSA comes from the two primes
        primes_in_range = key_bits // 2 / math.log2(math.e)  # ln(2^(k/2))
        prime_entropy = math.log2(primes_in_range)
        standard_entropy = 2 * prime_entropy
        # RSA security bits are approximately 1/2 the key size
        security_bits = key_bits / 2
    
    # Calculate entropy reduction for vanity keys
    if vanity_method is None:
        # For standard keys, no reduction
        vanity_entropy = standard_entropy
        entropy_reduction = 0
        reduction_percentage = 0
    elif key_type == 'ed25519':
        # For Ed25519, we're using brute force, so no entropy reduction
        # (the security comes from the difficulty of finding the private key given the public key)
        vanity_entropy = standard_entropy
        entropy_reduction = 0
        reduction_percentage = 0
    else:  # RSA vanity
        # We're fixing one prime (p) and finding another (q) based on the target N
        if vanity_method == 'exact':
            # Brute force approach - no reduction beyond fixing one prime
            vanity_entropy = standard_entropy / 2
            entropy_reduction = standard_entropy / 2
        elif vanity_method == 'random':
            # Random selection from prime_candidates nearby primes
            prime_selection_entropy = math.log2(prime_candidates)
            vanity_entropy = standard_entropy / 2 + prime_selection_entropy
            entropy_reduction = standard_entropy - vanity_entropy
        else:  # 'closest'
            # Deterministic selection of closest prime - lose all entropy from q selection
            vanity_entropy = standard_entropy / 2
            entropy_reduction = standard_entropy / 2
        
        reduction_percentage = (entropy_reduction / standard_entropy) * 100
    
    # Calculate equivalent key size for comparison
    if key_type == 'rsa' and vanity_method is not None:
        # For vanity RSA, calculate what standard RSA key size would have equivalent security
        equivalent_key_bits = int(vanity_entropy * 2)  # Approximate
    else:
        equivalent_key_bits = key_bits
    
    return {
        'key_type': key_type,
        'key_bits': key_bits,
        'standard_entropy': standard_entropy,
        'vanity_entropy': vanity_entropy,
        'entropy_reduction': entropy_reduction,
        'reduction_percentage': reduction_percentage,
        'security_bits': security_bits * (vanity_entropy / standard_entropy) if vanity_method else security_bits,
        'equivalent_key_bits': equivalent_key_bits,
        'vanity_method': vanity_method
    }

def display_entropy_info(entropy_data):
    """Display entropy information in a user-friendly format"""
    print("\nEntropy Information:")
    print(f"  Key type: {entropy_data['key_type'].upper()}")
    print(f"  Key size: {entropy_data['key_bits']} bits")
    
    if entropy_data['vanity_method']:
        print(f"  Vanity method: {entropy_data['vanity_method']}")
        print(f"  Standard entropy: {entropy_data['standard_entropy']:.2f} bits")
        print(f"  Vanity key entropy: {entropy_data['vanity_entropy']:.2f} bits")
        print(f"  Entropy reduction: {entropy_data['entropy_reduction']:.2f} bits" + 
              f" ({entropy_data['reduction_percentage']:.2f}%)")
        print(f"  Approximate security: {entropy_data['security_bits']:.2f} bits")
        print(f"  Equivalent standard key size: {entropy_data['equivalent_key_bits']} bits")
        
        # Provide security recommendations
        recommended_bits = max(entropy_data['equivalent_key_bits'] * 2, 2048)
        if entropy_data['key_bits'] < recommended_bits:
            print(f"\nSecurity Recommendation:")
            print(f"  For equivalent security to a standard key, consider using at least " +
                  f"{recommended_bits} bits instead of {entropy_data['key_bits']} bits.")
    else:
        print(f"  Standard entropy: {entropy_data['standard_entropy']:.2f} bits")
        print(f"  Approximate security: {entropy_data['security_bits']:.2f} bits")

def handle_rsa_vanity_with_entropy(args):
    """Updated handler for RSA vanity key generation with entropy options"""
    logger.info(f"Generating RSA vanity key with text: {args.rsa_vanity}")
    
    # Check if key size is below recommended minimum for vanity keys
    if args.key_bits < args.recommended_rsa_bits:
        logger.warning(f"The requested key size ({args.key_bits} bits) is below the recommended" +
                       f" minimum of {args.recommended_rsa_bits} bits for vanity RSA keys.")
        logger.warning("Consider using a larger key size to compensate for entropy reduction.")
        
        if args.key_bits < args.min_rsa_bits:
            logger.error(f"Key size {args.key_bits} is below minimum {args.min_rsa_bits} for vanity RSA keys.")
            return False
    
    try:
        # If injection position is manually specified, use it
        if args.injection_position:
            logger.info(f"Using manually specified injection position: {args.injection_position}")
            generator = RSAVanityKeyGenerator(
                args.email, 
                args.rsa_vanity, 
                args.key_bits,
                args.optimize,
                args.similarity,
                args.injection_position,
                args.prime_selection,
                args.prime_candidates
            )
        else:
            # Use automatic position calculation
            generator = RSAVanityKeyGenerator(
                args.email, 
                args.rsa_vanity, 
                args.key_bits,
                args.optimize,
                args.similarity,
                prime_selection=args.prime_selection,
                prime_candidates=args.prime_candidates
            )
        
        privkey, pubkey = generator.generate_key()
        
        # Save the key
        safe_vanity = re.sub(r'[^a-zA-Z0-9]', '_', args.rsa_vanity)
        keyfile = f"vanity_key-rsa-{safe_vanity}_{int(time.time())}"
        with open(keyfile, 'w') as f:
            f.write(privkey)
        with open(f"{keyfile}.pub", 'w') as f:
            f.write(pubkey)
            
        logger.info(f"\nGenerated RSA vanity key with text: {args.rsa_vanity}")
        logger.info(f"Key saved as: {keyfile}")
        logger.info(f"Public key: {pubkey}")
        
        # Test the key to make sure it's valid
        logger.info("\nTesting key validity...")
        test_key(privkey, pubkey)
        logger.info("Key successfully validated!")
        
        # Show entropy information if requested
        if args.show_entropy:
            entropy_data = calculate_key_entropy(
                'rsa', 
                args.key_bits, 
                args.prime_selection,
                args.prime_candidates
            )
            display_entropy_info(entropy_data)
        
        return True
    except Exception as e:
        logger.error(f"Error generating RSA vanity key: {str(e)}")
        return False



class RSAVanityKeyGenerator:
    """Generate RSA keys with vanity strings at specified positions"""
    def __init__(self, email, vanity_text, key_bits=2048, optimize=False, 
                 similarity=0.7, injection_pos=None, prime_selection='closest', 
                 prime_candidates=10):
        self.email = email
        self.vanity_text = vanity_text
        self.key_bits = key_bits
        self.optimize = optimize
        self.similarity = similarity
        self.prime_selection = prime_selection
        self.prime_candidates = prime_candidates
    
        # Calculate injection position if not provided
        if injection_pos is None:
            self.injection_pos = KeyParser.calculate_injection_position(key_bits, 65537)
        else:
            self.injection_pos = injection_pos

        logger.info(f"Using injection position: {self.injection_pos} for vanity text: {vanity_text}")

    def is_valid_vanity(self, text=None):
        """Check if vanity text contains only valid base64 characters"""
        if text is None:
            text = self.vanity_text
        return all(c in BASE64_CHARS for c in text)
        
    def analyze_key(self, pub_key_bytes):
        """Analyze a public key's byte structure for debugging"""
        try:
            # Print the binary structure, hex values and base64
            logger.debug("Key bytes (hex): " + pub_key_bytes.hex())
            logger.debug("Key base64: " + base64.b64encode(pub_key_bytes).decode('utf-8'))
            
            # Try to parse specific components if it's an RSA key
            # This is a simplified approach - RSA SSH keys have specific ASN.1 structures
            if b'ssh-rsa' in pub_key_bytes:
                logger.debug("RSA key detected")
                # Find the header, exponent and modulus positions
                parts = pub_key_bytes.split(b' ')
                if len(parts) >= 2:
                    base64_part = parts[1]
                    try:
                        decoded = base64.b64decode(base64_part)
                        logger.debug(f"Decoded key length: {len(decoded)}")
                    except Exception as e:
                        logger.error(f"Error decoding base64: {e}")
            return True
        except Exception as e:
            logger.error(f"Error analyzing key: {e}")
            return False

    def generate_key(self):
        """Generate a valid RSA key with the vanity text"""
        # Check if vanity is valid
        if not self.is_valid_vanity():
            raise ValueError(f"Vanity text '{self.vanity_text}' contains invalid characters")
            
        # If optimization is enabled, find a better variation
        if self.optimize:
            original = self.vanity_text
            candidates = self.generate_optimized_candidates(original)
            logger.info(f"Original vanity: {original}")
            logger.info("Optimized candidates (estimated performance boost):")
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
        logger.info("Generating initial RSA key...")
        priv_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_bits
        )
        
        # Get the original key bytes for analysis
        orig_pub_bytes = priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        )
        logger.info("Original public key structure:")
        self.analyze_key(orig_pub_bytes)

        # Inject vanity string
        logger.info(f"Injecting vanity string: {self.vanity_text}")
        pub_key = self.inject_vanity_ssh(priv_key)
        
        # Get the modified key bytes for analysis
        modified_pub_bytes = pub_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        )
        logger.info("Modified public key structure:")
        self.analyze_key(modified_pub_bytes)

        # Fix the key to make it valid
        logger.info("Making the key mathematically valid (this may take a while)...")
        start_time = time.time()

        try:
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

        except Exception as e:
            logger.error(f"Error creating valid key {e}")
            raise

    def verify_key_functionality(self, key):
        """Verify that the key can be used for basic cryptographic operations"""
        logger.info("Verifying key functionality...")
        
        # Test message
        test_message = b"Test message for verification"
        
        # Test signing and verification
        try:
            signature = key.sign(
                test_message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            key.public_key().verify(
                signature,
                test_message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            logger.info("Signature verification successful")
        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            raise
            
        # Test encryption and decryption
        try:
            ciphertext = key.public_key().encrypt(
                test_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            plaintext = key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            if plaintext != test_message:
                raise ValueError("Decryption result doesn't match original message")
                
            logger.info("Encryption/decryption test successful")
        except Exception as e:
            logger.error(f"Encryption/decryption test failed: {e}")
            raise

    def inject_vanity_ssh(self, priv_key):
        """Embed the vanity text in an SSH-format public key"""
        vanity = self.vanity_text.encode()
        
        # Generate the SSH format public key
        public_key_repr = priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        )

        # Debug - show before injection
        logger.debug(f"Original public key: {public_key_repr}")
        logger.debug(f"Injection position: {self.injection_pos}")
        logger.debug(f"Vanity text to inject: {vanity}")
        
        # Ensure the injection position is within range
        if self.injection_pos >= len(public_key_repr):
            raise ValueError(f"Injection position {self.injection_pos} is beyond key length {len(public_key_repr)}")
        
        # Print what's at the injection position for debugging
        start_pos = max(0, self.injection_pos - 10)
        end_pos = min(len(public_key_repr), self.injection_pos + 10)
        context = public_key_repr[start_pos:end_pos]
        logger.debug(f"Context around injection position: {context}")
        
        # Inject the vanity text
        public_key_repr = (
            public_key_repr[:self.injection_pos] +
            vanity +
            public_key_repr[self.injection_pos + len(vanity):]
        )

        # Debug - show after injection
        logger.debug(f"Modified public key: {public_key_repr}")
        
        try:
            # Try to load the modified key
            pub_key = serialization.load_ssh_public_key(public_key_repr)
            return pub_key
        except Exception as e:
            logger.error(f"Error loading modified key: {e}")
            raise

    def make_valid_rsa_key(self, priv_key, pub_key):
        """Generate a valid private key, with N close to the N from pub_key"""
        try:
            # Extract components from the keys
            n_target = pub_key.public_numbers().n
            e = pub_key.public_numbers().e
            p_orig = priv_key.private_numbers().p
            q_orig = priv_key.private_numbers().q

            logger.debug(f"Target n: {n_target}")
            logger.debug(f"Original p: {p_orig}")
            logger.debug(f"Original q: {q_orig}")

            p = p_orig
            # Find a prime q such that p*q is close to n_target
            target_q = n_target // p 
            logger.debug(f"Target q: {q_target}")

            q = self.close_prime(target_q)
            logger.debug(f"Found close prime q: {q}")
        
            n = p * q
            logger.debug(f"New modulus n: {n}")

            # Compute the private key from p, q, and e
            phi = (p - 1) * (q - 1)
            try:
                d = self.mod_inverse(e, phi)
                iqmp = self.mod_inverse(p, q)
                dmp1 = d % (p - 1)
                dmq1 = d % (q - 1)
            except Exception as e:
                logger.error(f"Error calculating private components")
                raise

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

            valid_key = private_numbers.private_key()
            valid_key.private_numbers() # this raises an error if invalid

            return valid_key

        except Exception as e:
            logger.error(f"error in make_valid_rsa_key(): {e}")
        
    def close_prime(self, n):
        """Find a prime number close to n using the selected method"""
        if self.is_prime(n):
            logger.debug(f"Target value {n} is already prime")
            return n
            
        # Ensure we're working with an odd number
        if n % 2 == 0:
            n += 1
            
        logger.debug(f"Looking for prime near {n} using method: {self.prime_selection}")
        
        if self.prime_selection == 'exact':
            # This is a placeholder - exact method would require a completely different approach
            # that doesn't modify the key at all, just generates keys until one matches the pattern
            logger.warning("Exact prime selection not implemented - falling back to closest")
            self.prime_selection = 'closest'
        
        if self.prime_selection == 'closest':
            # Find the closest prime (deterministic approach)
            offset = 0
            max_offset = 1000000  # Safety limit
            
            while offset < max_offset:
                # Try positive offset first
                if self.is_prime(n + offset):
                    prime = n + offset
                    logger.debug(f"Found closest prime {prime} with +{offset} offset")
                    return prime
                    
                # Then try negative offset
                if offset > 0 and n - offset > 1 and self.is_prime(n - offset):
                    prime = n - offset
                    logger.debug(f"Found closest prime {prime} with -{offset} offset")
                    return prime
                    
                # Move to next odd number
                offset += 2
                
            raise ValueError(f"Could not find any primes within {max_offset} of {n}")
            
        elif self.prime_selection == 'random':
            # Find multiple primes and choose randomly for more entropy
            nearby_primes = []
            offset = 0
            max_offset = 1000000  # Safety limit
            
            while len(nearby_primes) < self.prime_candidates and offset < max_offset:
                # Try positive offset
                if self.is_prime(n + offset):
                    nearby_primes.append(n + offset)
                    logger.debug(f"Found prime {n + offset} with +{offset} offset")
                    
                # Try negative offset
                if offset > 0 and n - offset > 1 and self.is_prime(n - offset):
                    nearby_primes.append(n - offset)
                    logger.debug(f"Found prime {n - offset} with -{offset} offset")
                    
                # Move to next odd number
                offset += 2
                
            if not nearby_primes:
                raise ValueError(f"Could not find any primes within {max_offset} of {n}")
                
            # Choose randomly from the found primes
            prime = random.choice(nearby_primes)
            logger.debug(f"Randomly selected prime {prime} from {len(nearby_primes)} candidates")
            return prime
            
    def is_prime(self, n, k=10):
        """Check if a number is prime."""
        # Basic checks
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0:
            return False
        
        if HAVE_GMPY2:
            return gmpy2.is_prime(n)
        else:
            # Miller-Rabin primality test
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
            try:
                return int(gmpy2.invert(a, m))
            except Exception as e:
                logger.error(f"GMPY2 invert failed: {e}")

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

def add_entropy_arguments(parser):
    """Add entropy calculation related arguments to the argument parser"""
    entropy_group = parser.add_argument_group('Entropy and Security Options')
    entropy_group.add_argument(
        '--show-entropy',
        action='store_true',
        help='Calculate and display entropy information for the generated key'
    )
    entropy_group.add_argument(
        '--prime-selection',
        choices=['closest', 'random', 'exact'],
        default='closest',
        help='Method for selecting primes in RSA vanity keys'
    )
    entropy_group.add_argument(
        '--prime-candidates',
        type=int,
        default=10,
        help='Number of prime candidates to consider when using random selection'
    )
    entropy_group.add_argument(
        '--min-rsa-bits',
        type=int,
        default=2048,
        help='Minimum RSA key size for vanity keys (will warn if below this)'
    )
    entropy_group.add_argument(
        '--recommended-rsa-bits',
        type=int,
        default=3072,
        help='Recommended RSA key size for vanity keys to compensate for entropy loss'
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

def test_injection_position(vanity_text, injection_positions, iterations=10):
    results = {}
    success_rates = {}

    for pos in injection_positions:
        timings = []
        successes = 0
        
        logger.info(f"Testing injection position {pos} with vanity text '{vanity_text}'")
        
        for i in range(iterations):
            logger.info(f"Iteration {i+1}/{iterations} for position {pos}")
            
            generator = RSAVanityKeyGenerator(
                email="test@example.com",
                vanity_text=vanity_text,
                key_bits=2048,
                injection_pos=pos
            )

            start = time.time()
            try:
                priv_pem, pub_ssh = generator.generate_key()
                test_key(priv_pem, pub_ssh)

                elapsed = time.time() - start
                timings.append(elapsed)
                successes += 1

                logger.info(f"Success at position {pos}, iteration {i+1}: {elapsed:.2f} seconds")
                
                # Save successful key for examination
                tmp_keyfile = f"vanity_key-rsa-test-pos{pos}-iter{i+1}_{int(time.time())}"
                with open(tmp_keyfile, 'w') as f:
                    f.write(priv_pem)
                with open(f"{tmp_keyfile}.pub", 'w') as f:
                    f.write(pub_ssh)
                logger.info(f"Test key saved as: {tmp_keyfile}")

            except Exception as e:
                logger.error(f"Error at injection position {pos}, iteration {i+1}: {e}")
                elapsed = time.time() - start
                logger.info(f"Failed after {elapsed:.2f} seconds")

def main():
    parser = argparse.ArgumentParser(
        description="Vanity SSH key generation with complex pattern matching",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
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
    add_entropy_arguments(parser)

    
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
    
    if args.rsa_vanity:
        success = handle_rsa_vanity_with_entropy(args)
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
    
    # If showing entropy was requested
    if args.show_entropy:
        entropy_data = calculate_key_entropy(
            args.key_type, 
            args.key_bits,
            None if args.key_type == 'ed25519' else args.prime_selection,
            args.prime_candidates
        )
        display_entropy_info(entropy_data)
    
    return 0

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
    main()