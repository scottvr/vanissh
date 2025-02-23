#!/usr/bin/env python3
import subprocess
import re
import argparse
from pathlib import Path
import threading
import queue
import time

class VanityKeyGenerator:
    def __init__(self, email, output_dir=None, workers=4, key_type='ed25519', key_bits=2048):
        self.email = email
        self.output_dir = Path(output_dir) if output_dir else Path.cwd()
        self.workers = workers
        self.key_type = key_type
        self.key_bits = key_bits
        self.found_key = threading.Event()
        self.result_queue = queue.Queue()
        
        # Track statistics
        self.stats = {
            'attempts': 0,
            'start_time': None
        }
        
    def generate_key(self, prefix=None, suffix=None, wordlist=None, min_word_length=4):
        """Generate keys until criteria are met"""
        threads = []
        
        # Load wordlist if provided
        target_words = set()
        if wordlist:
            with open(wordlist) as f:
                target_words = {word.strip().lower() for word in f 
                              if len(word.strip()) >= min_word_length}
        
        # Start worker threads
        for i in range(self.workers):
            t = threading.Thread(
                target=self._key_worker,
                args=(i, prefix, suffix, target_words),
                daemon=True
            )
            threads.append(t)
            t.start()
            
        # Wait for a result
        result = self.result_queue.get()
        self.found_key.set()  # Signal other threads to stop
        
        # Save the winning key
        keyfile = self.output_dir / f"vanity_key_{int(time.time())}"
        with open(keyfile, 'w') as f:
            f.write(result['private'])
        with open(f"{keyfile}.pub", 'w') as f:
            f.write(result['public'])
            
        return result, keyfile
    
    def _key_worker(self, worker_id, prefix, suffix, target_words):
        """Worker thread to generate and test keys"""
        while not self.found_key.is_set():
            # Generate a new key pair
            key_file = f"temp_key_{worker_id}"
            cmd = ['ssh-keygen']
            
            if self.key_type == 'ed25519':
                cmd.extend(['-t', 'ed25519'])
            else:  # RSA
                cmd.extend([
                    '-t', 'rsa',
                    '-b', str(self.key_bits)
                ])
                
            cmd.extend([
                '-f', key_file,
                '-C', self.email,
                '-N', '',
                '-q'  # Quiet mode
            ])
            
            subprocess.run(cmd)
            
            # Update statistics
            with threading.Lock():
                self.stats['attempts'] += 1
            
            # Read the public key
            with open(f"{key_file}.pub") as f:
                pubkey = f.read().strip()
            with open(key_file) as f:
                privkey = f.read()
                
            # Clean up temporary files
            Path(key_file).unlink()
            Path(f"{key_file}.pub").unlink()
            
            # Extract the key portion (between ssh-ed25519 and the email)
            key_part = pubkey.split()[1]
            
            # Check if key matches criteria
            if self._matches_criteria(key_part, prefix, suffix, target_words):
                self.result_queue.put({
                    'public': pubkey,
                    'private': privkey,
                    'matched_part': key_part
                })
                break
    
    def _matches_criteria(self, key_part, prefix, suffix, target_words, pattern=None):
        """Check if key matches any of the specified criteria"""
        if prefix and not key_part.startswith(prefix):
            return False
            
        if suffix and not key_part.endswith(suffix):
            return False
            
        if pattern:
            import re
            if not re.search(pattern, key_part):
                return False
                
        if target_words:
            # Look for any target word in the key
            key_lower = key_part.lower()
            for word in target_words:
                if word in key_lower:
                    return True
            if target_words:  # If we had words but found none
                return False
            
        # If we got here and had any criteria, we matched them all
        return True if (prefix or suffix or pattern or target_words) else False

def main():
    parser = argparse.ArgumentParser(
        description="Generate SSH ED25519 keys with memorable patterns"
    )
    parser.add_argument(
        '--email', '-e',
        required=True,
        help='Email address for key comment'
    )
    parser.add_argument(
        '--prefix', '-p',
        help='Desired prefix for the key'
    )
    parser.add_argument(
        '--suffix', '-s',
        help='Desired suffix for the key'
    )
    parser.add_argument(
        '--wordlist', '-w',
        help='Path to wordlist file for finding embedded words'
    )
    parser.add_argument(
        '--min-word-length', '-l',
        type=int, default=4,
        help='Minimum length for matching words'
    )
    parser.add_argument(
        '--output-dir', '-o',
        help='Directory to store generated keys'
    )
    parser.add_argument(
        '--workers', '-n',
        type=int, default=4,
        help='Number of worker threads'
    )
    parser.add_argument(
        '--key-type', '-t',
        choices=['ed25519', 'rsa'],
        default='ed25519',
        help='Type of key to generate'
    )
    parser.add_argument(
        '--key-bits', '-b',
        type=int,
        default=2048,
        help='Bits for RSA key (ignored for ed25519)'
    )
    
    args = parser.parse_args()
    
    generator = VanityKeyGenerator(
        args.email,
        args.output_dir,
        args.workers
    )
    
    print("Generating vanity SSH key...")
    start_time = time.time()
    
    result, keyfile = generator.generate_key(
        args.prefix,
        args.suffix,
        args.wordlist,
        args.min_word_length
    )
    
    elapsed = time.time() - start_time
    
    print(f"\nFound matching key in {elapsed:.2f} seconds!")
    print(f"Key files saved as: {keyfile}")
    print(f"Public key: {result['public']}")
    print(f"Matched pattern: {result['matched_part']}")

if __name__ == '__main__':
    main()
