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
        
    def _compile_pattern(self, pattern, anchor, case_sensitive, wordlist, min_word_length):
        """Compile regex pattern from various inputs"""
        patterns = []
        
        # Add user-specified pattern if provided
        if pattern:
            patterns.append(pattern)
            
        # Add wordlist patterns if provided
        if wordlist:
            with open(wordlist) as f:
                words = {word.strip() for word in f 
                        if len(word.strip()) >= min_word_length}
                # Escape special regex chars in words
                words = {re.escape(word) for word in words}
                if words:
                    patterns.append(f"({'|'.join(words)})")
                    
        if not patterns:
            raise ValueError("No pattern specified (use --pattern or --wordlist)")
            
        # Combine patterns with OR
        combined = '|'.join(f'({p})' for p in patterns)
        
        # Apply anchoring
        if anchor == 'start':
            combined = '^' + combined
        elif anchor == 'end':
            combined = combined + '$'
        elif anchor == 'both':
            combined = '^' + combined + '$'
        # 'anywhere' needs no anchors
        
        # Compile with case sensitivity flag
        flags = 0 if case_sensitive else re.IGNORECASE
        return re.compile(combined, flags)
        
    def generate_key(self, pattern=None, anchor='anywhere', case_sensitive=False, 
                     wordlist=None, min_word_length=4):
        """Generate keys until criteria are met"""
        self.stats['start_time'] = time.time()
        threads = []
        
        # Compile the regex pattern based on inputs
        compiled_pattern = self._compile_pattern(
            pattern, anchor, case_sensitive, wordlist, min_word_length
        )
        
        # Start worker threads
        for i in range(self.workers):
            t = threading.Thread(
                target=self._key_worker,
                args=(i, compiled_pattern),
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
        
    def _key_worker(self, worker_id, pattern):
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
            
            # Update statistics
            with threading.Lock():
                self.stats['attempts'] += 1
            
            # Try to find match
            match = pattern.search(key_part)
            if match:
                self.result_queue.put({
                    'public': pubkey,
                    'private': privkey,
                    'matched_part': key_part,
                    'match': match.group(0),
                    'match_position': match.span()
                })
                break

def main():
    parser = argparse.ArgumentParser(
        description="Generate SSH keys with vanity patterns"
    )
    parser.add_argument(
        '--email', '-e',
        required=True,
        help='Email address for key comment'
    )
    parser.add_argument(
        '--pattern', '-p',
        help='Regular expression pattern to match in the key'
    )
    parser.add_argument(
        '--anchor', '-a',
        choices=['start', 'end', 'both', 'anywhere'],
        default='anywhere',
        help='Where to anchor the pattern in the key'
    )
    parser.add_argument(
        '--case-sensitive', '-c',
        action='store_true',
        help='Make pattern matching case-sensitive'
    )
    parser.add_argument(
        '--wordlist', '-w',
        help='Path to wordlist file for finding embedded words (will be converted to regex)'
    )
    parser.add_argument(
        '--min-word-length', '-l',
        type=int, default=4,
        help='Minimum length for matching words from wordlist'
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
        args.workers,
        args.key_type,
        args.key_bits
    )
    
    print("Generating vanity SSH key...")
    start_time = time.time()
    
    result, keyfile = generator.generate_key(
        args.pattern,
        args.anchor,
        args.case_sensitive,
        args.wordlist,
        args.min_word_length
    )
    
    elapsed = time.time() - start_time
    attempts = generator.stats['attempts']
    
    print(f"\nFound matching key in {elapsed:.2f} seconds after {attempts} attempts!")
    print(f"Key files saved as: {keyfile}")
    print(f"Public key: {result['public']}")
    print(f"Matched pattern '{result['match']}' at position {result['match_position']}")

if __name__ == '__main__':
    main()
