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
        
        self.stats = {
            'attempts': 0,
            'start_time': None
        }
        
    def _load_wordlist(self, wordlist_path, min_word_length):
        """Load wordlist into a set for efficient lookup"""
        with open(wordlist_path) as f:
            words = {word.strip() for word in f 
                    if len(word.strip()) >= min_word_length}
        return words

    def _check_wordlist_match(self, key_part, words, anchor, case_sensitive):
        """Check if any word from wordlist matches according to anchor rules"""
        if not case_sensitive:
            key_part = key_part.lower()
            # Create lowercase version of words if needed
            words = {w.lower() for w in words}

        for word in words:
            if anchor == 'start' and key_part.startswith(word):
                return word, (0, len(word))
            elif anchor == 'end' and key_part.endswith(word):
                return word, (len(key_part) - len(word), len(key_part))
            elif anchor == 'both' and key_part == word:
                return word, (0, len(word))
            elif anchor == 'anywhere' and word in key_part:
                pos = key_part.index(word)
                return word, (pos, pos + len(word))
        return None, None

    def generate_key(self, pattern=None, anchor='anywhere', case_sensitive=False, 
                     wordlist=None, min_word_length=4):
        """Generate keys until criteria are met"""
        self.stats['start_time'] = time.time()
        threads = []
        
        # Handle regex pattern if provided
        compiled_pattern = None
        if pattern:
            if anchor == 'start':
                pattern = '^' + pattern
            elif anchor == 'end':
                pattern = pattern + '$'
            elif anchor == 'both':
                pattern = '^' + pattern + '$'
            flags = 0 if case_sensitive else re.IGNORECASE
            compiled_pattern = re.compile(pattern, flags)
            
        # Load wordlist if provided
        wordlist_words = None
        if wordlist:
            wordlist_words = self._load_wordlist(wordlist, min_word_length)
            if not wordlist_words:
                raise ValueError("No valid words found in wordlist")
                
        if not (compiled_pattern or wordlist_words):
            raise ValueError("No pattern or wordlist specified")
            
        # Start worker threads
        for i in range(self.workers):
            t = threading.Thread(
                target=self._key_worker,
                args=(i, compiled_pattern, wordlist_words, anchor, case_sensitive),
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
        
    def _key_worker(self, worker_id, pattern, wordlist_words, anchor, case_sensitive):
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
            
            # Extract the key portion
            key_part = pubkey.split()[1]
            
            # Update statistics
            with threading.Lock():
                self.stats['attempts'] += 1
            
            # Check for matches
            match_word = None
            match_pos = None
            
            # Check regex pattern if provided
            if pattern:
                match = pattern.search(key_part)
                if match:
                    match_word = match.group(0)
                    match_pos = match.span()
            
            # Check wordlist if provided and no regex match found
            if wordlist_words and not match_word:
                match_word, match_pos = self._check_wordlist_match(
                    key_part, wordlist_words, anchor, case_sensitive
                )
            
            if match_word:
                self.result_queue.put({
                    'public': pubkey,
                    'private': privkey,
                    'matched_part': key_part,
                    'match': match_word,
                    'match_position': match_pos
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
        help='Where to anchor the pattern or wordlist matches'
    )
    parser.add_argument(
        '--case-sensitive', '-c',
        action='store_true',
        help='Make pattern and wordlist matching case-sensitive'
    )
    parser.add_argument(
        '--wordlist', '-w',
        help='Path to wordlist file for finding embedded words'
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
    
    if not (args.pattern or args.wordlist):
        parser.error("Either --pattern or --wordlist must be specified")
    
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
