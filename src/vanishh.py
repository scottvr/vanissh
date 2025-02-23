#!/usr/bin/env python3
import subprocess
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
import os

class KeyParser:
    # Known headers for different key types
    KEY_HEADERS = {
        'ed25519': 'AAAAC3NzaC1lZDI1NTE5AAAA',
        'rsa': 'AAAAB3NzaC1yc2E'
    }
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
        4096: 'AAACAQ'  # Add more as needed
    }

    @staticmethod
    def extract_matchable_portion(pubkey, key_type='ed25519'):
        """Extract only the meaningful portion of the key for pattern matching"""
        parts = pubkey.split()
        if len(parts) < 2:
            return None, None

        base64_part = parts[1]
        base64_part = base64_part.rstrip('=')

        if key_type == 'ed25519':
            if not base64_part.startswith(KeyParser.ED25519_HEADER):
                return None, None
            # For ed25519, everything after header is fair game
            return (
                base64_part[len(KeyParser.ED25519_HEADER):],
                len(KeyParser.ED25519_HEADER)
            )

        elif key_type == 'rsa':
            if not base64_part.startswith(KeyParser.RSA_HEADER):
                return None, None

            # Find where the actual key material starts
            offset = len(KeyParser.RSA_HEADER)

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
            return 43  # 32 bytes in base64 ≈ 43 chars
        elif key_type == 'rsa':
            # This varies by key size, return None to indicate variable length
            return None
        return None

class PatternSpec:
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
            patterns = self.pattern.split('|')

            for p in patterns:
                if len(p) > max_length:
                    raise ValueError(
                        f"Pattern '{p}' is too long for ed25519 key "
                        f"(max {max_length} chars)"
                    )

                # Check if pattern could appear in base64
                if not all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
                          for c in p if c not in '^$'):
                    raise ValueError(
                        f"Pattern '{p}' contains characters that cannot "
                        "appear in base64-encoded data"
                    )

    def compile(self):
        """Compile the pattern with appropriate anchors"""
        # Handle each pattern in the alternation separately
        patterns = self.pattern.split('|')
        
        if self.anchor == 'start':
            patterns = ['^' + p for p in patterns]
        elif self.anchor == 'end':
            patterns = [p + '$' for p in patterns]
        elif self.anchor == 'both':
            patterns = ['^' + p + '$' for p in patterns]
            
        pattern = '|'.join(f'({p})' for p in patterns)
        flags = 0 if self.case_sensitive else re.IGNORECASE
        self._compiled = re.compile(pattern, flags)
        return self._compiled

    def match(self, text):
        """Try to match the pattern against text"""
        if not self._compiled:
            self.compile()
        return self._compiled.search(text)


class VanityKeyBenchmark:
    def __init__(self, email, patterns, key_type='ed25519', key_bits=2048):
        self.email = email
        self.patterns = patterns  # List of PatternSpec objects
        self.key_type = key_type
        self.key_bits = key_bits
        self.found_key = multiprocessing.Event()
        self.result_queue = multiprocessing.Queue()
        self.stats = BenchmarkStats()

    def _key_worker(self, worker_id):
        """Worker process to generate and test keys"""
        while not self.found_key.is_set():
            # Generate a new key pair
            key_file = f"temp_key_{os.getpid()}_{worker_id}"
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
              
            try:
                with open(f"{key_file}.pub") as f:
                    pubkey = f.read().strip()
                with open(key_file) as f:
                    privkey = f.read()
        
                # Extract only the meaningful portion for matching
                key_part = KeyParser.extract_matchable_portion(pubkey, self.key_type)
                if not key_part:
                    continue  # Invalid or unexpected key format

                # Update statistics
                self.stats.increment_attempts()

                # Store original key for reporting
                full_key_part = pubkey.split()[1]

                # Check all patterns against the meaningful portion
                for pattern_spec in self.patterns:
                    match = pattern_spec.match(key_part)
                    if match:
                        # Calculate the actual position in the full base64 string
                        header_len = len(KeyParser.KEY_HEADERS[self.key_type])
                        match_start = match.span()[0] + header_len
                        match_end = match.span()[1] + header_len

                        self.result_queue.put({
                            'public': pubkey,
                            'private': privkey,
                            'matched_part': full_key_part,
                            'match': match.group(0),
                            'match_position': (match_start, match_end),
                            'worker_id': worker_id,
                            'process_id': os.getpid(),
                            'pattern': pattern_spec.pattern,
                            'anchor': pattern_spec.anchor
                        })
                        self.found_key.set()
                        break
            finally:
                # Clean up temporary files
                try:
                    Path(key_file).unlink()
                    Path(f"{key_file}.pub").unlink()
                except FileNotFoundError:
                    pass


    def _metrics_recorder(self):
        """Thread to record performance metrics"""
        while not self.found_key.is_set():
            self.stats.record_metrics()
            time.sleep(self.stats.sampling_interval)
            
    def run_benchmark(self):
        """Run the benchmark with multiple processes"""
        pattern = self._compile_pattern()
        processes = []
        
        # Start metrics recording thread
        metrics_thread = threading.Thread(target=self._metrics_recorder, daemon=True)
        metrics_thread.start()
        
        # Start worker processes
        for i in range(multiprocessing.cpu_count()):
            p = multiprocessing.Process(
                target=self._key_worker,
                args=(i, pattern),
                daemon=True
            )
            processes.append(p)
            p.start()
            
        # Wait for a result
        result = self.result_queue.get()
        duration = time.time() - self.stats.start_time
        
        # Clean up processes
        for p in processes:
            p.terminate()
            
        # Calculate final statistics
        benchmark_stats = self.stats.calculate_statistics(duration)
        
        # Add system information
        system_info = {
            'cpu_model': platform.processor(),
            'cpu_count': multiprocessing.cpu_count(),
            'physical_cores': psutil.cpu_count(logical=False),
            'logical_cores': psutil.cpu_count(logical=True),
            'memory_gb': psutil.virtual_memory().total / (1024**3),
            'platform': platform.platform()
        }
        
        # Combine all results
        benchmark_results = {
            'timestamp': datetime.now().isoformat(),
            'system_info': system_info,
            'benchmark_config': {
                'pattern': self.pattern,
                'anchor': self.anchor,
                'case_sensitive': self.case_sensitive,
                'key_type': self.key_type,
                'key_bits': self.key_bits
            },
            'performance_metrics': benchmark_stats,
            'winning_key': {
                'worker_id': result['worker_id'],
                'process_id': result['process_id'],
                'match': result['match'],
                'match_position': result['match_position']
            }
        }
        
        return result, benchmark_results
    def run_benchmark(self):
        """Run the benchmark with multiple processes"""
        processes = []

        # Start metrics recording thread
        metrics_thread = threading.Thread(target=self._metrics_recorder, daemon=True)
        metrics_thread.start()

        # Start worker processes
        for i in range(multiprocessing.cpu_count()):
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

        # Clean up processes
        for p in processes:
            p.terminate()

        # Calculate final statistics
        benchmark_stats = self.stats.calculate_statistics(duration)

        # Add system information
        system_info = {
            'cpu_model': platform.processor(),
            'cpu_count': multiprocessing.cpu_count(),
            'physical_cores': psutil.cpu_count(logical=False),
            'logical_cores': psutil.cpu_count(logical=True),
            'memory_gb': psutil.virtual_memory().total / (1024**3),
            'platform': platform.platform()
        }

        # Combine all results
        benchmark_results = {
            'timestamp': datetime.now().isoformat(),
            'system_info': system_info,
            'benchmark_config': {
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
            'performance_metrics': benchmark_stats,
            'winning_key': {
                'worker_id': result['worker_id'],
                'process_id': result['process_id'],
                'pattern': result['pattern'],
                'anchor': result['anchor'],
                'match': result['match'],
                'match_position': result['match_position']
            }
        }

        return result, benchmark_results

class BenchmarkStats:
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
        } if self.cpu_freqs else {}
        
        # Calculate temperature statistics if available
        temp_stats = {
            'min': min(min(t) for t in self.cpu_temps if t),
            'max': max(max(t) for t in self.cpu_temps if t),
            'avg': sum(sum(t)/len(t) for t in self.cpu_temps if t) / len(self.cpu_temps)
        } if self.cpu_temps else {}
        
        return {
            'total_attempts': total_attempts,
            'duration': duration,
            'keys_per_second': keys_per_second,
            'keys_per_second_per_worker': keys_per_second / multiprocessing.cpu_count(),
            'cpu_frequency_mhz': freq_stats,
            'cpu_temperature_c': temp_stats
        }
        return result, benchmark_results

def main():
    parser = argparse.ArgumentParser(
        description="Benchmark SSH key generation with complex pattern matching"
    )
    parser.add_argument(
        '--email', '-e',
        required=True,
        help='Email address for key comment'
    )
    
    # Pattern group arguments
    parser.add_argument(
        '--anywhere-pattern', '-ap',
        action='append',
        help='Pattern to match anywhere in the key'
    )
    parser.add_argument(
        '--start-pattern', '-sp',
        action='append',
        help='Pattern that must match at start of key'
    )
    parser.add_argument(
        '--end-pattern', '-ep',
        action='append',
        help='Pattern that must match at end of key'
    )
    parser.add_argument(
        '--exact-pattern', '-xp',
        action='append',
        help='Pattern that must match exactly (both start and end)'
    )
    
    # Case sensitivity can be specified per pattern group
    parser.add_argument(
        '--case-sensitive-anywhere', '-ca',
        action='store_true',
        help='Make anywhere patterns case-sensitive'
    )
    parser.add_argument(
        '--case-sensitive-start', '-cs',
        action='store_true',
        help='Make start patterns case-sensitive'
    )
    parser.add_argument(
        '--case-sensitive-end', '-ce',
        action='store_true',
        help='Make end patterns case-sensitive'
    )
    parser.add_argument(
        '--case-sensitive-exact', '-cx',
        action='store_true',
        help='Make exact patterns case-sensitive'
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
    parser.add_argument(
        '--output', '-o',
        help='Output file for benchmark results (JSON)'
    )
    
    args = parser.parse_args()
    
    # Collect all patterns
    patterns = []
    
    if args.anywhere_pattern:
        for p in args.anywhere_pattern:
            patterns.append(PatternSpec(p, 'anywhere', args.case_sensitive_anywhere))
            
    if args.start_pattern:
        for p in args.start_pattern:
            patterns.append(PatternSpec(p, 'start', args.case_sensitive_start))
            
    if args.end_pattern:
        for p in args.end_pattern:
            patterns.append(PatternSpec(p, 'end', args.case_sensitive_end))
            
    if args.exact_pattern:
        for p in args.exact_pattern:
            patterns.append(PatternSpec(p, 'both', args.case_sensitive_exact))
    
    if not patterns:
        parser.error("At least one pattern must be specified")
    
    benchmark = VanityKeyBenchmark(
        args.email,
        patterns,
        args.key_type,
        args.key_bits
    )
    
    print(f"Starting benchmark with {multiprocessing.cpu_count()} processes...")
    start_time = time.time()
    
    result, benchmark_results = benchmark.run_benchmark()

    # Print summary
    print("\nBenchmark Results:")
    print(f"Found matching key in {benchmark_results['performance_metrics']['duration']:.2f} seconds")
    print(f"Total attempts: {benchmark_results['performance_metrics']['total_attempts']}")
    print(f"Keys per second: {benchmark_results['performance_metrics']['keys_per_second']:.2f}")
    print(f"Keys per second per worker: {benchmark_results['performance_metrics']['keys_per_second_per_worker']:.2f}")
    
    if benchmark_results['performance_metrics']['cpu_frequency_mhz']:
        freq = benchmark_results['performance_metrics']['cpu_frequency_mhz']
        print(f"\nCPU Frequency (MHz):")
        print(f"  Min: {freq['min']:.0f}")
        print(f"  Max: {freq['max']:.0f}")
        print(f"  Avg: {freq['avg']:.0f}")
        
    if benchmark_results['performance_metrics']['cpu_temperature_c']:
        temp = benchmark_results['performance_metrics']['cpu_temperature_c']
        print(f"\nCPU Temperature (°C):")
        print(f"  Min: {temp['min']:.1f}")
        print(f"  Max: {temp['max']:.1f}")
        print(f"  Avg: {temp['avg']:.1f}")
    
    print(f"\nMatching Key:")
    print(f"Public key: {result['public']}")
    print(f"Matched pattern '{result['match']}' at position {result['match_position']}")
    print(f"Found by worker {result['worker_id']} (PID: {result['process_id']})")
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(benchmark_results, f, indent=2)
        print(f"\nDetailed benchmark results saved to: {args.output}")

if __name__ == '__main__':
    main()
