package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"hash"
	"io/ioutil"
	"math"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/mikesmitty/edkey"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
)

var (
	global_key_regex      string
	global_fp_regex       string
	global_user_streaming bool
	global_user_help      bool
	global_workers        int
	global_batch_size     int
	global_buffer_size    int

	global_counter int64
	start          time.Time
	keyRe          *regexp.Regexp
	fpRe           *regexp.Regexp

	// Pool for reusing buffers
	pemBlockPool = sync.Pool{
		New: func() interface{} {
			return &pem.Block{Type: "OPENSSH PRIVATE KEY"}
		},
	}

	sha256Pool = sync.Pool{
		New: func() interface{} {
			return sha256.New()
		},
	}

	// Pre-compiled SSH key prefix for faster matching
	sshKeyPrefix = []byte("ssh-ed25519 ")
)

func init() {
	flag.StringVar(&global_key_regex, "key-regex", "", "regex pattern for public key")
	flag.StringVar(&global_fp_regex, "fp-regex", "", "regex pattern for fingerprint")
	flag.BoolVar(&global_user_streaming, "streaming", false, "Keep processing keys, even after a match")
	flag.BoolVar(&global_user_help, "help", false, "Show help message")
	flag.IntVar(&global_workers, "workers", runtime.NumCPU()*2, "Number of worker goroutines")
	flag.IntVar(&global_batch_size, "batch", 1000, "Keys to process per batch")
	flag.IntVar(&global_buffer_size, "buffer", 64, "Random bytes buffer size in KB")
	flag.Parse()

	if global_user_help {
		fmt.Println("SSH Key Generator - Generates ED25519 SSH keys matching regex patterns")
		fmt.Println("\nUsage:")
		fmt.Println("  -key-regex string   Regex pattern for public key")
		fmt.Println("  -fp-regex string    Regex pattern for fingerprint")
		fmt.Println("  -streaming         Keep processing keys, even after a match")
		fmt.Println("  -workers int       Number of worker goroutines (default: NumCPU*2)")
		fmt.Println("  -batch int         Keys to process per batch (default: 1000)")
		fmt.Println("  -buffer int        Random bytes buffer size in KB (default: 64)")
		fmt.Println("  -help              Show this help message")
		fmt.Println("\nNotes:")
		fmt.Println("  - If only one regex is specified, the other is considered as always matching")
		fmt.Println("  - If both are specified, both must match")
		fmt.Println("  - For case-insensitive matching, use (?i) at the start of your regex pattern")
		fmt.Println("    Example: -key-regex '(?i).*abc.*' will match ABC, abc, AbC, etc.")
		os.Exit(0)
	}

	start = time.Now()

	// Compile regexes
	var err error
	if global_key_regex != "" {
		keyRe, err = regexp.Compile(global_key_regex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid key-regex: %v\n", err)
			os.Exit(1)
		}
	}
	if global_fp_regex != "" {
		fpRe, err = regexp.Compile(global_fp_regex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid fp-regex: %v\n", err)
			os.Exit(1)
		}
	}

	// Only print if at least one regex is specified
	if global_key_regex != "" || global_fp_regex != "" {
		fmt.Println("key-regex =", global_key_regex)
		fmt.Println("fp-regex =", global_fp_regex)
		fmt.Println("workers =", global_workers)
		fmt.Println("batch-size =", global_batch_size)
		fmt.Println("buffer-size =", global_buffer_size, "KB")
	}
}

// Optimized random reader with buffering
type bufferedRandom struct {
	buf []byte
	pos int
	mu  sync.Mutex
}

func newBufferedRandom(size int) *bufferedRandom {
	return &bufferedRandom{
		buf: make([]byte, size*1024), // Convert KB to bytes
	}
}

func (b *bufferedRandom) Read(p []byte) (n int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.pos == 0 {
		// Refill buffer
		_, err = rand.Read(b.buf)
		if err != nil {
			return 0, err
		}
	}

	n = copy(p, b.buf[b.pos:])
	b.pos = (b.pos + n) % len(b.buf)
	return n, nil
}

// Worker function with all optimizations
func findsshkeysBatch(batchSize int, randReader *bufferedRandom) {
	// Pre-allocate all buffers for this worker
	pubKeys := make([]ed25519.PublicKey, batchSize)
	privKeys := make([]ed25519.PrivateKey, batchSize)
	seeds := make([]byte, batchSize*ed25519.SeedSize)

	// Pre-allocate string builder for key generation
	var keyBuilder strings.Builder
	keyBuilder.Grow(128) // Typical SSH key length

	for {
		// Read all random data at once
		randReader.Read(seeds)

		// Generate batch of keys from seeds
		for i := 0; i < batchSize; i++ {
			seed := seeds[i*ed25519.SeedSize : (i+1)*ed25519.SeedSize]
			privKeys[i] = ed25519.NewKeyFromSeed(seed)
			pubKeys[i] = privKeys[i].Public().(ed25519.PublicKey)
		}

		// Process batch
		for i := 0; i < batchSize; i++ {
			atomic.AddInt64(&global_counter, 1)

			// Early exit checks
			matchedKey := keyRe == nil
			matchedFp := fpRe == nil

			var keyStr, fpStr string
			var publicKey ssh.PublicKey

			// Only create SSH public key if we need to check something
			if !matchedKey || !matchedFp {
				publicKey, _ = ssh.NewPublicKey(pubKeys[i])
			}

			// Check key regex if needed
			if !matchedKey {
				keyStr = getAuthorizedKeyFast(publicKey, &keyBuilder)
				matchedKey = keyRe.MatchString(keyStr)
			}

			// Skip fingerprint if key doesn't match
			if matchedKey && !matchedFp {
				fpStr = getFingerprintFast(publicKey)
				matchedFp = fpRe.MatchString(fpStr)
			}

			// Both must match
			if matchedKey && matchedFp {
				// Compute missing values if needed
				if publicKey == nil {
					publicKey, _ = ssh.NewPublicKey(pubKeys[i])
				}
				if keyStr == "" {
					keyStr = getAuthorizedKeyFast(publicKey, &keyBuilder)
				}
				if fpStr == "" {
					fpStr = getFingerprintFast(publicKey)
				}

				// Get a pem.Block from the pool
				pemKey := pemBlockPool.Get().(*pem.Block)
				pemKey.Bytes = edkey.MarshalED25519PrivateKey(privKeys[i])
				privateKey := pem.EncodeToMemory(pemKey)

				// Return pem.Block to pool
				pemBlockPool.Put(pemKey)

				// Output results
				fmt.Printf("\033[2K\r%s%d", "SSH Keys Processed = ", atomic.LoadInt64(&global_counter))
				fmt.Println("\nTotal execution time", time.Since(start))
				fmt.Printf("%s\n", privateKey)
				fmt.Printf("%s\n", keyStr)
				fmt.Printf("SHA256:%s\n", fpStr)

				if !global_user_streaming {
					_ = ioutil.WriteFile("id_ed25519", privateKey, 0600)
					_ = ioutil.WriteFile("id_ed25519.pub", []byte(keyStr), 0644)
					os.Exit(0)
				}
			}
		}
	}
}

// Optimized fingerprint generation using pooled hashers
func getFingerprintFast(key ssh.PublicKey) string {
	h := sha256Pool.Get().(hash.Hash)
	h.Reset()
	h.Write(key.Marshal())
	result := h.Sum(nil)
	sha256Pool.Put(h)
	return base64.StdEncoding.EncodeToString(result)
}

// Optimized authorized key generation with string builder reuse
func getAuthorizedKeyFast(key ssh.PublicKey, builder *strings.Builder) string {
	builder.Reset()
	builder.Write(sshKeyPrefix)
	builder.WriteString(base64.StdEncoding.EncodeToString(key.Marshal()))
	return builder.String()
}

func expMovingAverage(value, oldValue, deltaTime, timeWindow float64) float64 {
	alpha := 1.0 - math.Exp(-deltaTime/timeWindow)
	return alpha*value + (1.0-alpha)*oldValue
}

func main() {
	// Validate that at least one regex is provided
	if global_key_regex == "" && global_fp_regex == "" {
		fmt.Fprintf(os.Stderr, "Error: At least one of -key-regex or -fp-regex must be specified\n")
		fmt.Fprintf(os.Stderr, "Use -help for more information\n")
		os.Exit(1)
	}

	// Performance tuning
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Tune GC for throughput over latency
	debug.SetGCPercent(200) // Less frequent GC

	// Set process priority (Unix-like systems)
	syscall.Setpriority(syscall.PRIO_PROCESS, 0, -10)

	// Create buffered random readers for each worker
	randReaders := make([]*bufferedRandom, global_workers)
	for i := 0; i < global_workers; i++ {
		randReaders[i] = newBufferedRandom(global_buffer_size)
	}

	// Start worker goroutines
	for i := 0; i < global_workers; i++ {
		go findsshkeysBatch(global_batch_size, randReaders[i])
	}

	fmt.Printf("Press Ctrl+C to end\n")

	// Stats display goroutine
	go func() {
		deleteLine := "\033[2K\r"
		cursorUp := "\033[A"
		cursorUp2 := "\033[A\033[A"
		avgKeyRate := float64(0)
		peakKeyRate := float64(0)
		oldCounter := int64(0)
		oldTime := time.Now()

		for {
			time.Sleep(250 * time.Millisecond)

			currentCounter := atomic.LoadInt64(&global_counter)
			relTime := time.Since(oldTime).Seconds()

			if oldCounter == 0 {
				avgKeyRate = float64(currentCounter)
			}

			currentRate := float64(currentCounter-oldCounter) / relTime / 1000
			if currentRate > peakKeyRate {
				peakKeyRate = currentRate
			}

			fmt.Printf("%s%s%s%s", deleteLine, cursorUp2, deleteLine, cursorUp)
			fmt.Printf("SSH Keys Processed = %s (%.2f%%)\n",
				humanize.Comma(currentCounter),
				float64(currentCounter)/float64(1<<64)*100) // Progress through keyspace
			fmt.Printf("kKeys/s = %.2f (avg) | %.2f (current) | %.2f (peak)\n",
				avgKeyRate/relTime/1000, currentRate, peakKeyRate)
			fmt.Printf("Runtime = %s", time.Since(start).Round(time.Second))

			avgKeyRate = expMovingAverage(
				float64(currentCounter-oldCounter), avgKeyRate, relTime, 5)
			oldCounter = currentCounter
			oldTime = time.Now()
		}
	}()

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	// Final stats
	fmt.Printf("\n\nFinal Statistics:\n")
	fmt.Printf("Total keys processed: %s\n", humanize.Comma(atomic.LoadInt64(&global_counter)))
	fmt.Printf("Total runtime: %s\n", time.Since(start))
	fmt.Printf("Average rate: %.2f kKeys/s\n",
		float64(atomic.LoadInt64(&global_counter))/time.Since(start).Seconds()/1000)
}
