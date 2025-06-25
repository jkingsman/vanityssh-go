package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/mikesmitty/edkey"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
)

var global_key_regex string
var global_fp_regex string
var global_user_streaming bool
var global_user_help bool

var global_counter int64
var start time.Time
var keyRe *regexp.Regexp
var fpRe *regexp.Regexp
var err error

func init() {
	flag.StringVar(&global_key_regex, "key-regex", "", "regex pattern for public key")
	flag.StringVar(&global_fp_regex, "fp-regex", "", "regex pattern for fingerprint")
	flag.BoolVar(&global_user_streaming, "streaming", false, "Keep processing keys, even after a match")
	flag.BoolVar(&global_user_help, "help", false, "Show help message")
	flag.Parse()

	if global_user_help {
		fmt.Println("SSH Key Generator - Generates ED25519 SSH keys matching regex patterns")
		fmt.Println("\nUsage:")
		fmt.Println("  -key-regex string   Regex pattern for public key")
		fmt.Println("  -fp-regex string    Regex pattern for fingerprint")
		fmt.Println("  -streaming         Keep processing keys, even after a match")
		fmt.Println("  -help              Show this help message")
		fmt.Println("\nNotes:")
		fmt.Println("  - If only one regex is specified, the other is considered as always matching")
		fmt.Println("  - If both are specified, both must match")
		fmt.Println("  - For case-insensitive matching, use (?i) at the start of your regex pattern")
		fmt.Println("    Example: -key-regex '(?i).*abc.*' will match ABC, abc, AbC, etc.")
		os.Exit(0)
	}

	start = time.Now()

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
	}
}

func WaitForCtrlC() {
	var end_waiter sync.WaitGroup
	end_waiter.Add(1)
	var signal_channel chan os.Signal
	signal_channel = make(chan os.Signal, 1)
	signal.Notify(signal_channel, os.Interrupt)
	go func() {
		<-signal_channel
		end_waiter.Done()
	}()
	end_waiter.Wait()
}

func findsshkeys() {
	for {
		global_counter++
		pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
		publicKey, _ := ssh.NewPublicKey(pubKey)
		pemKey := &pem.Block{
			Type:  "OPENSSH PRIVATE KEY",
			Bytes: edkey.MarshalED25519PrivateKey(privKey),
		}
		privateKey := pem.EncodeToMemory(pemKey)

		matchedKey := true // Default to true if no key regex specified
		matchedFp := true  // Default to true if no fp regex specified
		keyStr := getAuthorizedKey(publicKey)
		fpStr := getFingerprint(publicKey)

		// Only check if regex is specified
		if keyRe != nil {
			matchedKey = keyRe.MatchString(keyStr)
		}
		if fpRe != nil {
			matchedFp = fpRe.MatchString(fpStr)
		}

		// Both must match (or be true by default if not specified)
		if matchedKey && matchedFp {
			fmt.Printf("\033[2K\r%s%d", "SSH Keys Processed = ", global_counter)
			fmt.Println("\nTotal execution time", time.Since(start))
			fmt.Printf("%s\n", privateKey)
			fmt.Printf("%s\n", keyStr)
			fmt.Printf("SHA256:%s\n", fpStr)
			if global_user_streaming == false {
				_ = ioutil.WriteFile("id_ed25519", privateKey, 0600)
				_ = ioutil.WriteFile("id_ed25519.pub", []byte(keyStr), 0644)
				os.Exit(0)
			}
		}
	}
}

// Generate a SHA256 fingerprint of a public key
func getFingerprint(key ssh.PublicKey) string {
	h := sha256.New()
	h.Write(key.Marshal())
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// Generate an `authorized_keys` line for a public key
func getAuthorizedKey(key ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
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

	//	input threads, else numcpu
	for i := 1; i <= runtime.NumCPU(); i++ {
		go findsshkeys()
	}

	fmt.Printf("Press Ctrl+C to end\n")

	deleteLine := "\033[2K\r"
	cursorUp := "\033[A"
	avgKeyRate := float64(global_counter)
	oldCounter := global_counter
	oldTime := time.Now()

	for {
		time.Sleep(250 * time.Millisecond)
		relTime := time.Since(oldTime).Seconds()

		// on first run, initialize the moving average with the current rate
		// instead of starting at 0 and taking many seconds to tend towards the
		// actual key rate
		if oldCounter == 0 {
			avgKeyRate = float64(global_counter)
		}

		fmt.Printf("%s%s%s", deleteLine, cursorUp, deleteLine)
		fmt.Printf("SSH Keys Processed = %s\n", humanize.Comma(global_counter))
		fmt.Printf("kKeys/s = %.2f", avgKeyRate/relTime/1000)

		avgKeyRate = expMovingAverage(
			float64(global_counter-oldCounter), avgKeyRate, relTime, 5)
		oldCounter = global_counter
		oldTime = time.Now()
	}

	WaitForCtrlC()
	fmt.Printf("\n")
}
