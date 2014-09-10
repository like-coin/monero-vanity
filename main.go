package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	//"io"
	"os"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	//"code.google.com/p/go.crypto/openpgp"
	//"code.google.com/p/go.crypto/openpgp/packet"
	"github.com/conformal/fastsha256"

	"github.com/ehmry/monero"
	"github.com/ehmry/monero/base58"
	"github.com/ehmry/monero/crypto"
)

const version = "1.0"

const blockSize = 11 // full base58 comes in blocks of 11 characters

var (
	bench            bool
	skip, numWorkers int
	convert, pgpFn   string
	duration         time.Duration
	blockCount       int

	res   []*regexp.Regexp
	flags *flag.FlagSet

	// fastest hash I could find with a 256 bit output
	newHash = fastsha256.New
)

func die(format string, msg ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", msg...)
	os.Exit(1)
}

func init() {

}

func main() {
	flags = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flags.BoolVar(&bench, "bench", false, "run performance benchmark")
	flags.IntVar(&blockCount, "blocks", 1, "match against the first N blocks of 11 base58 characters")
	flags.StringVar(&convert, "convert", "", "convert a hex secret key to a mnemonic seed")
	flags.IntVar(&skip, "skip", 2, "skip the first N characters when matching regexps")
	flags.DurationVar(&duration, "stop", 0, "give up after the given duration")
	flags.IntVar(&numWorkers, "threads", runtime.NumCPU(), "number of workers to start")
	//flags.StringVar(&pgpFn, "pgp", "", "encrypt result to the PGP key in the following file")

	flags.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s-%s:\n\n\t%s FLAGS REGEX1 [REGEX2 ...]\n\n", os.Args[0], version, os.Args[0])
		flags.PrintDefaults()
	}

	flags.Parse(os.Args[1:])
	args := flags.Args()

	if convert != "" {
		b, err := hex.DecodeString(convert)
		if err != nil {
			die(err.Error())
		}
		words, err := monero.BytesToWords(b)
		if err != nil {
			die("Error: could not convert key, %s", err)
		}
		fmt.Fprintln(os.Stdout, strings.Join(words, " "))
		os.Exit(0)
	}

	if len(args) < 1 {
		die("Error: atleast one regular expression must be specified")
	}

	res = make([]*regexp.Regexp, len(args))
	var err error
	for i, arg := range args {
		res[i], err = regexp.Compile(arg)
		if err != nil {
			die("invalid regexp %q, %s", arg, err)
		}
	}

	if bench {
		r := testing.Benchmark(benchmark)
		fmt.Fprintln(os.Stdout, r)
		os.Exit(0)
	}

	//var resultW io.WriteCloser
	//if pgpFn != "" {
	//	var e *openpgp.Entity
	//	fr, err := os.Open(pgpFn)
	//	if err == nil {
	//		e, err = openpgp.ReadEntity(packet.NewReader(fr))
	//	}
	//	if err != nil {
	//		die("Error: could not read PGP key,", err)
	//	}
	//	resultW, err = openpgp.Encrypt(os.Stdout, []*openpgp.Entity{e}, nil, nil, nil)
	//	if err != nil {
	//		die("Error: cannot encrypt to %s, %s", e, err)
	//	}
	//} else {
	//	resultW = os.Stdout
	//}

	c := make(chan *[32]byte, 1)
	for i := 0; i < numWorkers; i++ {
		go worker(c)
	}

	var seed *[32]byte

	if duration != 0 {
		select {
		case <-time.After(duration):
			os.Exit(0)
		case seed = <-c:
			break
		}
	} else {
		seed = <-c
	}

	a, _ := monero.RecoverAccount(*seed)

	fmt.Fprintf(os.Stdout, "%s %x\n", a, seed[:])

	//resultW.Close()
	//rand.Read(seed[:]) // trash this buffer
	os.Exit(0)
}

func benchmark(b *testing.B) {
	var seed, secret, public [32]byte

	slice := seed[:]

	enc := make([]byte, blockSize*blockCount)
	raw := make([]byte, 8*blockCount)
	raw[0] = 0x12 // the network tag

	h := newHash()
	for i := 0; i < b.N; i++ {
		crypto.SecretFromSeed(&secret, &seed)
		crypto.PublicFromSecret(&public, &secret)

		// need to encode base58 in multiples of 8 bytes
		copy(raw[1:], public[:7])
		base58.Encode(enc, raw)

		for _, re := range res {
			re.Match(enc[skip:])
		}

		h.Write(slice)
		h.Sum(slice[:0])
	}
}

func worker(c chan *[32]byte) {
	var seed, secret, public [32]byte

	slice := seed[:]
	rand.Read(slice)

	enc := make([]byte, blockSize*blockCount)
	raw := make([]byte, 8*blockCount)
	raw[0] = 0x12 // the network tag

	h := newHash()
	for {
		crypto.SecretFromSeed(&secret, &seed)
		crypto.PublicFromSecret(&public, &secret)

		// need to encode multiples of 8 bytes
		copy(raw[1:], public[:7])
		base58.Encode(enc, raw)

		for _, re := range res {
			if re.Match(enc[skip:]) {
				// clean hash state
				//h.Write(slice)
				//h.Sum(slice[:0])
				//h.Write(slice)

				c <- &secret
				return
			}
		}
		h.Write(slice)
		h.Sum(slice[:0])
	}
}
