package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"text/template"
	"time"
)

var ipFile = flag.String("file", "", "The path to the file that has the host:port, one per line")

// tmpl is a Go text template. I use this to output your text output.
// template.Must() means it must compile or it crashes, and I create a
// new template that parses the text you see.
var tmpl = template.Must(template.New("").Parse(`
Checking cerificate for server: {{ .Server }}
Version: TLS {{ .TLSVersion }}
Expires On: {{ .ExpiresOn }}
In {{ .ExpireInDays }} days
`,
))

// values are values that the template will receive.
type values struct {
	// Server is the name of the server.
	Server string
	// Port is the TCP port the server listens on.
	Port string
	// ExpiresOn is when the TLS certificate expires.
	ExpiresOn time.Time

	// version is the TLS version number as specified by the TLS spec.
	version uint16
}

// ExpireInDays converts ExpiresOn to the number of days until the cert expires.
func (v values) ExpireInDays() int {
	x := int(time.Until(v.ExpiresOn).Hours()/24)
	if x < 0 {
		x = 0
	}
	return x
}

// Version returns the TLS version as a human readable string.
func (v values) TLSVersion() string {
	switch v.version {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	}
	return "unknown version"
}

// getTLSInfo takes a host:port string, connects via TLS and returns our values. An error is returned
// if we can't connect, TLS is not present, or hostPort is badly formed.
func getTLSInfo(hostPort string) (values, error) {
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return values{}, fmt.Errorf("hostPort must be the DNS hostname or IP address + ':' + port, was %q", hostPort)
	}

	conn, err := tls.Dial("tcp", hostPort, nil)
	if err != nil {
		return values{}, fmt.Errorf("server doesn't support SSL certificate err: %s", err)
	}
	defer conn.Close()

	cs := conn.ConnectionState()
	v := values{
		Server:    host,
		Port:      port,
		ExpiresOn: cs.PeerCertificates[0].NotAfter,
		version:   cs.Version,
	}
	return v, nil
}

func main() {
	// Causes the flags defined to be read in, almost always the first line in main().
	flag.Parse()

	// limit is a limiter that prevents over 100 TLS connections at a time.
	limit := make(chan struct{}, 100)

	// This opens the file at "/path/to/file.txt".
	file, err := os.Open(*ipFile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close() // Close the file when main() ends.

	// We are going to use this to scan the file line by line.
	scanner := bufio.NewScanner(file)
	// wg will let us know when all of our concurrent operations are done.
	wg := sync.WaitGroup{}

	// Scan each line from the file.
	for scanner.Scan() {
		// Trim any space characters from the line and assign it to hostPort.
		hostPort := strings.TrimSpace(scanner.Text())
		if hostPort == "" {
			continue
		}

		// Add a counter for our concurrent operation.
		wg.Add(1)
		limit <- struct{}{} // Only proceed if < 100 operations are in effect.

		// Start a concurrent operation.
		go func() {
			defer wg.Done()            // remove a counter for a concurrent operation when this closes.
			defer func() { <-limit }() // remove a limit when this operation is done.

			// Get our TLS info
			v, err := getTLSInfo(hostPort)
			if err != nil {
				fmt.Printf("%q: error: %s\n", hostPort, err)
				return
			}
			// Render our text to stdout.
			if err := tmpl.Execute(os.Stdout, v); err != nil {
				log.Fatal(err)
			}
		}()
	}

	// Wait for all concurrent operations to end.
	wg.Wait()

	// If we had a problem reading the file, throw a fatal error.
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Finished")
}
