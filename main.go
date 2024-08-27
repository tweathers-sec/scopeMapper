package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
)

type Result struct {
	Domain string `json:"domain" xml:"domain"`
	IP     string `json:"ip" xml:"ip"`
}

func main() {
	// Define custom usage message
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Domain Scope Checker v1.0\n")
		fmt.Fprintf(os.Stderr, "Author: tweathers-sec\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}

	// Define command-line flags
	inScopeIPsFile := flag.String("ips", "", "File containing in-scope IP addresses/CIDRs")
	potentialDomainsFile := flag.String("domains", "", "File containing potential in-scope vhosts/subdomains")
	outputFile := flag.String("output", "", "Output file name")
	outputFormat := flag.String("format", "txt", "Output format (txt, json, xml, csv)")
	flag.Parse()

	// Read in-scope hosts
	inScopeHosts, err := readLines(*inScopeIPsFile)
	if err != nil {
		fmt.Println("Error reading in-scope IPs file:", err)
		return
	}

	// Read potential domains
	potentialDomains, err := readLines(*potentialDomainsFile)
	if err != nil {
		fmt.Println("Error reading potential domains file:", err)
		return
	}

	// Process domains and check if they're in scope
	var results []Result
	for _, domain := range potentialDomains {
		ips, err := net.LookupIP(domain)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if isInScope(ip.String(), inScopeHosts) {
				results = append(results, Result{Domain: domain, IP: ip.String()})
				break
			}
		}
	}

	// Output results
	if *outputFile != "" {
		err = writeResults(results, *outputFile, *outputFormat)
		if err != nil {
			fmt.Println("Error writing output:", err)
			return
		}
	} else {
		for _, result := range results {
			fmt.Printf("%s,%s\n", result.Domain, result.IP)
		}
	}
}

func readLines(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, strings.TrimSpace(scanner.Text()))
	}
	return lines, scanner.Err()
}

func isInScope(ip string, inScopeHosts []string) bool {
	for _, host := range inScopeHosts {
		if strings.Contains(host, "/") {
			_, ipnet, err := net.ParseCIDR(host)
			if err != nil {
				continue
			}
			if ipnet.Contains(net.ParseIP(ip)) {
				return true
			}
		} else if ip == host {
			return true
		}
	}
	return false
}

func writeResults(results []Result, filename, format string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	switch format {
	case "txt":
		for _, result := range results {
			fmt.Fprintf(file, "%s,%s\n", result.Domain, result.IP)
		}
	case "json":
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(results)
	case "xml":
		encoder := xml.NewEncoder(file)
		encoder.Indent("", "  ")
		err = encoder.Encode(struct {
			Results []Result `xml:"result"`
		}{results})
	case "csv":
		writer := csv.NewWriter(file)
		err = writer.Write([]string{"Domain", "IP"})
		if err != nil {
			return err
		}
		for _, result := range results {
			err = writer.Write([]string{result.Domain, result.IP})
			if err != nil {
				return err
			}
		}
		writer.Flush()
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}

	return err
}
