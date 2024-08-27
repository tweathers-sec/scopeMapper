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
	"path/filepath"
	"strings"
)

type Result struct {
	Domain string `json:"domain" xml:"domain"`
	IP     string `json:"ip" xml:"ip"`
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Domain Scope Checker v1.0\n")
		fmt.Fprintf(os.Stderr, "Author: tweathers-sec\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}

	inScopeIPsFile := flag.String("ips", "", "File containing in-scope IP addresses/CIDRs")
	potentialDomainsFile := flag.String("domains", "", "File containing potential in-scope vhosts/subdomains")
	outputFile := flag.String("output", "", "Output file name")
	outputFormat := flag.String("format", "txt", "Output format (txt, json, xml, csv)")
	portScan := flag.Bool("portscan", false, "Create an in-scope subdomains txt file from a scopeMapper output file")
	inputFile := flag.String("input", "", "Input file for portscan option")
	flag.Parse()

	if *portScan {
		if *inputFile == "" {
			fmt.Println("Error: -input flag is required when using -portscan")
			return
		}
		err := createInScopeSubdomainsFile(*inputFile, *outputFile)
		if err != nil {
			fmt.Println("Error creating in-scope subdomains file:", err)
			return
		}
		fmt.Println("In-scope subdomains file created successfully")
		return
	}

	// Only read in-scope IPs and potential domains if not using -portscan
	inScopeHosts, err := readLines(*inScopeIPsFile)
	if err != nil {
		fmt.Println("Error reading in-scope IPs file:", err)
		return
	}

	potentialDomains, err := readLines(*potentialDomainsFile)
	if err != nil {
		fmt.Println("Error reading potential domains file:", err)
		return
	}

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
		fmt.Fprintf(file, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
		err = encoder.Encode(struct {
			XMLName xml.Name `xml:"results"`
			Results []Result `xml:"result"`
		}{Results: results})
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

func createInScopeSubdomainsFile(inputFile, outputFile string) error {
	results, err := readResultsFromFile(inputFile)
	if err != nil {
		return err
	}

	if outputFile == "" {
		outputFile = "inscope_subdomains.txt"
	}

	file, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, result := range results {
		_, err := fmt.Fprintln(file, result.Domain)
		if err != nil {
			return err
		}
	}

	return nil
}

func readResultsFromFile(filename string) ([]Result, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var results []Result

	switch filepath.Ext(filename) {
	case ".json":
		decoder := json.NewDecoder(file)
		err = decoder.Decode(&results)
	case ".xml":
		decoder := xml.NewDecoder(file)
		var xmlResults struct {
			Results []Result `xml:"result"`
		}
		err = decoder.Decode(&xmlResults)
		results = xmlResults.Results
	case ".txt", ".csv":
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			parts := strings.Split(scanner.Text(), ",")
			if len(parts) == 2 {
				results = append(results, Result{Domain: parts[0], IP: parts[1]})
			}
		}
		err = scanner.Err()
	default:
		return nil, fmt.Errorf("unsupported file format: %s", filepath.Ext(filename))
	}

	if err != nil {
		return nil, err
	}

	return results, nil
}
