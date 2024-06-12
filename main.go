package main

import (
    "bufio"
    "fmt"
    "log"
    "os"
    "strings"
)

func main() {
    scanner := bufio.NewScanner(os.Stdin)
    fmt.Println("Enter email addresses to verify. Press Ctrl+C to exit.")

    for scanner.Scan() {
        email := scanner.Text()
        domain := email[strings.LastIndex(email, "@")+1:]

        result, err := checkDomain(email, domain)
        if err != nil {
            log.Printf("Error checking domain for %s: %v\n", email, err)
        } else {
            printResult(email, result)
        }

        fmt.Println("\nEnter another email address or press Ctrl+C to exit:")
    }

    if err := scanner.Err(); err != nil {
        log.Fatalf("Couldn't read input: %v", err)
    }
}

func printResult(email string, result map[string]bool) {
    fmt.Printf("\nEmail verification result for %s:\n", email)
    fmt.Printf("  Syntax Valid: %t\n", result["SyntaxValid"])
    fmt.Printf("  MX Record: %t\n", result["MXRecord"])
    fmt.Printf("  SPF Record: %t\n", result["SPFRecord"])
    fmt.Printf("  DKIM Record: %t\n", result["DKIMRecord"])
    fmt.Printf("  DMARC Record: %t\n", result["DMARCRecord"])
}
