package main

import (
    "fmt"
    "net"
    "regexp"
    "strings"
)

func isEmailValidSyntax(email string) bool {
    regex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
    re := regexp.MustCompile(regex)
    return re.MatchString(email)
}

func checkMXRecords(domain string) (bool, error) {
    mxRecords, err := net.LookupMX(domain)
    if err != nil {
        return false, err
    }
    return len(mxRecords) > 0, nil
}

func checkSPFRecord(domain string) (bool, error) {
    txtRecords, err := net.LookupTXT(domain)
    if err != nil {
        return false, err
    }

    for _, txt := range txtRecords {
        if strings.HasPrefix(txt, "v=spf1") {
            return true, nil
        }
    }
    return false, nil
}

func checkDKIMRecord(domain string) (bool, error) {
    selector := "default._domainkey"
    dkimDomain := fmt.Sprintf("%s.%s", selector, domain)
    txtRecords, err := net.LookupTXT(dkimDomain)
    if err != nil {
        return false, err
    }

    for _, txt := range txtRecords {
        if strings.Contains(txt, "v=DKIM1;") {
            return true, nil
        }
    }
    return false, nil
}

func checkDMARCRecord(domain string) (bool, error) {
    dmarcDomain := fmt.Sprintf("_dmarc.%s", domain)
    txtRecords, err := net.LookupTXT(dmarcDomain)
    if err != nil {
        return false, err
    }

    for _, txt := range txtRecords {
        if strings.HasPrefix(txt, "v=DMARC1;") {
            return true, nil
        }
    }
    return false, nil
}


func checkDomain(email, domain string) (map[string]bool, error) {
    result := make(map[string]bool)

    if !isEmailValidSyntax(email) {
        result["SyntaxValid"] = false
        return result, fmt.Errorf("invalid email syntax")
    }
    result["SyntaxValid"] = true

    mxValid, err := checkMXRecords(domain)
    if err != nil || !mxValid {
        result["MXRecord"] = false
        return result, fmt.Errorf("invalid MX records or domain does not exist")
    }
    result["MXRecord"] = true

    spfValid, err := checkSPFRecord(domain)
    if err != nil || !spfValid {
        result["SPFRecord"] = false
    } else {
        result["SPFRecord"] = true
    }

    dkimValid, err := checkDKIMRecord(domain)
    if err != nil || !dkimValid {
        result["DKIMRecord"] = false
    } else {
        result["DKIMRecord"] = true
    }

    dmarcValid, err := checkDMARCRecord(domain)
    if err != nil || !dmarcValid {
        result["DMARCRecord"] = false
    } else {
        result["DMARCRecord"] = true
    }

    return result, nil
}
