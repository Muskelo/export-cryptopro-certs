package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func ForEachE[A any](args []A, f func(A) error) error {
	for _, arg := range args {
		err := f(arg)
		if err != nil {
			return err
		}
	}
	return nil
}
func Map[A any, R any](args []A, f func(A) R) []R {
	results := []R{}
	for _, arg := range args {
		results = append(results, f(arg))
	}
	return results
}
func MapE[A any, R any](args []A, f func(A) (R, error)) ([]R, error) {
	results := []R{}
	for _, arg := range args {
		res, err := f(arg)
		if err != nil {
			return nil, err
		}
		results = append(results, res)
	}
	return results, nil
}
func FilterE[A any](items []A, f func(A) (bool, error)) ([]A, error) {
	results := []A{}
	for _, item := range items {
		ok, err := f(item)
		if err != nil {
			return nil, fmt.Errorf("Filtering failed on item '%v': %v", item, err)
		}
		if ok {
			results = append(results, item)
		}
	}
	return results, nil
}

func printErr(err error) {
	fmt.Printf("Error: %v\n", err)
}

// Flags struct
type Flags struct {
	Certmgr  string
	Output   string
	Expiring bool
}

var flags Flags

// Certs struct
func NewCert(v string) (*Cert, error) {
	cert := &Cert{}
	lines := strings.Split(v, "\n")
	err := ForEachE(lines, cert.SetString)
	return cert, err
}

type Cert struct {
	Subject string `json:"subject"`
	Serial  string `json:"serial"`
	Expire  string `json:"expire"`
}

func (cert *Cert) SetString(v string) error {
	args := strings.SplitN(v, ":", 2)
	if len(args) != 2 {
		return fmt.Errorf("Can't split '%v'", v)
	}
	key := strings.TrimSpace(args[0])
	value := strings.TrimSpace(args[1])
	cert.Set(key, value)
	return nil
}
func (cert *Cert) Set(key, value string) {
	switch key {
	case "Subject", "Субъект":
		cert.Subject = value
	case "Serial", "Серийный номер":
		cert.Serial = value
	case "Истекает", "Not valid after":
		cert.Expire = value
	}
}

// Main

func parseFlags() error {
	flagSet := flag.NewFlagSet("Default", flag.ContinueOnError)
	flagSet.StringVar(&flags.Certmgr, "certmgr", "/opt/cprocsp/bin/amd64/certmgr", "Path to certmgr")
	flagSet.StringVar(&flags.Output, "output", "/tmp/certs-info.json", "Path to output file")
	flagSet.BoolVar(&flags.Expiring, "expiring", true, "Export only expiring certs")
	return flagSet.Parse(os.Args[1:])
}

func parseCerts(output string) ([]*Cert, error) {
	// get list between two border
	borderRE, _ := regexp.Compile(`\n={5,}\n`) // example ===========
	rawCertslist := borderRE.Split(output, -1)[1]
	// split list by number
	numberRE, _ := regexp.Compile(`\d-{5,}`) // example: 2-----
	rawCerts := numberRE.Split(rawCertslist, -1)[1:]
	// trim
	rawCerts = Map(rawCerts, func(s string) string {
		return strings.Trim(s, "\n")
	})
	return MapE(rawCerts, NewCert)
}

func certIsExpiring(cert *Cert) (bool, error) {
	date := strings.Split(cert.Expire, " ")[0]
	certExpire, err := time.Parse("02/01/2006", date)
	if err != nil {
		return false, err
	}
	warningDate := certExpire.AddDate(0, 0, -14)
	if time.Now().Unix() > warningDate.Unix() {
		return true, nil
	}
	return false, nil
}

func getFile() (*os.File, error) {
	// create file
	file, err := os.Create(flags.Output)
	if err != nil {
		return nil, err
	}

	// set perm
	if err := file.Chmod(0660); err != nil {
		return nil, err
	}

	// get uid and gid for zabbix user
	zabbixUser, err := user.Lookup("zabbix")
	if err != nil {
		return nil, err
	}
	uid, err := strconv.ParseInt(zabbixUser.Uid, 10, 64)
	gid, err := strconv.ParseInt(zabbixUser.Gid, 10, 64)
	if err != nil {
		return nil, err
	}

	// set uid and gid for file
	err = file.Chown(int(uid), int(gid))

	return file, err
}
func writeJSON(certs []*Cert) error {
	file, err := getFile()
	if err != nil {
		return err
	}
	b, err := json.Marshal(certs)
	if err != nil {
		return err
	}
	_, err = file.Write(b)
	return err
}

func main() {
	if err := parseFlags(); err != nil {
		printErr(err)
		return
	}

	cmd := exec.Command(flags.Certmgr, "-list")
	output, err := cmd.Output()
	if err != nil {
		printErr(fmt.Errorf("Can't exec certmgr Command: %v", err))
		return
	}

	certs, err := parseCerts(string(output))
	if err != nil {
		printErr(fmt.Errorf("Can't parse certs: %v", err))
		return
	}
	if flags.Expiring {
		certs, err = FilterE(certs, certIsExpiring)
		if err != nil {
			printErr(fmt.Errorf("Can't check cert is expiring: %v", err))
			return
		}
	}

	err = writeJSON(certs)
	if err != nil {
		printErr(fmt.Errorf("Can't write to file: %v", err))
	}
}
