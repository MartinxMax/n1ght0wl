// S-H4CK13 Maptnh 
package main

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)
 
var LOGO = []string{
	"	⢠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
	"	⢸⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
	"	⠸⣿⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
	"	⢣⠈⠻⣿⣷⣦⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⣄⠀",
	"	⢸⣶⣄⡀⠉⡝⣽⣿⣾⣦⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣧⠀",
	"	⢰⠙⢿⣿⣷⣶⣏⣙⡛⠿⢿⣿⣿⣿⣶⣶⣀⣀⣰⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⣰⣿⢏⡆",
	"	⠈⢷⣤⡈⠙⠻⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣾⣾⣤⣴⣶⣿⠿⢋⡾⠀",
	"	⠀⠀⠻⣿⣷⣦⣤⣤⣈⣩⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⣀⣼⣿⣿⣿⣿⣿⣿⣿⣧⣦⡷⠁⠀",
	"	⠀⠀⠙⢦⣍⣉⡛⠻⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡄⠀⠀⠀⠀⠀⣰⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣯⠵⠂⠀⠀",
	"	⠀⠀⠀⠀⠉⠛⠻⠿⠿⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀⠀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠋⠉⠀⠀⠀⠀",
	"	⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠼⡿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣶⣾⣿⣿⣿⣿⡿⠿⠿⠿⠿⠟⠋⠀⠀⠀⠀⠀⠀",
	"	⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
	"	⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⡀⠀⠀⠀⠀⠀⠀⠀⠀",
	"	⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⣷⡄⠀⠀⠀⠀⠀⠀⠀",
	"	⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⣿⣿⣿⣿⠟⠋⠀⠈⠙⠻⣦⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀",
	"	⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠈⣷⣿⡀⠀⠀⠀⠀⠀⠀⠀",
	"	⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣾⣿⣿⣿⣿⣿⣿⠿⠿⣆⡀⠀⠀⠀⠀⠀⠀⠀⢿⢹⡇⠀⠀⠀⠀⠀⠀",
	"	⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⣿⣿⣿⠙⠲⢄⠀⠉⣳⠦⢤⡠⣤⠀⠀⠈⠀⠁⠀⠀⠀⠀⠀⠀",
	"	⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡝⣹⣿⣿⣿⣿⣿⣿⡆⠀⢬⡛⡇⠇⠀⠸⠆⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
	"	⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠟⣿⣿⣿⣿⡟⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
	"	⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⢿⣿⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
	"	⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
	"    Maptnh@S-H4CK13    <Raven>    @https://github.com/MartinxMax/  ",
}

type LogCat struct{}
var logCat = &LogCat{}

const (
	Reset      = "\033[0m"     // Reset
	Italic     = "\033[3m"     // Italic
	Bold       = "\033[1m"     // Bold
	Gray       = "\033[90m"    // Gray
	Blue       = "\033[94m"    // Bright Blue
	Orange     = "\033[38;5;208m" // Orange
	Purple     = "\033[95m"    // Bright Purple
	Red        = "\033[91m"    // Bright Red
	Green      = "\033[92m"    // Bright Green
)


type NmapRun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []Host   `xml:"host"`
}

type Host struct {
	Status Status   `xml:"status"`
	Address []Address `xml:"address"`
	Ports   []Port   `xml:"ports>port"`
}

type Status struct {
	State string `xml:"state,attr"`
}

type Address struct {
	AddrType string `xml:"addrtype,attr"`
	Addr     string `xml:"addr,attr"`
}

type Port struct {
	Protocol string `xml:"protocol,attr"`
	PortId   string `xml:"portid,attr"`
	State    PortState `xml:"state"`
}

type PortState struct {
	State string `xml:"state,attr"`
}

 
type MD5Record struct {
	FilePath   string `json:"FILE_PATH"`
	FileHash   string `json:"FILE_HASH"`
	R4venFile  string `json:"R4ven_FILE"`
}

type PortIPs struct {
	PROT string   `json:"PROT"`
	IPS  []string `json:"IPS"`
}

const (
	r4venIPsDir   = "./r4ven_ips"
	md5sJsonPath = "./r4ven_ips/md5s.json"
) 


func (l *LogCat) _getEnglishDatetime() string {
	return time.Now().Format("15:04:05")
}

// Info
func (l *LogCat) Info(data string) {
	datetimeStr := l._getEnglishDatetime()
	fmt.Printf("%s[%s]%s %s[INFO]%s  %s\n", Gray, datetimeStr, Reset, Blue,data,Reset)
}

// Warning
func (l *LogCat) Warning(data string) {
	datetimeStr := l._getEnglishDatetime()
	fmt.Printf("%s[%s]%s %s%s[WARNING]%s  %s\n", Gray, datetimeStr, Reset, Italic, Orange,data,Reset)
}

// System
func (l *LogCat) System(data string) {
	datetimeStr := l._getEnglishDatetime()
	fmt.Printf("%s[%s]%s %s%s[SYSTEM]%s  %s\n", Gray, datetimeStr, Reset, Italic, Purple,data,Reset)
}

// Error
func (l *LogCat) Error(data string) {
	datetimeStr := l._getEnglishDatetime()
	fmt.Printf("%s[%s]%s %s%s[ERROR]%s  %s\n", Gray, datetimeStr, Reset, Bold, Red,data,Reset)
}

// Success
func (l *LogCat) Success(data string) {
	datetimeStr := l._getEnglishDatetime()
	fmt.Printf("%s[%s]%s %s%s[SUCCESS]%s  %s\n", Gray, datetimeStr, Reset, Bold, Green,data,Reset)
}

// Debug
func (l *LogCat) Debug(data string) {
	datetimeStr := l._getEnglishDatetime()
	fmt.Printf("%s[%s]%s %s%s[DEBUG]%s  %s\n", Gray, datetimeStr, Reset, Italic, Gray,data,Reset)
}

func (l *LogCat) InfoInline(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	fmt.Printf("\r\033[K%s", msg)
}

func show_logo(){
	totalLines := len(LOGO)
	step := 255.0 / float64(totalLines-1)
	for i, line := range LOGO {
		r := int(float64(i) * step)
		b := 255 - r
		g := 0
		colorPrefix := fmt.Sprintf("\033[38;2;%d;%d;%dm", r, g, b)
		fmt.Println(colorPrefix + line + Reset)
	}
}
 
func parseAliveIPsFromNmapXML(xmlData []byte) ([]string, error) {
	var result NmapRun
	if err := xml.Unmarshal(xmlData, &result); err != nil {
		return nil, err
	}

	var aliveIPs []string
	for _, host := range result.Hosts {
		if host.Status.State != "up" {
			continue
		}
		for _, addr := range host.Address {
			if addr.AddrType == "ipv4" {
				aliveIPs = append(aliveIPs, addr.Addr)
			}
		}
	}
	return aliveIPs, nil
}
 
func parseOpenIPsFromNmapXML(xmlData []byte, port string) ([]string, error) {
	var result NmapRun
	if err := xml.Unmarshal(xmlData, &result); err != nil {
		return nil, err
	}

	var openIPs []string
	for _, host := range result.Hosts {
		var ipv4 string
		for _, addr := range host.Address {
			if addr.AddrType == "ipv4" {
				ipv4 = addr.Addr
				break
			}
		}
		if ipv4 == "" {
			continue
		}
		for _, p := range host.Ports {
			if p.PortId == port && p.State.State == "open" {
				openIPs = append(openIPs, ipv4)
				break
			}
		}
	}
	return openIPs, nil
}

func checkNmapInstalled() bool {
	cmd := exec.Command("which", "nmap")
	err := cmd.Run()
	return err == nil
}


func installNmap() error {
	logCat.Info("Install nmap...")
	cmdUpdate := exec.Command("sudo", "apt", "update")
	cmdUpdate.Stdout = os.Stdout
	cmdUpdate.Stderr = os.Stderr
	if err := cmdUpdate.Run(); err != nil {
		msg := fmt.Sprintf("Failed to update apt sources: %v", err)
		logCat.Error(msg)
		return fmt.Errorf(msg)
	}
 
	cmdInstall := exec.Command("sudo", "apt", "install", "-y", "nmap")
	cmdInstall.Stdout = os.Stdout
	cmdInstall.Stderr = os.Stderr
	if err := cmdInstall.Run(); err != nil {
		msg := fmt.Sprintf("Failed to install nmap: %v", err)
		logCat.Error(msg)
		return fmt.Errorf(msg)
	}
	logCat.System("Nmap installed successfully...")
	return nil
}


func calculateFileMD5(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func readMD5Records() ([]MD5Record, error) {
	if _, err := os.Stat(md5sJsonPath); os.IsNotExist(err) {
		return []MD5Record{}, nil
	}

	file, err := os.Open(md5sJsonPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var records []MD5Record
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&records); err != nil {
		return nil, err
	}
	return records, nil
}


func writeMD5Records(records []MD5Record) error {
	if err := os.MkdirAll(r4venIPsDir, 0755); err != nil {
		return err
	}

	file, err := os.Create(md5sJsonPath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "    ")
	return encoder.Encode(records)
}


func loadingAnimation(done chan struct{}) {
	spinner := []rune{'|', '/', '-', '\\'}
	i := 0

	for {
		select {
		case <-done:
			fmt.Print("\r\033[K")
			return
		default:
			logCat.InfoInline("[WAIT] Processing... %c", spinner[i%len(spinner)])
			i++
			time.Sleep(100 * time.Millisecond)
		}
	}
}
 
func runNmapAliveScan(filePath string) ([]string, error) {
	cmd := exec.Command("nmap", "-sn", "-iL", filePath, "-oX", "-")
	stdout, err := cmd.Output()
	if err != nil {
		logCat.Error("Alive scan failed")
		return nil, err
	}

	return parseAliveIPsFromNmapXML(stdout)
}

 
func runNmapPortScan(liveIPFile, port string) ([]string, error) {
	cmd := exec.Command("nmap", "-Pn", "-sS", "-T4", "-p", port, "-iL", liveIPFile, "-oX", "-")
	stdout, err := cmd.Output()
	if err != nil {
		logCat.Error("Port scan failed")
		return nil, err
	}
	return parseOpenIPsFromNmapXML(stdout, port)
}

 
func deleteOldRecordAndFiles(records []MD5Record, targetFilePath string) ([]MD5Record, error) {
	var newRecords []MD5Record
	var deletedRecord MD5Record
	found := false
 
	for _, record := range records {
		if record.FilePath == targetFilePath {
			deletedRecord = record
			found = true
			continue
		}
		newRecords = append(newRecords, record)
	}

	if !found {
		return records, nil
	}

 
	if _, err := os.Stat(deletedRecord.R4venFile); err == nil {
		if err := os.Remove(deletedRecord.R4venFile); err != nil {
			return nil, err
		}
	}

 
	dirPath := filepath.Dir(deletedRecord.R4venFile)
	if _, err := os.Stat(dirPath); err == nil {
		if err := os.RemoveAll(dirPath); err != nil {
			return nil, err
		}
	}
	logCat.Info("Old records and files cleaned up.")
	return newRecords, nil
}

 
func handleLoadCommand(filePath string) {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		logCat.Warning(fmt.Sprintf("Input file not found: %s", filePath))
		return
	}

	fileMD5, err := calculateFileMD5(filePath)
	if err != nil {
		logCat.Error(fmt.Sprintf("Failed to calculate MD5: %v", err))
		return
	}

	records, err := readMD5Records()
	if err != nil {
		logCat.Error(fmt.Sprintf("Failed to read cache records: %v", err))
		return
	}

	md5Exists := false
	var existingRecord MD5Record
	for _, record := range records {
		if record.FileHash == fileMD5 {
			md5Exists = true
			existingRecord = record
			break
		}
	}

	if md5Exists {
		if _, err := os.Stat(existingRecord.R4venFile); os.IsNotExist(err) {
			var newRecords []MD5Record
			for _, record := range records {
				if record.FileHash != fileMD5 {
					newRecords = append(newRecords, record)
				}
			}
			if err := writeMD5Records(newRecords); err != nil {
				logCat.Error(fmt.Sprintf("Failed to clear invalid cache: %v", err))
				return
			}
			logCat.Warning("Invalid cache cleared, please reload the target file")
			return
		}

		logCat.Warning(fmt.Sprintf(
			"Target already scanned, existing result: %s",
			existingRecord.R4venFile,
		))
		return
	}

	filePathExists := false
	for _, record := range records {
		if record.FilePath == filePath {
			filePathExists = true
			break
		}
	}

	if filePathExists {
		newRecords, err := deleteOldRecordAndFiles(records, filePath)
		if err != nil {
			logCat.Error(fmt.Sprintf("Failed to remove old records: %v", err))
			return
		}
		if err := writeMD5Records(newRecords); err != nil {
			logCat.Error(fmt.Sprintf("Failed to update cache records: %v", err))
			return
		}
		logCat.System("Target file changed, rescan scheduled")
	}

	logCat.Info("Starting alive host discovery scan")
	done := make(chan struct{})
	go loadingAnimation(done)
	liveIPs, err := runNmapAliveScan(filePath)
	close(done)
	if err != nil {
		logCat.Error(fmt.Sprintf("Alive scan failed: %v", err))
		return
	}

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	tempLiveFile := fmt.Sprintf("%s/live_mechines_%s.r4v", r4venIPsDir, timestamp)

	if err := os.MkdirAll(r4venIPsDir, 0755); err != nil {
		logCat.Error(fmt.Sprintf("Failed to create output directory: %v", err))
		return
	}

	tempFile, err := os.Create(tempLiveFile)
	if err != nil {
		logCat.Error(fmt.Sprintf("Failed to create temp alive file: %v", err))
		return
	}

	writer := bufio.NewWriter(tempFile)
	for _, ip := range liveIPs {
		fmt.Fprintln(writer, ip)
	}
	writer.Flush()
	tempFile.Close()

	logCat.Success(fmt.Sprintf("Alive IPs saved: %s", tempLiveFile))

	md5Dir := fmt.Sprintf("%s/%s", r4venIPsDir, fileMD5)
	if err := os.MkdirAll(md5Dir, 0755); err != nil {
		logCat.Error(fmt.Sprintf("Failed to create module directory: %v", err))
		return
	}

	liveFile := fmt.Sprintf("%s/live.r4v", md5Dir)
	liveFileHandle, err := os.Create(liveFile)
	if err != nil {
		logCat.Error(fmt.Sprintf("Failed to write alive result: %v", err))
		return
	}

	writer = bufio.NewWriter(liveFileHandle)
	for _, ip := range liveIPs {
		fmt.Fprintln(writer, ip)
	}
	writer.Flush()
	liveFileHandle.Close()

	records = append(records, MD5Record{
		FilePath:  filePath,
		FileHash:  fileMD5,
		R4venFile: liveFile,
	})

	if err := writeMD5Records(records); err != nil {
		logCat.Error(fmt.Sprintf("Failed to persist fingerprint record: %v", err))
		return
	}

	logCat.Success("Target fingerprint registered successfully")
}

 
func readPortIPFile(filePath string) (*PortIPs, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var portIPs PortIPs
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&portIPs); err != nil {
		return nil, err
	}

	return &portIPs, nil
}
 
func formatIPS(ips []string) string {
	if len(ips) == 0 {
		return "N/A"
	}
	showCount := 3
	if len(ips) < showCount {
		showCount = len(ips)
	}
	ipStr := strings.Join(ips[:showCount], ", ")
	if len(ips) > showCount {
		ipStr += "..."
	}
	return ipStr
}

func handleShowAllCommand() {
	dirs, err := os.ReadDir(r4venIPsDir)
	if err != nil {
		logCat.Error(fmt.Sprintf("Failed to read r4ven_ips directory: %v", err))
		return
	}

	portFileRegex := regexp.MustCompile(`^\d+.r4v$`)
	resultMap := make(map[string]map[string][]string)

	for _, dir := range dirs {
		if !dir.IsDir() {
			continue
		}
		md5Dir := dir.Name()
		if md5Dir == filepath.Base(md5sJsonPath) {
			continue
		}
		dirPath := fmt.Sprintf("%s/%s", r4venIPsDir, md5Dir)
		files, err := os.ReadDir(dirPath)
		if err != nil {
			logCat.Warning(fmt.Sprintf("Failed to read MD5 dir %s: %v", md5Dir, err))
			continue
		}

		resultMap[md5Dir] = make(map[string][]string)
		for _, file := range files {
			if file.IsDir() {
				continue
			}
			filename := file.Name()
			if !portFileRegex.MatchString(filename) {
				continue
			}

			filePath := fmt.Sprintf("%s/%s", dirPath, filename)
			portIPs, err := readPortIPFile(filePath)
			if err != nil {
				logCat.Warning(fmt.Sprintf("Failed to read port file %s: %v", filePath, err))
				continue
			}

			resultMap[md5Dir][portIPs.PROT] = portIPs.IPS
		}
	}

	fmt.Println("======")
	fmt.Printf("%-36s | %-8s | %s\n", "Module", "PORT", "IPS")
	fmt.Println("--------------------------------------------------------------")

	var md5Dirs []string
	for md5Dir := range resultMap {
		md5Dirs = append(md5Dirs, md5Dir)
	}
	sort.Strings(md5Dirs)

	for _, md5Dir := range md5Dirs {
		portMap := resultMap[md5Dir]
		if len(portMap) == 0 {
			fmt.Printf("%-36s | %-8s | %s\n", md5Dir, "N/A", "N/A")
			continue
		}

		var ports []string
		for port := range portMap {
			ports = append(ports, port)
		}
		sort.Slice(ports, func(i, j int) bool {
			portI, _ := strconv.Atoi(ports[i])
			portJ, _ := strconv.Atoi(ports[j])
			return portI < portJ
		})

		firstPort := ports[0]
		ipsStr := formatIPS(portMap[firstPort])
		fmt.Printf("%-36s | PORT %-6s | %s\n", md5Dir, firstPort, ipsStr)

		for i := 1; i < len(ports); i++ {
			port := ports[i]
			ipsStr := formatIPS(portMap[port])
			fmt.Printf("%-36s | PORT %-6s | %s\n", "", port, ipsStr)
		}
	}
	fmt.Println("======")
}

func handleShowMD5Command(md5Module string) {
	md5Dir := fmt.Sprintf("%s/%s", r4venIPsDir, md5Module)
	if _, err := os.Stat(md5Dir); os.IsNotExist(err) {
		logCat.Warning(fmt.Sprintf("MD5 module %s does not exist", md5Module))
		return
	}

	portFileRegex := regexp.MustCompile(`^\d+.r4v$`)
	portMap := make(map[string][]string)

	files, err := os.ReadDir(md5Dir)
	if err != nil {
		logCat.Error(fmt.Sprintf("Failed to read MD5 dir %s: %v", md5Module, err))
		return
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		filename := file.Name()
		if !portFileRegex.MatchString(filename) {
			continue
		}

		filePath := fmt.Sprintf("%s/%s", md5Dir, filename)
		portIPs, err := readPortIPFile(filePath)
		if err != nil {
			logCat.Warning(fmt.Sprintf("Failed to read port file %s: %v", filePath, err))
			continue
		}

		portMap[portIPs.PROT] = portIPs.IPS
	}

	fmt.Println("======")
	fmt.Printf("%-36s | %-8s | %s\n", "Module", "PORT", "IPS")
	fmt.Println("--------------------------------------------------------------")

	if len(portMap) == 0 {
		fmt.Printf("%-36s | %-8s | %s\n", md5Module, "N/A", "N/A")
	} else {
		var ports []string
		for port := range portMap {
			ports = append(ports, port)
		}
		sort.Slice(ports, func(i, j int) bool {
			portI, _ := strconv.Atoi(ports[i])
			portJ, _ := strconv.Atoi(ports[j])
			return portI < portJ
		})

		firstPort := ports[0]
		ipsStr := formatIPS(portMap[firstPort])
		fmt.Printf("%-36s | PORT %-6s | %s\n", md5Module, firstPort, ipsStr)

		for i := 1; i < len(ports); i++ {
			port := ports[i]
			ipsStr := formatIPS(portMap[port])
			fmt.Printf("%-36s | PORT %-6s | %s\n", "", port, ipsStr)
		}
	}
	fmt.Println("======")
}

func handleShowMD5PortCommand(md5Module, port string) {
	md5Dir := fmt.Sprintf("%s/%s", r4venIPsDir, md5Module)
	if _, err := os.Stat(md5Dir); os.IsNotExist(err) {
		logCat.Warning(fmt.Sprintf("MD5 module %s does not exist", md5Module))
		return
	}

	portFilePath := fmt.Sprintf("%s/%s.r4v", md5Dir, port)
	if _, err := os.Stat(portFilePath); os.IsNotExist(err) {
		logCat.Warning(fmt.Sprintf("Scan file for port %s does not exist", port))
		return
	}

	portIPs, err := readPortIPFile(portFilePath)
	if err != nil {
		logCat.Error(fmt.Sprintf("Failed to read port info file %s: %v", portFilePath, err))
		return
	}

	fmt.Printf("=====%s====\n", port)
	for _, ip := range portIPs.IPS {
		fmt.Println(ip)
	}
	fmt.Printf("=================\n")
	logCat.Info(fmt.Sprintf("File path: %s", portFilePath))

	fmt.Print(Red+"[?] Do you want to extract these IPs and save (Y/N, default N): "+Reset)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	answer := strings.TrimSpace(scanner.Text())
	if strings.EqualFold(answer, "Y") {
		tmpFile := fmt.Sprintf("/tmp/%s.txt", port)
		file, err := os.Create(tmpFile)
		if err != nil {
			logCat.Error(fmt.Sprintf("Failed to create file %s: %v", tmpFile, err))
			return
		}
		defer file.Close()
		writer := bufio.NewWriter(file)
		for _, ip := range portIPs.IPS {
			fmt.Fprintln(writer, ip)
		}
		writer.Flush()
		logCat.Success(fmt.Sprintf("IPs saved to %s", tmpFile))
	} else {
		logCat.Info("Skipped saving IPs.")
	}
}


func handleScanCommand(fileHash, port string) {
	if _, err := strconv.Atoi(port); err != nil {
		logCat.Warning(fmt.Sprintf("Port %s is not a valid number", port))
		return
	}

	records, err := readMD5Records()
	if err != nil {
		logCat.Error(fmt.Sprintf("Failed to read md5s.json: %v", err))
		return
	}

	var targetRecord MD5Record
	found := false
	for _, record := range records {
		if record.FileHash == fileHash {
			targetRecord = record
			found = true
			break
		}
	}

	if !found {
		logCat.Warning("Specified module not loaded, use `load <file>` first")
		return
	}

	if _, err := os.Stat(targetRecord.R4venFile); os.IsNotExist(err) {
		logCat.Error(fmt.Sprintf("Alive IP file does not exist: %s", targetRecord.R4venFile))
		return
	}

	logCat.Info(fmt.Sprintf("Scanning module %s on port %s", fileHash, port))
	done := make(chan struct{})
	go loadingAnimation(done)

	openIPs, err := runNmapPortScan(targetRecord.R4venFile, port)
	close(done)
	if err != nil {
		logCat.Error(fmt.Sprintf("Port scan failed: %v", err))
		return
	}

	portIPs := PortIPs{
		PROT: port,
		IPS:  openIPs,
	}

	md5Dir := filepath.Dir(targetRecord.R4venFile)
	portFilePath := fmt.Sprintf("%s/%s.r4v", md5Dir, port)
	file, err := os.Create(portFilePath)
	if err != nil {
		logCat.Error(fmt.Sprintf("Failed to create port file %s: %v", portFilePath, err))
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "    ")
	if err := encoder.Encode(portIPs); err != nil {
		logCat.Error(fmt.Sprintf("Failed to write port file %s: %v", portFilePath, err))
		return
	}

	logCat.Success(fmt.Sprintf("Port %s scan completed, saved to %s", port, portFilePath))
}


 
func parseCommand(input string) (string, []string) {
	parts := strings.Fields(input)
	if len(parts) == 0 {
		return "", nil
	}
	cmd := strings.ToLower(parts[0])
	args := parts[1:]
	return cmd, args
}


func showHelp() {
	fmt.Println("Usage:")
	fmt.Println("  help                         - Show this help message")
	fmt.Println("  load <file path>             - Load IP list and scan alive hosts")
	fmt.Println("  show                         - Display all modules and port info")
	fmt.Println("  show <MD5 module>            - Display info for a specific MD5 module")
	fmt.Println("  show <MD5 module> <port>     - Display detailed IPs for a module+port")
	fmt.Println("  scan <FILE_HASH> <port>      - Scan the specified port of a module")
	fmt.Println("  exit                         - Exit the program")
}

func main() {
	show_logo()

	if os.Geteuid() != 0 {
		logCat.Error("Please run this program with sudo/root privileges")
		os.Exit(1)
	}

	if !checkNmapInstalled() {
		logCat.Warning("Nmap not detected, will attempt automatic installation")
		if err := installNmap(); err != nil {
			logCat.Error(fmt.Sprintf("Failed to install nmap: %v", err))
			os.Exit(1)
		}
		logCat.Success("Nmap installed successfully")
	}

	fmt.Println("Type 'help' to see available commands")

	if err := os.MkdirAll(r4venIPsDir, 0755); err != nil {
		logCat.Error(fmt.Sprintf("Failed to create directory %s: %v", r4venIPsDir, err))
		os.Exit(1)
	}

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print(Orange+"R4ven > "+Reset)
		if !scanner.Scan() {
			break
		}
		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			continue
		}

		cmd, args := parseCommand(input)
		switch cmd {
		case "help":
			showHelp()
		case "load":
			if len(args) != 1 {
				logCat.Warning("Usage: load <file path>")
				continue
			}
			handleLoadCommand(args[0])
		case "show":
			switch len(args) {
			case 0:
				handleShowAllCommand()
			case 1:
				handleShowMD5Command(args[0])
			case 2:
				handleShowMD5PortCommand(args[0], args[1])
			default:
				logCat.Warning("Usage: show [MD5 module] [port]")
			}
		case "scan":
			if len(args) != 2 {
				logCat.Warning("Usage: scan <FILE_HASH> <port>")
				continue
			}
			handleScanCommand(args[0], args[1])
		case "exit":
			logCat.Info("Exiting R4ven Scanner")
			os.Exit(0)
		default:
			logCat.Warning(fmt.Sprintf("Unknown command: %s", cmd))
		}
	}

	if err := scanner.Err(); err != nil {
		logCat.Error(fmt.Sprintf("Failed to read input: %v", err))
		os.Exit(1)
	}
}

