package main
// S-H4CK13 @ Maptnh
import (
	"bufio"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
    "os/exec"
    "regexp"
    "strconv"
	"github.com/manifoldco/promptui"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)


var (
	startTimestamp string
	alive          sync.Map
	defaultConcurrency = 1000
)

 
func ensurePrivilege() {
	if runtime.GOOS == "linux" {
		if os.Geteuid() != 0 {
			fmt.Println("[!]Root privileges are required. Please run the program with sudo or as root.")
			os.Exit(1)
		}
	} else if runtime.GOOS == "windows" {
		_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
		if err != nil {
			fmt.Println("[!] Please run this program as an administrator!")
			os.Exit(1)
		}
	}
}


func getAvailableInterfaces() ([]net.Interface, error) {
	var available []net.Interface
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if ok && ipNet.IP.To4() != nil {
				available = append(available, iface)
				break
			}
		}
	}
	if len(available) == 0 {
		return nil, fmt.Errorf("[!] No available network interfaces found.")
	}
	return available, nil
}

func getInterfaceIP(iface net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if ok && ipNet.IP.To4() != nil {
			return ipNet.IP, nil
		}
	}
	return nil, fmt.Errorf("[!] Interface %s has no available IPv4 address.", iface.Name)
}

func selectInterfacePrompt() (net.Interface, error) {
	ifaces, err := getAvailableInterfaces()
	if err != nil {
		return net.Interface{}, err
	}
	type Item struct {
		Name  string
		Desc  string
		Iface net.Interface
	}
	items := []Item{}
	for _, iface := range ifaces {
		ip, _ := getInterfaceIP(iface)
		items = append(items, Item{
			Name:  iface.Name,
			Desc:  fmt.Sprintf("IPv4: %s", ip),
			Iface: iface,
		})
	}

	templates := &promptui.SelectTemplates{
		Label:    "{{ . }}",
		Active:   "[*] {{ .Name | cyan }}",
		Inactive: "[ ] {{ .Name }}",
		Selected: "[+] Currently selected network interface => {{ .Name | green }}",
		Details: `---------
IP-Address:
  {{ .Desc }}`,
	}

	searcher := func(input string, index int) bool {
		item := items[index]
		name := strings.Replace(strings.ToLower(item.Name), " ", "", -1)
		input = strings.Replace(strings.ToLower(input), " ", "", -1)
		return strings.Contains(name, input)
	}

	prompt := promptui.Select{
		Label:     "Please select an interface (use the arrow keys to navigate)",
		Items:     items,
		Templates: templates,
		Size:      6,
		Searcher:  searcher,
		HideHelp: true,
	}

	idx, _, err := prompt.Run()
	if err != nil {
		return net.Interface{}, err
	}
	return items[idx].Iface, nil
}

func tracerouteReal(target string, maxHops int, timeoutSec int) []string {
    var cmd *exec.Cmd
    if runtime.GOOS == "windows" {
        timeoutMs := strconv.Itoa(timeoutSec * 1000)
        cmd = exec.Command("tracert", "-d", "-h", strconv.Itoa(maxHops), "-w", timeoutMs, target)
    } else {
        cmd = exec.Command("traceroute", "-n", "-m", strconv.Itoa(maxHops), "-w", strconv.Itoa(timeoutSec), target)
    }

    out, err := cmd.Output()
    if err != nil {
        fmt.Println("[!] Traceroute failed. Your machine may not have the tracert or traceroute command installed. Please install it and try again...:", err)
        return nil
    }

    lines := strings.Split(string(out), "\n")
    var hops []string

    ipRegex := regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}\b`)

    for _, line := range lines {
        ips := ipRegex.FindAllString(line, -1)
        if len(ips) > 0 {
            hops = append(hops, ips[0])
        }
    }
    return hops
}


func detectPrivateSegments(ipList []string) []string {
	segments := make(map[string]bool)
	for _, ipStr := range ipList {
		if strings.HasPrefix(ipStr, "192.168") {
			segments["192.168"] = true
		} else if strings.HasPrefix(ipStr, "172.16") {
			segments["172.16"] = true
		} else if strings.HasPrefix(ipStr, "10.0") {
			segments["10.0"] = true
		}
	}
	var result []string
	for k := range segments {
		result = append(result, k)
	}
	return result
}


func genTargetsForSegment(segment string) []string {
	parts := strings.Split(segment, ".")
	first := parts[0]
	second := "0"
	if len(parts) > 1 {
		second = parts[1]
	}
	targets := []string{}
	switch first {
	case "192":
		for c := 0; c <= 255; c++ {
			targets = append(targets, fmt.Sprintf("%s.%d.1", segment, c))
			targets = append(targets, fmt.Sprintf("%s.%d.254", segment, c))
		}
	case "172":
		for c := 0; c <= 255; c++ {
			targets = append(targets, fmt.Sprintf("%s.%d.1", first+"."+second, c))
			targets = append(targets, fmt.Sprintf("%s.%d.254", first+"."+second, c))
		}
	case "10":
		for b := 0; b <= 255; b++ {
			for c := 0; c <= 255; c++ {
				targets = append(targets, fmt.Sprintf("%s.%d.%d.1", first, b, c))
				targets = append(targets, fmt.Sprintf("%s.%d.%d.254", first, b, c))
			}
		}
	}
	return targets
}

func saveICMPResultSubnets(subnetMap map[string]bool, segment string) {
	dir := "./"
	switch {
	case strings.HasPrefix(segment, "10"):
		dir = "./A-10"
	case strings.HasPrefix(segment, "172"):
		dir = "./B-172"
	case strings.HasPrefix(segment, "192"):
		dir = "./C-192"
	}
	os.MkdirAll(dir, 0755)
	filename := filepath.Join(dir, startTimestamp+".nps")
	f, err := os.Create(filename)
	if err != nil {
		fmt.Println("[!] Failed to save log.", err)
		return
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for subnet := range subnetMap {
		w.WriteString(subnet + "\n")
	}
	w.Flush()
	fmt.Printf("[+] Log saved successfully:%s\n", filename)
}

func icmpScan(segment string) {
	targets := genTargetsForSegment(segment)
	total := len(targets)
	fmt.Printf("[*] Estimated number of targets: %d Concurrency: %d\n", total, defaultConcurrency)

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		fmt.Println("[!] Failed to open raw ICMP socket, please check permissions:", err)
		return
	}
	defer conn.Close()

	var lastReplyTime int64 = time.Now().Unix()  
	var mu sync.Mutex

 
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 1500)
		for {
			conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					mu.Lock()
					if time.Now().Unix()-lastReplyTime >= 5 {
						mu.Unlock()
						break
					}
					mu.Unlock()
					continue
				}
				continue
			}
			msg, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), buf[:n])
			if err != nil {
				continue
			}
			if msg.Type == ipv4.ICMPTypeEchoReply {
				ipStr := addr.String()
				host, _, _ := net.SplitHostPort(ipStr)
				if host != "" {
					alive.Store(host, true)
				} else {
					alive.Store(ipStr, true)
				}

				mu.Lock()
				lastReplyTime = time.Now().Unix() 
				mu.Unlock()
			}
		}
		close(done)
	}()

	bar := progressbar.Default(int64(total), "Scan Progress:")
	sem := make(chan struct{}, defaultConcurrency)
	var wg sync.WaitGroup

	for _, t := range targets {
		ip := net.ParseIP(t)
		if ip == nil {
			bar.Add(1)
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(dst net.IP) {
			defer wg.Done()
			defer func() { <-sem }()
			defer bar.Add(1)

			icmpID := rand.Intn(0xffff)
			icmpSeq := rand.Intn(0xffff)
			body := &icmp.Echo{ID: icmpID, Seq: icmpSeq, Data: []byte("PING")}
			msg := &icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: body}
			b, err := msg.Marshal(nil)
			if err != nil {
				return
			}
			dstAddr := &net.IPAddr{IP: dst}
			for i := 0; i < 3; i++ {
				conn.WriteTo(b, dstAddr)
				time.Sleep(5 * time.Millisecond)
			}
		}(ip)
	}
	wg.Wait()
	bar.Finish()

	fmt.Println("[*] Nightowl is processing results...")
	<-done 

	subnetMap := make(map[string]bool)
	alive.Range(func(key, _ interface{}) bool {
		ip := net.ParseIP(key.(string))
		if ip == nil {
			return true
		}
		parts := strings.Split(ip.String(), ".")
		if len(parts) != 4 {
			return true
		}
		subnet := fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
		subnetMap[subnet] = true
		return true
	})
	if len(subnetMap) == 0 {
		fmt.Println("[?] No active subnets detected.")
	} else {
		fmt.Printf("===================\n")
		for subnet := range subnetMap {
			fmt.Printf("[:)] %s\n", subnet)
		}
		saveICMPResultSubnets(subnetMap, segment)
		fmt.Printf("===================\n")
	}
}
const RED = "\033[31m"
const BLUE = "\033[34m"
const RESET = "\033[0m"
 
var LOGO = `
⢠⣴⣾⣿⣿⣶⣶⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣶⣶⣿⣿⣷⣦⡄
⠀⠉⠻⣿⣿⣿⣿⡟⠛⠷⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣴⠾⠛⢻⣿⣿⣿⣿⠟⠉⠀
⠀⠀⠀⠈⢻⣿⣿⣿⠀⠀⠈⠙⠳⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡴⠞⠋⠁⠀⠀⣿⣿⣿⡟⠁⠀⠀⠀
⠀⠀⠀⠀⠀⢻⣿⣿⡄⠀⠀⠀⠀⠀⠈⠑⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠊⠁⠀⠀⠀⠀⠀⢠⣿⣿⡟⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⡀⢹⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠄⠀⠀⠀⠀⠀⠀⠀⢸⣿⡏⢀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠘⢷⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⢶⣤⣄⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣠⣤⡶⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⡾⠃⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣌⣻⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠿⢿⣿⣿⣷⣶⣶⣶⣶⣶⣶⣾⣿⣿⣿⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣟⡡⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢸⣿⣿⢿⣆⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠛⠿⣿⣿⣿⣿⠿⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⣰⡿⣿⣿⡇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⣾⣿⠏⠀⢻⣷⣿⣄⠀⠀⠀⠀⠠⣀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠙⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠄⠀⠀⠀⠀⣠⣿⣾⡟⠀⠹⣿⣷⡀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⣾⣿⠏⠀⠀⠀⠙⠿⣿⣷⣦⣄⡀⠀⠈⠑⢦⣬⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣥⡴⠊⠁⠀⢀⣠⣴⣾⣿⠿⠋⠀⠀⠀⠹⣿⣷⡀⠀⠀⠀⠀
⠀⠀⠀⠀⣾⣿⠃⠀⠀⠀⠲⠶⠿⣿⣿⠿⠟⠛⠲⠄⠀⠐⠺⢿⣿⣶⣄⠀⠀⠀⠀⠀⠀⣠⣴⣿⡿⠗⠂⠀⠠⠖⠛⠻⠿⣿⣿⠿⠶⠖⠀⠀⠀⠘⣿⣷⠀⠀⠀⠀
⠀⠀⠀⢰⣿⠃⠀⠀⣠⠂⠀⠠⠚⢉⣤⣶⣿⣿⣿⣿⣶⣄⡀⠀⠈⠙⠻⣿⣶⣶⣶⣶⣿⠿⠛⠁⠀⢀⣤⣶⣿⣿⣿⣿⣶⣤⡉⠓⠄⠀⠐⢄⠀⠀⠘⣿⡆⠀⠀⠀
⠀⠀⠀⢸⠇⠀⢀⣾⠁⠀⠀⠀⠀⠻⣿⡿⠋` + RED + "⢡⣿⣿⠟" + RESET + `⢿⣷⡄⠀⠀⣄⢀⠙⠿⡿⠋⡁⢠⠀⠀⢠⣾` + BLUE + "⣿⣿⡿⠻⡌" + RESET + `⠙⢿⣿⠟⠀⠀⠀⠀⠈⢷⡄⠀⢸⡇⠀⠀⠀
⠀⠀⠀⢸⠀⠀⣼⣷⠀⠀⠀⠀⠀⠀⠸⣇⠀` + RED + "⠸⣿⣿⣷⡾" + RESET + `⠙⢿⡄⠀⠈⠳⣷⣤⣤⣾⡞⠁⠀⢠⡿⠉` + BLUE + "⢿⣿⣿⣾⠇" + RESET + `⠀⣸⠇⠀⠀⠀⠀⠀⠀⣾⣷⠀⠀⡇⠀⠀⠀
⠀⠀⠀⢸⠀⠀⣸⡟⠀⠀⠀⠀⠀⠀⠀⠹⣄⠀` + RED + "⠈⠉⠉" + RESET + `⣀⣴⣿⡷⠀⠀⠀⠈⠛⠛⠁⠀⠀⠀⢿⣿⣦⣀` + BLUE + "⠉⠉⠁" + RESET + `⠀⣰⠏⠀⠀⠀⠀⠀⠀⠀⢹⣇⠀⠀⡇⠀⠀⠀
⠀⠀⠀⠸⠀⠀⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠈⠙⠛⠋⠩⠕⠛⠁⠀⠀⠀⠀⢠⣾⠻⡄⠀⠀⠀⠀⠈⠛⠪⠍⠛⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⠀⠀⠇⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠘⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⠀⢿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⠋⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢸⣿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⠘⢿⣿⣄⣄⠀⠀⠀⠀⠀⠠⠤⢤⣤⡀⠀⠀⠀⠀⠀⢸⣿⢰⡏⠀⠀⠀⠀⠀⢀⣤⡤⠤⠤⠀⠀⠀⠀⠀⢠⣄⣿⡿⠃⠁⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠿⠿⠿⠶⢄⡀⠀⠀⠐⠒⠒⠾⢿⣷⣄⠀⠀⠀⠈⣿⣿⠁⠀⠀⠀⣠⣾⡿⠷⠒⠒⠂⠀⠀⢀⡠⠶⠿⠿⠿⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣷⣄⠀⠀⢹⡏⠀⠀⣠⣾⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢷⣦⣄⣠⣴⡾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⠿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
     <<Nightowl>>  		(Network Path Segment Leakage Hunter)
@https://github.com/MartinxMax/     Maptnh@S-H4CK13
===============================================================================`
 
func main() {
	fmt.Println(LOGO)
	ensurePrivilege()
	startTimestamp = time.Now().Format("20060102")
	rand.Seed(time.Now().UnixNano())
	_, err := selectInterfacePrompt()
	if err != nil {
		fmt.Println("[!] Exit.....")
		return
	}
	//ip, _ := getInterfaceIP(iface)
	fmt.Println("[*] Tracing route...")
	tracerouteIPs :=  tracerouteReal("84.200.69.80", 5, 5)
	fmt.Println("[+] Traceroute Table:", tracerouteIPs)
	segments := detectPrivateSegments(tracerouteIPs)
	if len(segments) == 0 {
		fmt.Println("[!] No route path found, exiting...")
		return
	}

 
	prompt := promptui.Select{
		Label: "Please select the network segment to scan (use the arrow keys to navigate)",
		Items: segments,
		HideHelp: true,
	}
	_, selectedSegment, err := prompt.Run()
	if err != nil {
		fmt.Println("[!] Failed to select network segment:", err)
		return
	}
	fmt.Printf("[*] Tracing active subnets => [ %s ]\n", selectedSegment)
	icmpScan(selectedSegment)
}
