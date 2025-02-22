package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
)

var (
	interfacesFile = "network_interfaces.json"
	devicesFile    = "network_devices.json"
	whitelistFile  = "ip_whitelist.json"
	netcutFile     = "netcut_ips.json"

	activeThreads sync.WaitGroup
	stopCh        = make(chan struct{})
)

type NetworkInterface struct {
	Index int    `json:"index"`
	Name  string `json:"name"`
	GUID  string `json:"guid"`
	Flags string `json:"flags"`
}

type Device struct {
	IP   string `json:"ip"`
	MAC  string `json:"mac"`
	Host string `json:"host"`
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/scan_interfaces", logRequest(scanInterfaces)).Methods("GET")
	r.HandleFunc("/interface_data", logRequest(getInterfaceData)).Methods("GET")
	r.HandleFunc("/scan_network", logRequest(scanNetwork)).Methods("GET")
	r.HandleFunc("/start_netcut", logRequest(startNetcut)).Methods("POST")
	r.HandleFunc("/stop_netcut", logRequest(stopNetcut)).Methods("POST")
	r.HandleFunc("/whitelist", logRequest(addToWhitelist)).Methods("POST")
	r.HandleFunc("/whitelist", logRequest(removeFromWhitelist)).Methods("DELETE")
	r.HandleFunc("/whitelist", logRequest(getWhitelist)).Methods("GET")
	r.HandleFunc("/help", logRequest(help)).Methods("GET")

	fmt.Println("Server is running on port 5000")
	http.ListenAndServe(":5000", r)
}

func logRequest(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received %s request for %s", r.Method, r.URL.Path)
		handler(w, r)
	}
}

func scanInterfaces(w http.ResponseWriter, r *http.Request) {
	ifaces, err := net.Interfaces()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var interfaces []NetworkInterface
	for _, iface := range ifaces {
		interfaces = append(interfaces, NetworkInterface{Name: iface.Name, GUID: iface.HardwareAddr.String(), Flags: iface.Flags.String(), Index: iface.Index})
	}

	saveToJSON(interfacesFile, interfaces)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "Success Scan interfaces"})
}

func getInterfaceData(w http.ResponseWriter, r *http.Request) {
	var interfaces []NetworkInterface
	loadFromJSON(interfacesFile, &interfaces)
	json.NewEncoder(w).Encode(interfaces)
}

func scanNetwork(w http.ResponseWriter, r *http.Request) {
	var devices []Device

	// Run ARP scan to get IP-MAC mappings
	cmd := exec.Command("arp", "-a")
	output, err := cmd.Output()
	if err != nil {
		http.Error(w, "Failed to execute ARP scan", http.StatusInternalServerError)
		return
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			ip := strings.Trim(fields[0], "()")
			mac := fields[1]
			devices = append(devices, Device{IP: ip, MAC: mac, Host: ""})
		}
	}

	// Encode the result as JSON and send response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(devices)
}

func startNetcut(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Interface  int      `json:"interface"`
		TargetIPs  []string `json:"target_ips"`
		NumThreads int      `json:"num_threads"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Start ARP spoofing in a new goroutine
	go arpSpoofingManager(req.TargetIPs, req.NumThreads)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ARP spoofing started"})
}

func stopNetcut(w http.ResponseWriter, r *http.Request) {
	close(stopCh)
	activeThreads.Wait()
	stopCh = make(chan struct{})
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ARP spoofing stopped"})
}

func addToWhitelist(w http.ResponseWriter, r *http.Request) {
	var ips []string
	if err := json.NewDecoder(r.Body).Decode(&ips); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var whitelist []string
	loadFromJSON(whitelistFile, &whitelist)
	whitelist = append(whitelist, ips...)
	saveToJSON(whitelistFile, whitelist)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "IPs added to whitelist"})
}

func removeFromWhitelist(w http.ResponseWriter, r *http.Request) {
	var ips []string
	if err := json.NewDecoder(r.Body).Decode(&ips); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var whitelist []string
	loadFromJSON(whitelistFile, &whitelist)
	var newWhitelist []string
	for _, ip := range whitelist {
		if !contains(ips, ip) {
			newWhitelist = append(newWhitelist, ip)
		}
	}
	saveToJSON(whitelistFile, newWhitelist)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "IPs removed from whitelist"})
}

func getWhitelist(w http.ResponseWriter, r *http.Request) {
	var whitelist []string
	loadFromJSON(whitelistFile, &whitelist)
	json.NewEncoder(w).Encode(whitelist)
}

func help(w http.ResponseWriter, r *http.Request) {
	helpInfo := map[string]interface{}{
		"description": "Custom NetCut API for ARP spoofing",
		"endpoints": map[string]interface{}{
			"/scan_interfaces": map[string]string{
				"method":      "GET",
				"description": "Scan available network interfaces and save them to JSON.",
			},
			"/scan_network": map[string]interface{}{
				"method":      "GET",
				"description": "Scan devices on the network, excluding whitelisted IPs.",
				"parameters": map[string]string{
					"interface": "Index of the network interface (default is 0).",
				},
			},
			"/start_netcut": map[string]interface{}{
				"method":      "POST",
				"description": "Start ARP spoofing on the specified IPs.",
				"parameters": map[string]string{
					"interface":   "Index of the network interface.",
					"target_ips":  "List of IPs or 'all' to target all scanned devices.",
					"num_threads": "Number of threads to use (default is 10).",
				},
			},
			"/stop_netcut": map[string]string{
				"method":      "POST",
				"description": "Stop all running ARP spoofing attacks.",
			},
			"/whitelist": map[string]interface{}{
				"GET": map[string]string{
					"description": "Get the list of whitelisted IPs.",
				},
				"POST": map[string]interface{}{
					"description": "Add an IP to the whitelist, stopping ARP spoofing if it is running.",
					"parameters": map[string]string{
						"ip": "The IP address to be added to the whitelist.",
					},
				},
				"DELETE": map[string]interface{}{
					"description": "Remove an IP from the whitelist, stopping ARP spoofing if it is running.",
					"parameters": map[string]string{
						"ip": "The IP address to be removed from the whitelist.",
					},
				},
			},
			"/help": map[string]string{
				"method":      "GET",
				"description": "Display this help message.",
			},
		},
		"note": "Ensure you have permission to perform network scanning and ARP spoofing on the network you are testing.",
	}
	json.NewEncoder(w).Encode(helpInfo)
}

func arpSpoofingManager(targetIPs []string, numThreads int) {
	for _, ip := range targetIPs {
		activeThreads.Add(1)
		go func(ip string) {
			defer activeThreads.Done()
			for {
				select {
				case <-stopCh:
					return
				default:
					// Simulate ARP spoofing
					fmt.Printf("Spoofing IP: %s\n", ip)
					time.Sleep(1 * time.Second)
				}
			}
		}(ip)
	}
}

func saveToJSON(filename string, data interface{}) {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		log.Fatal(err)
	}
}

func loadFromJSON(filename string, data interface{}) {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(data); err != nil {
		log.Fatal(err)
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
