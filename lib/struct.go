package lib

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

type Whitelist struct {
	IPs []string `json:"ips"`
}
