package main

import (
	"fmt"

	NVD_API_handler "github.com/kaustgen/Integrating_AI_OSINT/NVD_getters"
)

func main() {
	NVD_API_handler.PrintCVEs()
	fmt.Println()
}
