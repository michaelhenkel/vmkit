package main

import (
	"github.com/michaelhenkel/vmkit/cmd"
	log "github.com/sirupsen/logrus"
)

func main() {
	log.SetReportCaller(false)
	cmd.Execute()
}
