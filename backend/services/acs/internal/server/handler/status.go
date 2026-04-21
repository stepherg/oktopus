package handler

import (
	"log"
	"time"
)

func (h *Handler) HandleCpeStatus() {
	for {
		for _, cpe := range h.SnapshotCPEs() {
			if cpe == nil {
				continue
			}

			cpe.mu.Lock()
			serialNumber := cpe.SerialNumber
			lastConnection := cpe.LastConnection
			cpe.mu.Unlock()

			if serialNumber == "" {
				continue
			}
			if h.acsConfig.DebugMode {
				log.Println("Checking CPE " + serialNumber + " status")
			}
			if time.Since(lastConnection) > h.acsConfig.KeepAliveInterval {
				log.Printf("LastConnection: %s, KeepAliveInterval: %s", lastConnection, h.acsConfig.KeepAliveInterval)
				log.Println("CPE", serialNumber, "is offline")
				h.pub("cwmp.v1."+serialNumber+".status", []byte("0")) //nolint:errcheck
				h.DeleteCPE(serialNumber)
				break
			}
		}
		time.Sleep(10 * time.Second)
	}
}
