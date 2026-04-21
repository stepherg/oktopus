package handler

import (
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"oktopUSP/backend/services/acs/internal/auth"
	"oktopUSP/backend/services/acs/internal/cwmp"
	"time"

	"github.com/oleiade/lane"
)

func (h *Handler) CwmpHandler(w http.ResponseWriter, r *http.Request) {

	log.Printf("--> Connection from %s", r.RemoteAddr)

	defer func() { _ = r.Body.Close() }()
	defer log.Printf("<-- Connection from %s closed", r.RemoteAddr)

	tmp, _ := io.ReadAll(r.Body)
	body := string(tmp)

	if h.acsConfig.DebugMode {
		log.Println("Received message: ", body)
	}

	var envelope cwmp.SoapEnvelope
	if err := xml.Unmarshal(tmp, &envelope); err != nil {
		log.Println("xml unmarshal error:", err)
	}

	messageType := envelope.Body.CWMPMessage.XMLName.Local
	log.Println("messageType: ", messageType)

	var cpe *CPE
	var exists bool

	w.Header().Set("Server", "Oktopus "+Version)

	if messageType != "Inform" {
		if cookie, err := r.Cookie("oktopus"); err == nil {
			if cpe, exists = h.GetCPE(cookie.Value); !exists {
				log.Printf("CPE with serial number %s not found", cookie.Value)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			log.Printf("CPE with serial number %s found", cookie.Value)
		} else {
			fmt.Println("cookie 'oktopus' missing")
			w.WriteHeader(401)
			return
		}
	}

	switch messageType {
	case "Inform":
		var Inform cwmp.CWMPInform
		if err := xml.Unmarshal(tmp, &Inform); err != nil {
			log.Println("xml unmarshal error:", err)
		}

		var addr string
		if r.Header.Get("X-Real-Ip") != "" {
			addr = r.Header.Get("X-Real-Ip")
		} else {
			addr = r.RemoteAddr
		}

		sn := Inform.DeviceId.SerialNumber

		if cpe, exists = h.GetCPE(sn); !exists {
			log.Println("New device: " + sn)
			cpe = &CPE{
				SerialNumber:         sn,
				SoftwareVersion:      Inform.GetSoftwareVersion(),
				HardwareVersion:      Inform.GetHardwareVersion(),
				ExternalIPAddress:    addr,
				ConnectionRequestURL: Inform.GetConnectionRequest(),
				OUI:                  Inform.DeviceId.OUI,
				Queue:                lane.NewQueue(),
				DataModel:            Inform.GetDataModelType(),
			}
			h.PutCPE(cpe)
			h.pub(NATS_CWMP_SUBJECT_PREFIX+sn+".info", tmp) //nolint:errcheck
		}

		cpe.mu.Lock()
		cpe.ConnectionRequestURL = Inform.GetConnectionRequest()
		cpe.SoftwareVersion = Inform.GetSoftwareVersion()
		cpe.HardwareVersion = Inform.GetHardwareVersion()
		cpe.ExternalIPAddress = addr
		cpe.OUI = Inform.DeviceId.OUI
		cpe.DataModel = Inform.GetDataModelType()
		cpe.LastConnection = time.Now()
		cpe.mu.Unlock()

		log.Printf("Received an Inform from device %s withEventCodes %s", addr, Inform.GetEvents())

		expiration := time.Now().AddDate(0, 0, 1)

		cookie := http.Cookie{Name: "oktopus", Value: sn, Expires: expiration}
		http.SetCookie(w, &cookie)
		//data, _ := xml.Marshal(cwmp.InformResponse(envelope.Header.Id))
		_, _ = fmt.Fprint(w, cwmp.InformResponse(envelope.Header.Id))

	case "TransferComplete":

	case "GetRPC":

	default:

		if len(body) == 0 {
			log.Println("Got Empty Post")
		}

		cpe.mu.Lock()
		waiting := cpe.Waiting
		queueSize := cpe.Queue.Size()
		var nextReq *Request
		if queueSize > 0 {
			req := cpe.Queue.Dequeue().(Request)
			cpe.Waiting = &req
			nextReq = &req
		} else {
			cpe.Waiting = nil
		}
		cpe.LastConnection = time.Now()
		cpe.mu.Unlock()

		if waiting != nil {

			log.Println("ACS was waiting for a response from the CPE, now received something")

			var e cwmp.SoapEnvelope
			if err := xml.Unmarshal([]byte(body), &e); err != nil {
				log.Println("xml unmarshal error:", err)
			}
			log.Println("Kind of envelope: ", e.KindOf())

			if e.KindOf() == "GetParameterNamesResponse" {
				log.Println("Receive GetParameterNamesResponse from CPE:", cpe.SerialNumber)
				msgAnswer(waiting.Callback, waiting.Time, h.acsConfig.DeviceAnswerTimeout, tmp)
			} else if e.KindOf() == "GetParameterValuesResponse" {
				log.Println("Receive GetParameterValuesResponse from CPE:", cpe.SerialNumber)
				msgAnswer(waiting.Callback, waiting.Time, h.acsConfig.DeviceAnswerTimeout, tmp)
			} else if e.KindOf() == "SetParameterValuesResponse" {
				log.Println("Receive SetParameterValuesResponse from CPE:", cpe.SerialNumber)
				msgAnswer(waiting.Callback, waiting.Time, h.acsConfig.DeviceAnswerTimeout, tmp)
			} else if e.KindOf() == "Fault" {
				log.Println("Receive FaultResponse from CPE:", cpe.SerialNumber)
				msgAnswer(waiting.Callback, waiting.Time, h.acsConfig.DeviceAnswerTimeout, tmp)
				log.Println(body)
			} else {
				log.Println("Unknown message type")
				log.Println("Body:", body)
				msgAnswer(waiting.Callback, waiting.Time, h.acsConfig.DeviceAnswerTimeout, tmp)
			}
		} else {
			log.Println("CPE was not waiting for a response")
		}

		log.Printf("CPE %s Queue size: %d", cpe.SerialNumber, queueSize)

		if nextReq != nil {
			log.Println("Sending request to CPE:", nextReq.Id)
			w.Header().Set("Connection", "keep-alive")
			_, _ = w.Write(nextReq.CwmpMsg)
		} else {
			w.Header().Set("Connection", "close")
			w.WriteHeader(204)
		}
	}
}

func (h *Handler) ConnectionRequest(cpe *CPE) error {
	serialNumber, connectionRequestURL := cpe.ConnectionRequestDetails()
	log.Println("--> ConnectionRequest, CPE: ", serialNumber)
	// log.Println("ConnectionRequestURL: ", cpe.ConnectionRequestURL)
	// log.Println("ConnectionRequestUsername: ", cpe.Username)
	// log.Println("ConnectionRequestPassword: ", cpe.Password)

	ok, err := auth.Auth(h.acsConfig.ConnReqUsername, h.acsConfig.ConnReqPassword, connectionRequestURL)
	if !ok {
		log.Println("Error while authenticating to CPE, err:", err)
	} else {
		log.Println("<-- Successfully authenticated to CPE", serialNumber)
	}

	return err
}

func msgAnswer(
	callback chan []byte,
	timeMsgWasSent time.Time,
	timeOut time.Duration,
	msgAnswer []byte,
) {
	if time.Since(timeMsgWasSent) > timeOut {
		log.Println("CPE took too long to answer the request, the message will be discarded")
	} else {
		callback <- msgAnswer
	}
}
