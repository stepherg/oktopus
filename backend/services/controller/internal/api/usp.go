package api

import (
	"io"
	"log"
	"net/http"

	"github.com/google/uuid"
	"github.com/leandrofars/oktopus/internal/bridge"
	local "github.com/leandrofars/oktopus/internal/nats"
	"github.com/leandrofars/oktopus/internal/usp/usp_msg"
	"github.com/leandrofars/oktopus/internal/usp/usp_record"
	"github.com/leandrofars/oktopus/internal/usp/usp_utils"
	"github.com/leandrofars/oktopus/internal/utils"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func sendUspMsg(msg *usp_msg.Msg, sn string, w http.ResponseWriter, nc *nats.Conn, mtp, fromID, toID string) error {

	protoMsg, err := proto.Marshal(msg)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(utils.Marshall(err.Error()))
		return err
	}

	record := usp_utils.NewUspRecordWithOverrides(protoMsg, sn, fromID, toID)
	protoRecord, err := proto.Marshal(&record)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(utils.Marshall(err.Error()))
		return err
	}

	data, err := bridge.NatsUspInteraction(
		local.DEVICE_SUBJECT_PREFIX+sn+".api",
		mtp+"-adapter.usp.v1."+sn+".api",
		protoRecord,
		w,
		nc,
	)
	if err != nil {
		return err
	}

	var receivedRecord usp_record.Record
	err = proto.Unmarshal(data, &receivedRecord)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(utils.Marshall(err.Error()))
		return err
	}
	var receivedMsg usp_msg.Msg
	err = proto.Unmarshal(receivedRecord.GetNoSessionContext().Payload, &receivedMsg)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(utils.Marshall(err.Error()))
		return err
	}

	body := receivedMsg.Body.GetResponse()
	if body == nil {
		errorMsg := receivedMsg.Body.GetError()
		if errorMsg == nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Println("No response body or error")
			return nil
		}
		_, _ = w.Write(utils.Marshall(errorMsg))
		return nil
	}

	switch body.RespType.(type) {
	case *usp_msg.Response_GetResp:
		utils.MarshallEncoder(body.GetGetResp(), w)
	case *usp_msg.Response_DeleteResp:
		utils.MarshallEncoder(body.GetDeleteResp(), w)
	case *usp_msg.Response_AddResp:
		utils.MarshallEncoder(body.GetAddResp(), w)
	case *usp_msg.Response_SetResp:
		utils.MarshallEncoder(body.GetSetResp(), w)
	case *usp_msg.Response_GetInstancesResp:
		utils.MarshallEncoder(body.GetGetInstancesResp(), w)
	case *usp_msg.Response_GetSupportedDmResp:
		utils.MarshallEncoder(body.GetGetSupportedDmResp(), w)
	case *usp_msg.Response_GetSupportedProtocolResp:
		utils.MarshallEncoder(body.GetGetSupportedProtocolResp(), w)
	case *usp_msg.Response_NotifyResp:
		utils.MarshallEncoder(body.GetNotifyResp(), w)
	case *usp_msg.Response_OperateResp:
		utils.MarshallEncoder(body.GetOperateResp(), w)
	default:
		utils.MarshallEncoder("Unknown message answer", w)
	}

	return nil
}

// uspOverrides reads optional USP Record header overrides from query parameters.
// ?usp_from_id=<value> overrides the from_id field in the outgoing USP Record.
// ?usp_to_id=<value>  overrides the to_id  field in the outgoing USP Record.
// An empty string means "use the controller default".
func uspOverrides(r *http.Request) (fromID, toID string) {
	return r.URL.Query().Get("usp_from_id"), r.URL.Query().Get("usp_to_id")
}

func (a *Api) deviceGenericMessage(w http.ResponseWriter, r *http.Request) {

	sn := getSerialNumberFromRequest(r)
	mtp, err := getMtpFromRequest(r, w)
	if err != nil {
		return
	}

	if mtp == "" {
		var ok bool
		mtp, ok = deviceStateOK(w, a.nc, sn)
		if !ok {
			return
		}
	}

	payload, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(utils.Marshall(err.Error()))
		return
	}

	var msg usp_msg.Msg

	err = protojson.Unmarshal(payload, &msg)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(utils.Marshall(err.Error()))
		return
	}

	fromID, toID := uspOverrides(r)
	err = sendUspMsg(&msg, sn, w, a.nc, mtp, fromID, toID)
	if err != nil {
		return
	}
}

func (a *Api) deviceGetMsg(w http.ResponseWriter, r *http.Request) {

	sn := getSerialNumberFromRequest(r)
	mtp, err := getMtpFromRequest(r, w)
	if err != nil {
		return
	}

	if mtp == "" {
		var ok bool
		mtp, ok = deviceStateOK(w, a.nc, sn)
		if !ok {
			return
		}
	}

	var get usp_msg.Get

	_ = utils.MarshallDecoder(&get, r.Body)
	msg := usp_utils.NewGetMsg(&get)

	fromID, toID := uspOverrides(r)
	err = sendUspMsg(&msg, sn, w, a.nc, mtp, fromID, toID)
	if err != nil {
		return
	}
}

func (a *Api) deviceGetSupportedParametersMsg(w http.ResponseWriter, r *http.Request) {

	sn := getSerialNumberFromRequest(r)
	mtp, err := getMtpFromRequest(r, w)
	if err != nil {
		return
	}

	if mtp == "" {
		var ok bool
		mtp, ok = deviceStateOK(w, a.nc, sn)
		if !ok {
			return
		}
	}

	var getSupportedDM usp_msg.GetSupportedDM

	_ = utils.MarshallDecoder(&getSupportedDM, r.Body)
	msg := usp_utils.NewGetSupportedParametersMsg(&getSupportedDM)

	fromID, toID := uspOverrides(r)
	err = sendUspMsg(&msg, sn, w, a.nc, mtp, fromID, toID)
	if err != nil {
		return
	}
}

func (a *Api) deviceOperateMsg(w http.ResponseWriter, r *http.Request) {

	sn := getSerialNumberFromRequest(r)
	mtp, err := getMtpFromRequest(r, w)
	if err != nil {
		return
	}

	if mtp == "" {
		var ok bool
		mtp, ok = deviceStateOK(w, a.nc, sn)
		if !ok {
			return
		}
	}

	var operate usp_msg.Operate

	_ = utils.MarshallDecoder(&operate, r.Body)
	msg := usp_utils.NewOperateMsg(&operate)

	fromID, toID := uspOverrides(r)
	err = sendUspMsg(&msg, sn, w, a.nc, mtp, fromID, toID)
	if err != nil {
		return
	}
}

func (a *Api) deviceNotifyMsg(w http.ResponseWriter, r *http.Request) {

	sn := getSerialNumberFromRequest(r)
	mtp, err := getMtpFromRequest(r, w)
	if err != nil {
		return
	}

	if mtp == "" {
		var ok bool
		mtp, ok = deviceStateOK(w, a.nc, sn)
		if !ok {
			return
		}
	}

	// var notify usp_msg.Notify
	notify := usp_msg.Notify{
		SubscriptionId: uuid.NewString(),
		SendResp:       true,
		Notification: &usp_msg.Notify_Event_{
			Event: &usp_msg.Notify_Event{
				EventName: "Push!",
				ObjPath:   "Device.BulkData.Profile.1.",
			},
		},
	}

	log.Printf("Notify %s:", notify.String())

	msg := usp_utils.NewNotifyMsg(&notify)

	fromID, toID := uspOverrides(r)
	err = sendUspMsg(&msg, sn, w, a.nc, mtp, fromID, toID)
	if err != nil {
		return
	}
}

func (a *Api) deviceUpdateMsg(w http.ResponseWriter, r *http.Request) {

	sn := getSerialNumberFromRequest(r)
	mtp, err := getMtpFromRequest(r, w)
	if err != nil {
		return
	}

	if mtp == "" {
		var ok bool
		mtp, ok = deviceStateOK(w, a.nc, sn)
		if !ok {
			return
		}
	}

	var set usp_msg.Set

	_ = utils.MarshallDecoder(&set, r.Body)
	msg := usp_utils.NewSetMsg(&set)

	fromID, toID := uspOverrides(r)
	err = sendUspMsg(&msg, sn, w, a.nc, mtp, fromID, toID)
	if err != nil {
		return
	}
}

func (a *Api) deviceGetParameterInstances(w http.ResponseWriter, r *http.Request) {

	sn := getSerialNumberFromRequest(r)
	mtp, err := getMtpFromRequest(r, w)
	if err != nil {
		return
	}

	if mtp == "" {
		var ok bool
		mtp, ok = deviceStateOK(w, a.nc, sn)
		if !ok {
			return
		}
	}

	var getInstances usp_msg.GetInstances

	_ = utils.MarshallDecoder(&getInstances, r.Body)
	msg := usp_utils.NewGetParametersInstancesMsg(&getInstances)

	fromID, toID := uspOverrides(r)
	err = sendUspMsg(&msg, sn, w, a.nc, mtp, fromID, toID)
	if err != nil {
		return
	}
}

func (a *Api) deviceCreateMsg(w http.ResponseWriter, r *http.Request) {

	sn := getSerialNumberFromRequest(r)
	mtp, err := getMtpFromRequest(r, w)
	if err != nil {
		return
	}

	if mtp == "" {
		var ok bool
		mtp, ok = deviceStateOK(w, a.nc, sn)
		if !ok {
			return
		}
	}

	var add usp_msg.Add

	_ = utils.MarshallDecoder(&add, r.Body)
	msg := usp_utils.NewCreateMsg(&add)

	fromID, toID := uspOverrides(r)
	err = sendUspMsg(&msg, sn, w, a.nc, mtp, fromID, toID)
	if err != nil {
		return
	}
}

func (a *Api) deviceDeleteMsg(w http.ResponseWriter, r *http.Request) {

	sn := getSerialNumberFromRequest(r)
	mtp, err := getMtpFromRequest(r, w)
	if err != nil {
		return
	}

	if mtp == "" {
		var ok bool
		mtp, ok = deviceStateOK(w, a.nc, sn)
		if !ok {
			return
		}
	}

	var del usp_msg.Delete

	_ = utils.MarshallDecoder(&del, r.Body)
	msg := usp_utils.NewDelMsg(&del)

	fromID, toID := uspOverrides(r)
	err = sendUspMsg(&msg, sn, w, a.nc, mtp, fromID, toID)
	if err != nil {
		return
	}
}
