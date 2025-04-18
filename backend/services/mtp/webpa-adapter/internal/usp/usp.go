package usp

import (
	"github.com/OktopUSP/oktopus/backend/services/mtp/webpa-adapter/internal/usp/usp_msg"
	"github.com/OktopUSP/oktopus/backend/services/mtp/webpa-adapter/internal/usp/usp_record"
	"github.com/google/uuid"
)

const VERSION = "1.0"

func NewUspRecord(p []byte, toId, fromId string) usp_record.Record {
	return usp_record.Record{
		Version:         VERSION,
		ToId:            toId,
		FromId:          fromId,
		PayloadSecurity: usp_record.Record_PLAINTEXT,
		RecordType: &usp_record.Record_NoSessionContext{
			NoSessionContext: &usp_record.NoSessionContextRecord{
				Payload: p,
			},
		},
	}
}

func NewCreateMsg(createStuff usp_msg.Add) usp_msg.Msg {
	return usp_msg.Msg{
		Header: &usp_msg.Header{
			MsgId:   uuid.NewString(),
			MsgType: usp_msg.Header_ADD,
		},
		Body: &usp_msg.Body{
			MsgBody: &usp_msg.Body_Request{
				Request: &usp_msg.Request{
					ReqType: &usp_msg.Request_Add{
						Add: &createStuff,
					},
				},
			},
		},
	}
}

func NewGetMsg(getStuff usp_msg.Get) usp_msg.Msg {
	return usp_msg.Msg{
		Header: &usp_msg.Header{
			MsgId:   uuid.NewString(),
			MsgType: usp_msg.Header_GET,
		},
		Body: &usp_msg.Body{
			MsgBody: &usp_msg.Body_Request{
				Request: &usp_msg.Request{
					ReqType: &usp_msg.Request_Get{
						Get: &getStuff,
					},
				},
			},
		},
	}
}

func NewDelMsg(getStuff usp_msg.Delete) usp_msg.Msg {
	return usp_msg.Msg{
		Header: &usp_msg.Header{
			MsgId:   uuid.NewString(),
			MsgType: usp_msg.Header_DELETE,
		},
		Body: &usp_msg.Body{
			MsgBody: &usp_msg.Body_Request{
				Request: &usp_msg.Request{
					ReqType: &usp_msg.Request_Delete{
						Delete: &getStuff,
					},
				},
			},
		},
	}
}

func NewSetMsg(updateStuff usp_msg.Set) usp_msg.Msg {
	return usp_msg.Msg{
		Header: &usp_msg.Header{
			MsgId:   uuid.NewString(),
			MsgType: usp_msg.Header_SET,
		},
		Body: &usp_msg.Body{
			MsgBody: &usp_msg.Body_Request{
				Request: &usp_msg.Request{
					ReqType: &usp_msg.Request_Set{
						Set: &updateStuff,
					},
				},
			},
		},
	}
}

func NewGetSupportedParametersMsg(getStuff usp_msg.GetSupportedDM) usp_msg.Msg {
	return usp_msg.Msg{
		Header: &usp_msg.Header{
			MsgId:   uuid.NewString(),
			MsgType: usp_msg.Header_GET_SUPPORTED_DM,
		},
		Body: &usp_msg.Body{
			MsgBody: &usp_msg.Body_Request{
				Request: &usp_msg.Request{
					ReqType: &usp_msg.Request_GetSupportedDm{
						GetSupportedDm: &getStuff,
					},
				},
			},
		},
	}
}

func NewGetParametersInstancesMsg(getStuff usp_msg.GetInstances) usp_msg.Msg {
	return usp_msg.Msg{
		Header: &usp_msg.Header{
			MsgId:   uuid.NewString(),
			MsgType: usp_msg.Header_GET_INSTANCES,
		},
		Body: &usp_msg.Body{
			MsgBody: &usp_msg.Body_Request{
				Request: &usp_msg.Request{
					ReqType: &usp_msg.Request_GetInstances{
						GetInstances: &getStuff,
					},
				},
			},
		},
	}
}

func NewOperateMsg(getStuff usp_msg.Operate) usp_msg.Msg {
	return usp_msg.Msg{
		Header: &usp_msg.Header{
			MsgId:   uuid.NewString(),
			MsgType: usp_msg.Header_OPERATE,
		},
		Body: &usp_msg.Body{
			MsgBody: &usp_msg.Body_Request{
				Request: &usp_msg.Request{
					ReqType: &usp_msg.Request_Operate{
						Operate: &getStuff,
					},
				},
			},
		},
	}
}
