package main

import (
	"encoding/json"
	"log"
	"os"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
)

var users = map[string]string{
	"testusername": "testpassword",
}

var sharedSecret = []byte("mysharedsecret")
var logger *log.Logger

type LogEntry struct {
	Timestamp   string                 `json:"timestamp"`
	RemoteAddr  string                 `json:"remote_addr"`
	HandlerType string                 `json:"handler"`
	Username    string                 `json:"username"`
	Code        string                 `json:"code"`
	StatusType  string                 `json:"status_type,omitempty"`
	Extra       map[string]interface{} `json:"extra,omitempty"`
	SessionId   string                 `json:"session_id,omitempty"`
}

func logRequest(r *radius.Request, handler string, code radius.Code, statusType string) {
	username := rfc2865.UserName_GetString(r.Packet)
	sessionId := rfc2866.AcctSessionID_GetString(r.Packet)
	entry := LogEntry{
		Timestamp:   time.Now().Format(time.RFC3339),
		RemoteAddr:  r.RemoteAddr.String(),
		HandlerType: handler,
		Username:    username,
		Code:        code.String(),
		StatusType:  statusType,
		SessionId:   sessionId,
	}

	data, _ := json.Marshal(entry)
	logger.Println(string(data))
}

func accessHandler(w radius.ResponseWriter, r *radius.Request) {
	username := rfc2865.UserName_GetString(r.Packet)
	password := rfc2865.UserPassword_GetString(r.Packet)

	pswd, exists := users[username]
	var code radius.Code

	if !exists || pswd != password {
		code = radius.CodeAccessReject
	} else {
		code = radius.CodeAccessAccept
	}

	logRequest(r, "access", code, "")
	w.Write(r.Response(code))
}

func accountingHandler(w radius.ResponseWriter, r *radius.Request) {
	statusType := rfc2866.AcctStatusType_Get(r.Packet)

	var statusStr string
	switch statusType {
	case rfc2866.AcctStatusType_Value_Start:
		statusStr = "Start"
	case rfc2866.AcctStatusType_Value_Stop:
		statusStr = "Stop"
	case rfc2866.AcctStatusType_Value_InterimUpdate:
		statusStr = "Interim-Update"
	default:
		statusStr = "Unknown"
	}

	logRequest(r, "accounting", radius.CodeAccountingResponse, statusStr)
	w.Write(r.Response(radius.CodeAccountingResponse))
}

func coaHandler(w radius.ResponseWriter, r *radius.Request) {
	code := r.Packet.Code

	if code == radius.CodeDisconnectRequest {
		logRequest(r, "coa/disconnect", radius.CodeDisconnectACK, "")
		w.Write(r.Response(radius.CodeDisconnectACK))
		return
	}

	if code == radius.CodeCoARequest {
		logRequest(r, "coa", radius.CodeCoAACK, "")
		w.Write(r.Response(radius.CodeCoAACK))
		return
	}

	logRequest(r, "coa", radius.CodeCoANAK, "")
	w.Write(r.Response(radius.CodeCoANAK))
}

func setupLogger() {
	f, err := os.OpenFile("radius.log.json", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("failed to open log file: %v", err)
	}
	logger = log.New(f, "", 0) // no timestamp prefix; it's in JSON
}

func main() {
	setupLogger()
	// Access-Request Server (1812)
	go func() {
		accessSrv := radius.PacketServer{
			Addr:         ":1812",
			Handler:      radius.HandlerFunc(accessHandler),
			SecretSource: radius.StaticSecretSource(sharedSecret),
		}
		log.Println("Access server running on :1812")
		if err := accessSrv.ListenAndServe(); err != nil {
			log.Fatalf("Access server error: %v", err)
		}
	}()

	// Accounting Server (1813)
	go func() {
		acctSrv := radius.PacketServer{
			Addr:         ":1813",
			Handler:      radius.HandlerFunc(accountingHandler),
			SecretSource: radius.StaticSecretSource(sharedSecret),
		}
		log.Println("Accounting server running on :1813")
		if err := acctSrv.ListenAndServe(); err != nil {
			log.Fatalf("Accounting server error: %v", err)
		}
	}()

	// CoA / Disconnect Server (3799)
	go func() {
		coaSrv := radius.PacketServer{
			Addr:         ":3799",
			Handler:      radius.HandlerFunc(coaHandler),
			SecretSource: radius.StaticSecretSource(sharedSecret),
		}
		log.Println("CoA/Disconnect server running on :3799")
		if err := coaSrv.ListenAndServe(); err != nil {
			log.Fatalf("CoA server error: %v", err)
		}
	}()

	// Block main thread
	select {}
}
