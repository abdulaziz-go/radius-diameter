package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
)

const (
	username     = "testusername"
	password     = "testpassword"
	sharedSecret = "mysharedsecret"
	authAddr     = "127.0.0.1:1812"
	acctAddr     = "127.0.0.1:1813"
	coaAddr      = "127.0.0.1:3799"
	nasPort      = 0
	sessionID    = "test-session-123"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	fmt.Println("🔐 Access-Request:")
	if err := sendAccessRequest(ctx); err != nil {
		log.Fatalf("Access-Request failed: %v", err)
	}

	fmt.Println("📥 Accounting-Start:")
	if err := sendAccounting(ctx, rfc2866.AcctStatusType_Value_Start); err != nil {
		log.Fatalf("Accounting-Start failed: %v", err)
	}

	fmt.Println("📤 Accounting-Interim-Update:")
	if err := sendAccounting(ctx, rfc2866.AcctStatusType_Value_InterimUpdate); err != nil {
		log.Fatalf("Accounting-Interim-Update failed: %v", err)
	}

	fmt.Println("📤 Accounting-Stop:")
	if err := sendAccounting(ctx, rfc2866.AcctStatusType_Value_Stop); err != nil {
		log.Fatalf("Accounting-Stop failed: %v", err)
	}

	fmt.Println("🔄 CoA-Request:")
	if err := sendCoA(ctx, false); err != nil {
		log.Fatalf("CoA failed: %v", err)
	}

	fmt.Println("⛔ Disconnect-Request:")
	if err := sendCoA(ctx, true); err != nil {
		log.Fatalf("Disconnect failed: %v", err)
	}
}

func sendAccessRequest(ctx context.Context) error {
	packet := radius.New(radius.CodeAccessRequest, []byte(sharedSecret))
	rfc2865.UserName_SetString(packet, username)
	rfc2865.UserPassword_SetString(packet, password)
	rfc2865.NASPort_Set(packet, rfc2865.NASPort(nasPort))
	
	resp, err := radius.Exchange(ctx, packet, authAddr)
	if err != nil {
		return err
	}

	fmt.Printf("Response: %v\n", resp.Code)
	if resp.Code != radius.CodeAccessAccept {
		return fmt.Errorf("expected Access-Accept, got %v", resp.Code)
	}
	return nil
}

func sendAccounting(ctx context.Context, status rfc2866.AcctStatusType) error {
	packet := radius.New(radius.CodeAccountingRequest, []byte(sharedSecret))
	rfc2865.UserName_SetString(packet, username)
	rfc2865.NASPort_Set(packet, rfc2865.NASPort(nasPort))
	rfc2866.AcctStatusType_Set(packet, status)
	rfc2866.AcctSessionID_SetString(packet, sessionID)
	
	resp, err := radius.Exchange(ctx, packet, acctAddr)
	if err != nil {
		return err
	}
	fmt.Printf("Response: %v\n", resp.Code)
	if resp.Code != radius.CodeAccountingResponse {
		return fmt.Errorf("expected Accounting-Response, got %v", resp.Code)
	}
	return nil
}

func sendCoA(ctx context.Context, disconnect bool) error {
	code := radius.CodeCoARequest
	if disconnect {
		code = radius.CodeDisconnectRequest
	}

	packet := radius.New(code, []byte(sharedSecret))
	rfc2865.UserName_SetString(packet, username)
	rfc2865.NASPort_Set(packet, rfc2865.NASPort(nasPort))
	rfc2866.AcctSessionID_SetString(packet, sessionID)

	resp, err := radius.Exchange(ctx, packet, coaAddr)
	if err != nil {
		return err
	}
	fmt.Printf("Response: %v\n", resp.Code)

	if disconnect {
		if resp.Code != radius.CodeDisconnectACK {
			return fmt.Errorf("expected Disconnect-ACK, got %v", resp.Code)
		}
	} else {
		if resp.Code != radius.CodeCoAACK {
			return fmt.Errorf("expected CoA-ACK, got %v", resp.Code)
		}
	}
	return nil
}
