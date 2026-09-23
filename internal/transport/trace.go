package transport

import (
	"context"
	"net/http/httptrace"
)

func withWriteTrace(ctx context.Context, sent func()) context.Context {
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		WroteRequest: func(httptrace.WroteRequestInfo) {
			sent()
		},
	})
}
