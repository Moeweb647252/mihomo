package wtp

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
)

type testRequestStream struct {
	release       chan struct{}
	releaseOnce   sync.Once
	response      *http.Response
	readCanceled  atomic.Bool
	writeCanceled atomic.Bool
}

func (s *testRequestStream) SendRequestHeader(*http.Request) error { return nil }

func (s *testRequestStream) ReadResponse() (*http.Response, error) {
	if s.response != nil {
		return s.response, nil
	}
	<-s.release
	return nil, errors.New("request stream canceled")
}

func (s *testRequestStream) CancelRead(quic.StreamErrorCode) {
	s.readCanceled.Store(true)
	s.releaseOnce.Do(func() { close(s.release) })
}

func (s *testRequestStream) CancelWrite(quic.StreamErrorCode) {
	s.writeCanceled.Store(true)
	s.releaseOnce.Do(func() { close(s.release) })
}

func testSession(endpoint string, max int32) *session {
	s := &session{
		protocol:  "tcp",
		endpoint:  endpoint,
		active:    new(atomic.Int32),
		lastUsed:  new(atomic.Int64),
		maxStream: max,
	}
	s.touch()
	return s
}

func TestNormalizeEndpoint(t *testing.T) {
	tests := map[string]string{
		"Example.COM:443":  "example.com:443",
		"[2001:DB8::1]:53": "[2001:db8::1]:53",
		"opaque":           "opaque",
	}
	for input, expected := range tests {
		if actual := normalizeEndpoint(input); actual != expected {
			t.Fatalf("normalizeEndpoint(%q) = %q, want %q", input, actual, expected)
		}
	}
}

func TestWebTransportSettings(t *testing.T) {
	settings := webTransportSettings()
	want := map[uint64]uint64{
		0x8:                            1,
		webTransportSetting:            1,
		webTransportFingerprintSetting: 1,
	}
	if len(settings) != len(want) {
		t.Fatalf("settings count = %d, want %d", len(settings), len(want))
	}
	for key, value := range want {
		if settings[key] != value {
			t.Fatalf("setting 0x%x = %d, want %d", key, settings[key], value)
		}
	}
}

func TestConnectResponseHonorsContext(t *testing.T) {
	stream := &testRequestStream{release: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := sendRequestAndReadResponse(ctx, stream, &http.Request{})
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error = %v, want context deadline exceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("CONNECT response did not honor context deadline")
	}
	if !stream.readCanceled.Load() || !stream.writeCanceled.Load() {
		t.Fatalf("request stream was not fully canceled: read=%v write=%v", stream.readCanceled.Load(), stream.writeCanceled.Load())
	}
}

func TestConnectResponseStopsCancellationAfterSuccess(t *testing.T) {
	stream := &testRequestStream{
		release:  make(chan struct{}),
		response: &http.Response{StatusCode: 200},
	}
	ctx, cancel := context.WithCancel(context.Background())
	response, err := sendRequestAndReadResponse(ctx, stream, &http.Request{})
	if err != nil {
		t.Fatal(err)
	}
	if response == nil || response.StatusCode != 200 {
		t.Fatalf("response = %#v, want status 200", response)
	}
	cancel()
	time.Sleep(10 * time.Millisecond)
	if stream.readCanceled.Load() || stream.writeCanceled.Load() {
		t.Fatal("request stream was canceled after successful response")
	}
}

func TestTargetEndpoint(t *testing.T) {
	key, endpoint, err := targetEndpoint(&net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	if key != "[2001:db8::1]:443" || endpoint != "[2001:db8::1]:443" {
		t.Fatalf("target endpoint = (%q, %q)", key, endpoint)
	}
	if _, _, err := targetEndpoint(endpointAddr{network: "udp", address: "example.com:53"}); err != nil {
		t.Fatal(err)
	}
}

func TestSessionReservation(t *testing.T) {
	s := testSession("target:443", 2)
	if !s.reserveTCP() || !s.reserveTCP() {
		t.Fatal("expected two reservations")
	}
	if s.reserveTCP() {
		t.Fatal("reservation exceeded configured capacity")
	}
	s.releaseTCP()
	if !s.reserveTCP() {
		t.Fatal("released reservation was not reusable")
	}
	s.releaseTCP()
	s.releaseTCP()
}

func TestTCPPoolCoalescesDial(t *testing.T) {
	p := newTCPPool()
	defer p.close()

	var creates atomic.Int32
	create := func(context.Context) (*session, error) {
		creates.Add(1)
		return testSession("target:443", 100), nil
	}

	const count = 32
	results := make(chan *session, count)
	var wg sync.WaitGroup
	wg.Add(count)
	for i := 0; i < count; i++ {
		go func() {
			defer wg.Done()
			s, err := p.acquire(context.Background(), "target:443", create)
			if err != nil {
				t.Errorf("acquire: %v", err)
				return
			}
			results <- s
		}()
	}
	wg.Wait()
	close(results)
	if creates.Load() != 1 {
		t.Fatalf("created %d sessions, want 1", creates.Load())
	}
	var first *session
	for s := range results {
		if first == nil {
			first = s
		} else if first != s {
			t.Fatal("concurrent acquires did not share one session")
		}
	}
}

func TestTCPPoolCreatesSessionAfterCapacity(t *testing.T) {
	p := newTCPPool()
	defer p.close()

	var creates atomic.Int32
	create := func(context.Context) (*session, error) {
		creates.Add(1)
		return testSession("target:443", 1), nil
	}
	first, err := p.acquire(context.Background(), "target:443", create)
	if err != nil {
		t.Fatal(err)
	}
	second, err := p.acquire(context.Background(), "target:443", create)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("capacity exhaustion reused the full session")
	}
	if creates.Load() != 2 {
		t.Fatalf("created %d sessions, want 2", creates.Load())
	}
}
