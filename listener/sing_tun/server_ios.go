//go:build ios && with_gvisor

package sing_tun

import (
	"io"
	"sync"
	"sync/atomic"

	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/buf"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

// iOS 上 NetworkExtension 不允许扩展自己开 utun 设备（unix.Socket(AF_SYSTEM)
// 在沙盒里返回 EPERM）。我们用一个完全虚拟的 tun.Tun 实现，把 sing-tun 的
// gvisor 网络栈和 iOS 的 NEPacketTunnelFlow 之间用 channel + C 函数指针对
// 接：入向包从 ClashCore_write_packet 灌进 channel、出向包通过 IosPacketWriter
// 回调 NEPacketTunnelFlow.writePackets。

// IosPacketWriter 由 lib_ios.go 注册：mihomo 网络栈出向 IP 包时调用，
// 由 Swift 侧实际 packetFlow.writePackets。
type IosPacketWriter func(packet []byte)

type iosTun struct {
	inbound   chan []byte
	closed    chan struct{}
	closeOnce sync.Once
	writer    atomic.Value // IosPacketWriter
	mtu       uint32
}

var (
	iosTunMu      sync.Mutex
	iosTunCurrent *iosTun
)

func (t *iosTun) Read(p []byte) (int, error) {
	select {
	case pkt, ok := <-t.inbound:
		if !ok {
			return 0, io.EOF
		}
		return copy(p, pkt), nil
	case <-t.closed:
		return 0, io.EOF
	}
}

func (t *iosTun) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if w, _ := t.writer.Load().(IosPacketWriter); w != nil {
		cp := make([]byte, len(p))
		copy(cp, p)
		w(cp)
	}
	return len(p), nil
}

func (t *iosTun) WriteVectorised(buffers []*buf.Buffer) error {
	if len(buffers) == 0 {
		return nil
	}
	var total int
	for _, b := range buffers {
		if b != nil {
			total += b.Len()
		}
	}
	if total == 0 {
		return nil
	}
	out := make([]byte, 0, total)
	for _, b := range buffers {
		if b != nil {
			out = append(out, b.Bytes()...)
		}
	}
	if w, _ := t.writer.Load().(IosPacketWriter); w != nil {
		w(out)
	}
	return nil
}

func (t *iosTun) Close() error {
	t.closeOnce.Do(func() {
		close(t.closed)
	})
	return nil
}

// gvisor link endpoint
var _ tun.GVisorTun = (*iosTun)(nil)

func (t *iosTun) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	return &iosEndpoint{tun: t}, stack.NICOptions{}, nil
}

// WritePacket 是 sing-tun v0.4.11 的 GVisorTun 接口要求：mihomo 网络栈直接
// 写包时（不经 LinkEndpoint.WritePackets 路径）调这里。把 PacketBuffer 拼成
// 一段连续 IP 字节，然后走和 Write() 同一个 IosPacketWriter 回调。
func (t *iosTun) WritePacket(pkt *stack.PacketBuffer) (int, error) {
	views := pkt.AsSlices()
	var total int
	for _, v := range views {
		total += len(v)
	}
	if total == 0 {
		return 0, nil
	}
	out := make([]byte, 0, total)
	for _, v := range views {
		out = append(out, v...)
	}
	if w, _ := t.writer.Load().(IosPacketWriter); w != nil {
		w(out)
	}
	return total, nil
}

type iosEndpoint struct {
	tun        *iosTun
	dispatcher stack.NetworkDispatcher
}

var _ stack.LinkEndpoint = (*iosEndpoint)(nil)

func (e *iosEndpoint) MTU() uint32 {
	if e.tun.mtu == 0 {
		return 1500
	}
	return e.tun.mtu
}

func (e *iosEndpoint) SetMTU(mtu uint32) {}

func (e *iosEndpoint) MaxHeaderLength() uint16 { return 0 }

func (e *iosEndpoint) LinkAddress() tcpip.LinkAddress { return "" }

func (e *iosEndpoint) SetLinkAddress(addr tcpip.LinkAddress) {}

func (e *iosEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload
}

func (e *iosEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	if dispatcher == nil && e.dispatcher != nil {
		e.dispatcher = nil
		return
	}
	if dispatcher != nil && e.dispatcher == nil {
		e.dispatcher = dispatcher
		go e.dispatchLoop()
	}
}

func (e *iosEndpoint) dispatchLoop() {
	mtu := int(e.MTU())
	if mtu < 1280 {
		mtu = 1500
	}
	pktBuf := make([]byte, mtu+128)
	for {
		select {
		case <-e.tun.closed:
			return
		default:
		}
		n, err := e.tun.Read(pktBuf)
		if err != nil {
			return
		}
		if n <= 0 {
			continue
		}
		packet := pktBuf[:n]
		var networkProtocol tcpip.NetworkProtocolNumber
		switch header.IPVersion(packet) {
		case header.IPv4Version:
			networkProtocol = header.IPv4ProtocolNumber
		case header.IPv6Version:
			networkProtocol = header.IPv6ProtocolNumber
		default:
			continue
		}
		// gvisor 持有 packet 数据的引用，所以必须 copy 出去再交给 stack。
		copyPkt := make([]byte, n)
		copy(copyPkt, packet)
		pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload:           buffer.MakeWithData(copyPkt),
			IsForwardedPacket: true,
		})
		pb.NetworkProtocolNumber = networkProtocol
		d := e.dispatcher
		if d == nil {
			pb.DecRef()
			return
		}
		d.DeliverNetworkPacket(networkProtocol, pb)
		pb.DecRef()
	}
}

func (e *iosEndpoint) IsAttached() bool { return e.dispatcher != nil }

func (e *iosEndpoint) Wait() {}

func (e *iosEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (e *iosEndpoint) AddHeader(*stack.PacketBuffer) {}

func (e *iosEndpoint) ParseHeader(*stack.PacketBuffer) bool { return true }

func (e *iosEndpoint) WritePackets(list stack.PacketBufferList) (int, tcpip.Error) {
	var n int
	for _, p := range list.AsSlice() {
		slices := p.AsSlices()
		var total int
		for _, s := range slices {
			total += len(s)
		}
		if total == 0 {
			continue
		}
		out := make([]byte, 0, total)
		for _, s := range slices {
			out = append(out, s...)
		}
		if _, err := e.tun.Write(out); err != nil {
			return n, &tcpip.ErrAborted{}
		}
		n++
	}
	return n, nil
}

func (e *iosEndpoint) Close() {}

func (e *iosEndpoint) SetOnCloseAction(f func()) {}

// PushIosPacket 由 lib_ios.go 的 ClashCore_write_packet 调用，
// 把 iOS NEPacketTunnelFlow.readPackets 收到的 IP 包灌进虚拟 tun 的入向 channel。
func PushIosPacket(data []byte) {
	iosTunMu.Lock()
	inst := iosTunCurrent
	iosTunMu.Unlock()
	if inst == nil || len(data) == 0 {
		return
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	select {
	case inst.inbound <- cp:
	case <-inst.closed:
	default:
		// 队列满则丢包：TCP 重传会自愈，UDP 丢包属正常。
	}
}

// SetIosPacketWriter 注册出向 IP 包的回调（mihomo 网络栈 → NEPacketTunnelFlow.writePackets）。
// 传 nil 清除回调。
func SetIosPacketWriter(w IosPacketWriter) {
	iosTunMu.Lock()
	inst := iosTunCurrent
	iosTunMu.Unlock()
	if inst == nil {
		return
	}
	if w == nil {
		inst.writer.Store(IosPacketWriter(func(_ []byte) {}))
	} else {
		inst.writer.Store(w)
	}
}

// CloseIosTun 用于扩展进程关闭隧道时主动释放虚拟 tun。setupConfig 失败 / shutdown 时调用。
func CloseIosTun() {
	iosTunMu.Lock()
	inst := iosTunCurrent
	iosTunCurrent = nil
	iosTunMu.Unlock()
	if inst != nil {
		_ = inst.Close()
	}
}

// tunNew 是 sing_tun.New() 调用的工厂。在 iOS 上忽略 tun.Options 里和 OS-level
// 路由 / utun 设备相关的字段，直接返回一个虚拟 tun 实例。
func tunNew(options tun.Options) (tun.Tun, error) {
	inst := &iosTun{
		inbound: make(chan []byte, 512),
		closed:  make(chan struct{}),
		mtu:     options.MTU,
	}
	inst.writer.Store(IosPacketWriter(func(_ []byte) {}))

	iosTunMu.Lock()
	if old := iosTunCurrent; old != nil {
		old.closeOnce.Do(func() {
			close(old.closed)
		})
	}
	iosTunCurrent = inst
	iosTunMu.Unlock()
	return inst, nil
}
