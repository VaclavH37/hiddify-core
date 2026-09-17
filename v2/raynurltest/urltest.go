package raynurltest

// Copied from hiddify-sing-box/protocol/group/urltest.go at submodule commit
// 170d8315 and corrected. Diff against that file after a fork bump. The
// changes, each marked "rayn:" below:
//
//  1. Select ranks only usable probe results (select.go) and never wraps.
//  2. The sticky selection is abandoned on the next new connection once its
//     stored probe is a failure, not at the end of the group's next sweep.
//  3. A failed dial asks for a fresh probe instead of writing the failure
//     sentinel itself; one hub-connect error must not flip the exit.
//  4. The group's own sweep treats a 0 ms result as a failure.
//  5. The sticky fields are guarded; upstream read them unsynchronised.

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/monitoring"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/batch"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

// recheckInterval bounds how often a failed dial may request a fresh probe of
// the same outbound (rayn: 3).
const recheckInterval = 30 * time.Second

var (
	_ adapter.OutboundGroup       = (*URLTest)(nil)
	_ adapter.URLTestGroup        = (*URLTest)(nil)
	_ adapter.DirectRouteOutbound = (*URLTest)(nil)
)

type URLTest struct {
	outbound.Adapter
	ctx                          context.Context
	outbound                     adapter.OutboundManager
	connection                   adapter.ConnectionManager
	logger                       log.ContextLogger
	tags                         []string
	link                         string
	interval                     time.Duration
	tolerance                    uint16
	idleTimeout                  time.Duration
	group                        *URLTestGroup
	interruptExternalConnections bool
}

// New constructs the group. The adapter type stays C.TypeURLTest on purpose:
// see Type.
func New(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.URLTestOutboundOptions) (adapter.Outbound, error) {
	outbound := &URLTest{
		Adapter:                      outbound.NewAdapter(C.TypeURLTest, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.Outbounds),
		ctx:                          ctx,
		outbound:                     service.FromContext[adapter.OutboundManager](ctx),
		connection:                   service.FromContext[adapter.ConnectionManager](ctx),
		logger:                       logger,
		tags:                         options.Outbounds,
		link:                         options.URL,
		interval:                     time.Duration(options.Interval),
		tolerance:                    options.Tolerance,
		idleTimeout:                  time.Duration(options.IdleTimeout),
		interruptExternalConnections: options.InterruptExistConnections,
	}
	if len(outbound.tags) == 0 {
		return nil, E.New("missing tags")
	}
	return outbound, nil
}

func (s *URLTest) Start() error {
	outbounds := make([]adapter.Outbound, 0, len(s.tags))
	for i, tag := range s.tags {
		detour, loaded := s.outbound.Outbound(tag)
		if !loaded {
			return E.New("outbound ", i, " not found: ", tag)
		}
		outbounds = append(outbounds, detour)
	}
	group, err := NewURLTestGroup(s.ctx, s.outbound, s.logger, outbounds, s.link, s.interval, s.tolerance, s.idleTimeout, s.interruptExternalConnections)
	if err != nil {
		return err
	}
	s.group = group
	return nil
}

func (s *URLTest) PostStart() error {
	s.group.PostStart()
	return nil
}

func (s *URLTest) Close() error {
	return common.Close(
		common.PtrOrNil(s.group),
	)
}

// Now reports the outbound in use. Empty until the first selection, as
// upstream; after that it goes through current, so a dead selection stops
// being reported as soon as a probe has marked it (rayn: 2).
func (s *URLTest) Now() string {
	if s.group == nil {
		return ""
	}
	for _, network := range []string{N.NetworkTCP, N.NetworkUDP} {
		s.group.selectAccess.RLock()
		sticky := s.group.selected(network)
		s.group.selectAccess.RUnlock()
		if sticky == nil {
			continue
		}
		if outbound := s.group.current(network); outbound != nil {
			return outbound.Tag()
		}
	}
	return ""
}

func (s *URLTest) All() []string {
	return s.tags
}

func (s *URLTest) URLTest(ctx context.Context) (map[string]uint16, error) {
	return s.group.URLTest(ctx)
}

func (s *URLTest) CheckOutbounds() {
	s.group.CheckOutbounds(true)
}

func (s *URLTest) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	s.group.Touch()
	switch N.NetworkName(network) {
	case N.NetworkTCP, N.NetworkUDP:
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	outbound := s.group.current(N.NetworkName(network))
	if outbound == nil {
		return nil, E.New("missing supported outbound")
	}
	conn, err := outbound.DialContext(ctx, network, destination)
	if err == nil {
		return s.group.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
	}
	s.logger.ErrorContext(ctx, err)
	s.group.recheck(outbound)
	return nil, err
}

func (s *URLTest) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	s.group.Touch()
	outbound := s.group.current(N.NetworkUDP)
	if outbound == nil {
		return nil, E.New("missing supported outbound")
	}
	conn, err := outbound.ListenPacket(ctx, destination)
	if err == nil {
		return s.group.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
	}
	s.logger.ErrorContext(ctx, err)
	s.group.recheck(outbound)
	return nil, err
}

func (s *URLTest) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	s.connection.NewConnection(ctx, s, conn, metadata, onClose)
}

func (s *URLTest) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	s.connection.NewPacketConnection(ctx, s, conn, metadata, onClose)
}

func (s *URLTest) NewDirectRouteConnection(metadata adapter.InboundContext, routeContext tun.DirectRouteContext, timeout time.Duration) (tun.DirectRouteDestination, error) {
	s.group.Touch()
	selected := s.group.current(N.NetworkTCP)
	if selected == nil {
		return nil, E.New("missing supported outbound")
	}
	if !common.Contains(selected.Network(), metadata.Network) {
		return nil, E.New(metadata.Network, " is not supported by outbound: ", selected.Tag())
	}
	return selected.(adapter.DirectRouteOutbound).NewDirectRouteConnection(metadata, routeContext, timeout)
}

type URLTestGroup struct {
	ctx                          context.Context
	outbound                     adapter.OutboundManager
	pause                        pause.Manager
	pauseCallback                *list.Element[pause.Callback]
	logger                       log.Logger
	outbounds                    []adapter.Outbound
	link                         string
	interval                     time.Duration
	tolerance                    uint16
	idleTimeout                  time.Duration
	history                      adapter.URLTestHistoryStorage
	checking                     atomic.Bool
	interruptGroup               *interrupt.Group
	interruptExternalConnections bool
	access                       sync.Mutex
	ticker                       *time.Ticker
	close                        chan struct{}
	started                      bool
	lastActive                   common.TypedValue[time.Time]

	// rayn: 5. The sticky selection per network, and the re-selection that
	// replaces it, are serialised here; upstream read and wrote plain fields
	// from the dial path and the sweep concurrently.
	selectAccess sync.RWMutex
	selectedTCP  adapter.Outbound
	selectedUDP  adapter.Outbound

	// rayn: 3. When each outbound was last asked for a fresh probe.
	recheckAccess sync.Mutex
	recheckAt     map[string]time.Time
}

func NewURLTestGroup(ctx context.Context, outboundManager adapter.OutboundManager, logger log.Logger, outbounds []adapter.Outbound, link string, interval time.Duration, tolerance uint16, idleTimeout time.Duration, interruptExternalConnections bool) (*URLTestGroup, error) {
	if interval == 0 {
		interval = C.DefaultURLTestInterval
	}
	if tolerance == 0 {
		tolerance = 50
	}
	if idleTimeout == 0 {
		idleTimeout = C.DefaultURLTestIdleTimeout
	}
	if interval > idleTimeout {
		return nil, E.New("interval must be less or equal than idle_timeout")
	}
	var history adapter.URLTestHistoryStorage
	if historyFromCtx := service.PtrFromContext[urltest.HistoryStorage](ctx); historyFromCtx != nil {
		history = historyFromCtx
	} else if clashServer := service.FromContext[adapter.ClashServer](ctx); clashServer != nil {
		history = clashServer.HistoryStorage()
	} else {
		history = urltest.NewHistoryStorage()
	}
	return &URLTestGroup{
		ctx:                          ctx,
		outbound:                     outboundManager,
		logger:                       logger,
		outbounds:                    outbounds,
		link:                         link,
		interval:                     interval,
		tolerance:                    tolerance,
		idleTimeout:                  idleTimeout,
		history:                      history,
		close:                        make(chan struct{}),
		pause:                        service.FromContext[pause.Manager](ctx),
		interruptGroup:               interrupt.NewGroup(),
		interruptExternalConnections: interruptExternalConnections,
		recheckAt:                    make(map[string]time.Time),
	}, nil
}

func (g *URLTestGroup) PostStart() {
	g.access.Lock()
	defer g.access.Unlock()
	g.started = true
	g.lastActive.Store(time.Now())
	go g.CheckOutbounds(false)
}

func (g *URLTestGroup) Touch() {
	if !g.started {
		return
	}
	g.access.Lock()
	defer g.access.Unlock()
	if g.ticker != nil {
		g.lastActive.Store(time.Now())
		return
	}
	ticker := time.NewTicker(g.interval)
	g.ticker = ticker
	g.pauseCallback = pause.RegisterTicker(g.pause, ticker, g.interval, nil)
	go g.loopCheck(ticker, g.close)
}

func (g *URLTestGroup) Close() error {
	g.access.Lock()
	defer g.access.Unlock()
	if g.ticker == nil {
		return nil
	}
	g.ticker.Stop()
	g.ticker = nil
	g.pause.UnregisterCallback(g.pauseCallback)
	g.pauseCallback = nil
	close(g.close)
	return nil
}

// selected and setSelected read and write the sticky choice for network.
// Callers hold selectAccess.
func (g *URLTestGroup) selected(network string) adapter.Outbound {
	if network == N.NetworkUDP {
		return g.selectedUDP
	}
	return g.selectedTCP
}

func (g *URLTestGroup) setSelected(network string, outbound adapter.Outbound) {
	if network == N.NetworkUDP {
		g.selectedUDP = outbound
		return
	}
	g.selectedTCP = outbound
}

// Select is upstream's entry point: the lowest usable delay, with the current
// selection as the incumbent (rayn: 1). The bool is false when nothing has a
// usable result and the first compatible outbound is returned instead.
func (g *URLTestGroup) Select(network string) (adapter.Outbound, bool) {
	g.selectAccess.RLock()
	incumbent := g.selected(network)
	g.selectAccess.RUnlock()
	return g.selectFrom(network, incumbent)
}

func (g *URLTestGroup) selectFrom(network string, incumbent adapter.Outbound) (adapter.Outbound, bool) {
	var order []string
	byTag := make(map[string]adapter.Outbound, len(g.outbounds))
	for _, detour := range g.outbounds {
		if !common.Contains(detour.Network(), network) {
			continue
		}
		tag := realTag(detour)
		if _, seen := byTag[tag]; seen {
			continue
		}
		byTag[tag] = detour
		order = append(order, tag)
	}
	incumbentTag := ""
	if incumbent != nil {
		incumbentTag = realTag(incumbent)
	}
	if chosen, ok := selectLowest(order, incumbentTag, g.history.LoadURLTestHistory, g.tolerance); ok {
		if incumbent != nil && chosen == incumbentTag {
			return incumbent, true
		}
		return byTag[chosen], true
	}
	for _, detour := range g.outbounds {
		if !common.Contains(detour.Network(), network) {
			continue
		}
		return detour, false
	}
	return nil, false
}

// current returns the outbound to use for network (rayn: 2).
//
// The sticky choice is kept while its last probe is usable. Once the
// monitoring service or a sweep has marked it dead, the group re-selects here,
// on the next new connection, instead of at the end of its own next sweep,
// which in this app is 20 to 40 minutes away. Nothing usable anywhere keeps
// the sticky choice, or seeds it with the first compatible outbound, which is
// what upstream does. A switch away from a dead outbound interrupts only the
// group's internal connections; app connections riding the dead exit are left
// to time out, because one probe failure must never cut live sessions.
func (g *URLTestGroup) current(network string) adapter.Outbound {
	g.selectAccess.RLock()
	sticky := g.selected(network)
	g.selectAccess.RUnlock()
	if sticky != nil && usable(g.history.LoadURLTestHistory(realTag(sticky))) {
		return sticky
	}

	g.selectAccess.Lock()
	defer g.selectAccess.Unlock()
	sticky = g.selected(network)
	if sticky != nil && usable(g.history.LoadURLTestHistory(realTag(sticky))) {
		return sticky
	}
	picked, ok := g.selectFrom(network, sticky)
	if picked == nil {
		return sticky
	}
	if !ok {
		if sticky == nil {
			g.setSelected(network, picked)
			return picked
		}
		return sticky
	}
	if picked != sticky {
		g.setSelected(network, picked)
		if sticky != nil {
			g.logger.Info("outbound ", sticky.Tag(), " stopped responding; using ", picked.Tag())
			g.interruptGroup.Interrupt(g.interruptExternalConnections)
		}
	}
	return picked
}

// recheck asks for a fresh probe of detour after a failed dial (rayn: 3).
//
// Upstream wrote DeleteURLTestHistory here, which in this fork stores the
// failure sentinel, so one hub-connect error would have flipped the exit. The
// monitoring service is the writer the app already listens to, so it gets a
// priority probe; without one, the group sweeps itself. Per outbound, at most
// once per recheckInterval.
func (g *URLTestGroup) recheck(detour adapter.Outbound) {
	tag := realTag(detour)
	now := time.Now()
	g.recheckAccess.Lock()
	if last, seen := g.recheckAt[tag]; seen && now.Sub(last) < recheckInterval {
		g.recheckAccess.Unlock()
		return
	}
	g.recheckAt[tag] = now
	g.recheckAccess.Unlock()
	if monitor := monitoring.Get(g.ctx); monitor != nil {
		if err := monitor.InvalidateTest(tag); err == nil {
			return
		}
	}
	go g.CheckOutbounds(true)
}

func (g *URLTestGroup) loopCheck(ticker *time.Ticker, closeChan <-chan struct{}) {
	if time.Since(g.lastActive.Load()) > g.interval {
		g.lastActive.Store(time.Now())
		g.CheckOutbounds(false)
	}
	for {
		select {
		case <-closeChan:
			return
		case <-ticker.C:
		}
		if time.Since(g.lastActive.Load()) > g.idleTimeout {
			g.access.Lock()
			if g.ticker == ticker {
				g.ticker.Stop()
				g.ticker = nil
				g.pause.UnregisterCallback(g.pauseCallback)
				g.pauseCallback = nil
			}
			g.access.Unlock()
			return
		}
		g.CheckOutbounds(false)
	}
}

func (g *URLTestGroup) CheckOutbounds(force bool) {
	_, _ = g.urlTest(g.ctx, force)
}

func (g *URLTestGroup) URLTest(ctx context.Context) (map[string]uint16, error) {
	return g.urlTest(ctx, false)
}

func (g *URLTestGroup) urlTest(ctx context.Context, force bool) (map[string]uint16, error) {
	result := make(map[string]uint16)
	if g.checking.Swap(true) {
		return result, nil
	}
	defer g.checking.Store(false)
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](10))
	checked := make(map[string]bool)
	var resultAccess sync.Mutex
	for _, detour := range g.outbounds {
		tag := detour.Tag()
		realTag := realTag(detour)
		if checked[realTag] {
			continue
		}
		history := g.history.LoadURLTestHistory(realTag)
		if !force && history != nil && time.Since(history.Time) < g.interval {
			continue
		}
		checked[realTag] = true
		p, loaded := g.outbound.Outbound(realTag)
		if !loaded {
			continue
		}
		b.Go(realTag, func() (any, error) {
			testCtx, cancel := context.WithTimeout(g.ctx, C.TCPTimeout)
			defer cancel()
			t, err := urltest.URLTest(testCtx, g.link, p)
			// rayn: 4. A 0 ms "success" is the fork's URLTest returning early
			// on a cancelled context; it is a failure, not the fastest exit.
			if err != nil || t == 0 {
				g.logger.Debug("outbound ", tag, " unavailable: ", err)
				g.history.DeleteURLTestHistory(realTag)
			} else {
				g.logger.Debug("outbound ", tag, " available: ", t, "ms")
				g.history.StoreURLTestHistory(realTag, &adapter.URLTestHistory{
					Time:  time.Now(),
					Delay: t,
				})
				resultAccess.Lock()
				result[tag] = t
				resultAccess.Unlock()
			}
			return nil, nil
		})
	}
	b.Wait()
	g.performUpdateCheck()
	return result, nil
}

func (g *URLTestGroup) performUpdateCheck() {
	g.selectAccess.Lock()
	defer g.selectAccess.Unlock()
	var updated bool
	for _, network := range []string{N.NetworkTCP, N.NetworkUDP} {
		sticky := g.selected(network)
		picked, ok := g.selectFrom(network, sticky)
		if picked == nil || (sticky != nil && (!ok || picked == sticky)) {
			continue
		}
		g.setSelected(network, picked)
		if sticky != nil {
			updated = true
			g.logger.Info("outbound ", picked.Tag(), " is now the lowest; was ", sticky.Tag())
		}
	}
	if updated {
		g.interruptGroup.Interrupt(g.interruptExternalConnections)
	}
}

// realTag is protocol/group.RealTag: a member that is itself a group is ranked
// by the outbound it currently resolves to.
func realTag(detour adapter.Outbound) string {
	if group, isGroup := detour.(adapter.OutboundGroup); isGroup {
		return group.Now()
	}
	return detour.Tag()
}
