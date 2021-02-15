package cedar

import "go-softether/adapter"

type sessionAdapter struct {
	*Session
	l2r chan []adapter.Packet // local to remote
	r2l chan []adapter.Packet // remote to local
}

func (a *sessionAdapter) GetName() string {
	return a.Name
}

func (a *sessionAdapter) Destroy() {
	a.Connection.tcp[0].Close()
}

func (a *sessionAdapter) Read() (p []adapter.Packet, err error) {
	return <-a.l2r, nil
}

func (a *sessionAdapter) Write(p []adapter.Packet) (err error) {
	a.r2l <- p
	return nil
}
