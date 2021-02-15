package adapter

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// DarwinAdapter darwin adapter
// inspired from
// https://github.com/zerotier/ZeroTierOne/blob/master/osdep/MacEthernetTapAgent.c
type DarwinAdapter struct {
	name     string
	peerName string
	mac      string

	writer io.Writer
	reader io.Reader

	ndrvFD int
	bpfFD  int

	readBuf []uint8
}

const readPktSize = 131072

// GetName get name
func (a *DarwinAdapter) GetName() string {
	return a.name
}

// Read read packets
func (a *DarwinAdapter) Read() (p []Packet, err error) {
again:
	if n, err := a.reader.Read(a.readBuf); nil != err {
		return nil, err
	} else {
		if n == 0 {
			goto again
		}

		b := a.readBuf[:n]
		pos := 0
		for pos < n {
			hdr := (*unix.BpfHdr)(unsafe.Pointer(&b[pos]))
			frameStart := pos + int(hdr.Hdrlen)
			rawFrame := b[frameStart : frameStart+int(hdr.Caplen)]
			p = append(p, rawFrame)
			pos += bpfWordAlign(int(hdr.Hdrlen) + int(hdr.Caplen))
		}

		printPackets("reading", p)
		return p, nil
	}
}

// Write write packets
func (a *DarwinAdapter) Write(p []Packet) (err error) {
	printPackets("writing", p)
	for _, x := range p {
		if _, err := a.writer.Write(x); nil != err {
			return err
		}
	}
	return nil
}

// Destroy destroy adapters
func (a *DarwinAdapter) Destroy() {
	a.destroyAdapters()
}

func checkName(name string) (peer string, ok bool) {
	if !strings.HasPrefix(name, "feth") {
		return "", false
	}

	n := name[4:]
	i, err := strconv.Atoi(n)
	if nil != err {
		return "", false
	}
	if i < 0 || i >= 1024 {
		return "", false
	}

	return "feth" + strconv.Itoa(i+1024), true
}

// ErrInvalidAdapterName invalid adapter name
var ErrInvalidAdapterName = errors.New("invalid adapter name, valid names are feth0 to feth1023")

func createLocalMachineAdapter(name string, mac string) (Adapter, error) {
	peerName, ok := checkName(name)
	if !ok {
		return nil, ErrInvalidAdapterName
	}

	// create adapters
	a := &DarwinAdapter{name: name, peerName: peerName, mac: mac}
	a.destroyAdapters()
	if err := a.createAdapters(); nil != err {
		return nil, err
	}

	// create write socket
	if err := a.createWriteSocket(); nil != err {
		return nil, err
	}

	// create read socket
	if err := a.createReadSocket(); nil != err {
		return nil, err
	}

	return a, nil
}

const ifconfig = "/sbin/ifconfig"
const ipconfig = "/usr/sbin/ipconfig"

func (a *DarwinAdapter) destroyAdapters() {
	_, _ = exec.Command(ifconfig, a.name, "destroy").Output()
	_, _ = exec.Command(ifconfig, a.peerName, "destroy").Output()
}

func (a *DarwinAdapter) createAdapters() error {
	if _, err := exec.Command(ifconfig, a.name, "create").Output(); nil != err {
		return err
	}
	time.Sleep(10 * time.Microsecond)

	if _, err := exec.Command(ifconfig, a.peerName, "create").Output(); nil != err {
		return err
	}
	time.Sleep(10 * time.Microsecond)

	if _, err := exec.Command(ifconfig, a.name, "peer", a.peerName).Output(); nil != err {
		return err
	}
	time.Sleep(10 * time.Microsecond)

	if _, err := exec.Command(ifconfig, a.name, "lladdr", a.mac).Output(); nil != err {
		return err
	}
	time.Sleep(10 * time.Microsecond)

	// TODO: MTU, IPV6 Configuration

	if _, err := exec.Command(ifconfig, a.name, "up").Output(); nil != err {
		return err
	}
	time.Sleep(10 * time.Microsecond)

	if _, err := exec.Command(ifconfig, a.peerName, "up").Output(); nil != err {
		return err
	}
	time.Sleep(10 * time.Microsecond)

	return nil
}

func (a *DarwinAdapter) createWriteSocket() (err error) {
	a.ndrvFD, err = syscall.Socket(syscall.AF_NDRV, syscall.SOCK_RAW, 0)
	if nil != err {
		return
	}
	addr := &syscall.SockaddrNDRV{Name: a.peerName}

	if err := syscall.Bind(a.ndrvFD, addr); nil != err {
		return err
	}

	if err := syscall.Connect(a.ndrvFD, addr); nil != err {
		return err
	}

	a.writer = os.NewFile(uintptr(a.ndrvFD), "ndrv")

	return nil
}

// ErrNoValidBpf no valid bpf
var ErrNoValidBpf = errors.New("no valid /dev/bpf*")

func (a *DarwinAdapter) createReadSocket() (err error) {
	for i := 1; i < 64; i++ {
		dev := "/dev/bpf" + strconv.Itoa(i)
		a.bpfFD, err = syscall.Open(dev, os.O_RDWR, 0777)
		if nil == err {
			break
		}
	}

	if nil != err {
		return
	}
	if a.bpfFD < 0 {
		return ErrNoValidBpf
	}

	if _, err := syscall.SetBpfBuflen(a.bpfFD, readPktSize); nil != err {
		return err
	}

	if err := syscall.SetBpfImmediate(a.bpfFD, 1); nil != err {
		return err
	}

	if err := unix.IoctlSetPointerInt(a.bpfFD, syscall.BIOCSSEESENT, 0); nil != err {
		return err
	}

	if err := syscall.SetBpfInterface(a.bpfFD, a.peerName); nil != err {
		return err
	}

	if err := syscall.SetBpfHeadercmpl(a.bpfFD, 1); nil != err {
		return err
	}

	if err := syscall.SetBpfPromisc(a.bpfFD, 1); nil != err {
		return err
	}

	a.readBuf = make([]uint8, readPktSize)
	a.reader = os.NewFile(uintptr(a.bpfFD), "bpf")

	return nil
}

const wordSize = int(unsafe.Sizeof(uintptr(0)))

func bpfWordAlign(x int) int {
	return (((x) + (wordSize - 1)) &^ (wordSize - 1))
}

func invokeDHCP(a Adapter) error {
	_, err := exec.Command(ipconfig, "set", a.GetName(), "dhcp").Output()
	return err
}
