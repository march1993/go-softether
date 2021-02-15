# go-softether
go-softether is a *minimal* proof of concept(poc) SoftEther macOS client written in Golang. It is a minimal client since,
* Only username and password authentication is supported
* Only one tcp stream is used
* No udp acceleration support yet
* No auto-reconnect when connection broken
* Only macOS is supported

## Get Started
1. clone the repository
```shell
git clone https://github.com/march1993/go-softether.git
```

2. copy the magic feth golang api to `goroot`
```shell
make darwin_hack
# make darwin_unhack
```
or you can do it yourself
```shell
ln -s `pwd`/hack/darwin_syscall/syscall_darwin_hack.go $(GOROOT)/src/syscall
```

3. make yourself a configuration file
```shell
cd cmd/vpnclient
cp config.example.json config.json
```
* Username: username
* HashedPassword: hashed password, you may use a helper program in `cmd/genpwdhash`
* Host: server hostname
* Port: server port
* HubName: hub name
* InsecureSkipVerify: if your server hasn't a valid certificate or you don't know what it is, keep it `false`
* LocalAdapterMAC: make yourself a random MAC address, it would be better to keep `5e`(SE) as the prefix

4. run
```shell
go build .
sudo ./vpnclient
```

## Trouble shooting
If you encounter problem related with SSL communication, please try remove the following line in `session.go`,
```golang
s.WTFWriteRaw([]byte{0, 1, 2, 3, 4})
```
I don't why I need it to operate on my machine.

