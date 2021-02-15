GOROOT := `go env GOROOT`

darwin_hack:
	ln -s `pwd`/hack/darwin_syscall/syscall_darwin_hack.go $(GOROOT)/src/syscall

darwin_unhack:
	rm $(GOROOT)/src/syscall/syscall_darwin_hack.go

.PHONY: darwin_hack darwin_unhack
