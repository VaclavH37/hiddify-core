.ONESHELL:
PRODUCT_NAME=hiddify-core
BASENAME=$(PRODUCT_NAME)
BINDIR=bin
LIBNAME=$(PRODUCT_NAME)
CLINAME=HiddifyCli

BRANCH=$(shell git branch --show-current)
VERSION=$(shell git describe --tags || echo "unknown version")
ifeq ($(OS),Windows_NT)
$(error Not available for Windows! Build the core in WSL — see CORE_BUILD.md)
endif
CRONET_GO_VERSION := $(shell cat hiddify-sing-box/.github/CRONET_GO_VERSION)

# Prefer the cronet-go version recorded in go.mod over the bare commit hash in
# hiddify-sing-box/.github/CRONET_GO_VERSION. Both name the same commit — go.mod's
# pseudo-version v0.0.0-<date>-dc1cda1fe287 embeds the short form of the pinned
# hash — but they resolve very differently:
#
#   `go run pkg@<40-char-commit>` asks proxy.golang.org to turn a bare commit into
#   a pseudo-version, which it only does ON DEMAND. The first request for a commit
#   the proxy has not cached fails outright with "invalid version: unknown
#   revision" while it fetches in the background; re-running the same command
#   minutes later succeeds. A pseudo-version is an ordinary module version the
#   proxy serves directly, so it has no such first-run failure.
#
# That intermittency is why extraction is staged below rather than written
# straight into $(BINDIR). Falls back to the pinned hash if cronet-go is somehow
# not in the module graph. Deliberately lazy (`=`, not `:=`) so `go list` only
# runs for targets that actually extract cronet.
CRONET_GO_MOD_VERSION = $(shell go list -m -f '{{.Version}}' github.com/sagernet/cronet-go 2>/dev/null)
CRONET_GO_REF = $(or $(CRONET_GO_MOD_VERSION),$(CRONET_GO_VERSION))
TAGS=with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api,with_grpc,with_awg,tfogo_checklinkname0,with_naive_outbound,with_conntrack
IOS_ADD_TAGS=with_dhcp,with_low_memory,with_purego
MACOS_ADD_TAGS=with_dhcp
WINDOWS_ADD_TAGS=with_purego

# Opt-in build tags, appended to $(TAGS) rather than replacing it:
#
#   make android EXTRA_TAGS=raynconfigdump
#
# $(TAGS) is overridable from the command line, but overriding it means
# retyping the whole list — and quietly dropping with_quic or with_gvisor
# changes how the core handles traffic, which is a miserable thing to debug.
# Use this instead. Same additive shape as IOS_ADD_TAGS above.
#
# raynconfigdump makes the core write the full built config to
# data/debug-built-config.json in plaintext. NEVER ship a core built with it.
EXTRA_TAGS=
COMMA=,
ALL_TAGS=$(TAGS)$(if $(EXTRA_TAGS),$(COMMA)$(EXTRA_TAGS))
LDFLAGS=-w -s -checklinkname=0 -buildid= $${CODE_VERSION}
GOBUILDLIB=CGO_ENABLED=1 go build -trimpath -ldflags="$(LDFLAGS)" -buildmode=c-shared
GOBUILDSRV=CGO_ENABLED=1 go build -ldflags="$(LDFLAGS)" -trimpath -tags $(ALL_TAGS)

CRONET_DIR=./cronet
# Staging dir for cronet extraction. Kept outside $(BINDIR) so `rm -rf $(BINDIR)/*`
# cannot clear it, and so a failed extraction never leaves a half-written
# libcronet.dll where the build would pick it up.
CRONET_STAGE=$(BINDIR).cronet-stage
.PHONY: protos
protos:
	go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@latest
	# protoc --go_out=./ --go-grpc_out=./ --proto_path=hiddifyrpc hiddifyrpc/*.proto
	# for f in $(shell find v2 -name "*.proto"); do \
	# 	protoc --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative --go_out=./ --go-grpc_out=./  $$f; \
	# done
	# for f in $(shell find extension -name "*.proto"); do \
	# 	protoc --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative --go_out=./ --go-grpc_out=./  $$f; \
	# done
	protoc --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative --go_out=./ --go-grpc_out=./  $(shell find v2 -name "*.proto") $(shell find extension -name "*.proto")
	protoc --doc_out=./docs  --doc_opt=markdown,hiddifyrpc.md $(shell find v2 -name "*.proto") $(shell find extension -name "*.proto")
	# protoc --js_out=import_style=commonjs,binary:./extension/html/rpc/ --grpc-web_out=import_style=commonjs,mode=grpcwebtext:./extension/html/rpc/ $(shell find v2 -name "*.proto") $(shell find extension -name "*.proto")
	# npx browserify extension/html/rpc/extension.js >extension/html/rpc.js


lib_install: prepare
	go install -v github.com/sagernet/gomobile/cmd/gomobile@v0.1.11
	go install -v github.com/sagernet/gomobile/cmd/gobind@v0.1.11
	npm install

headers:
	go build -buildmode=c-archive -o $(BINDIR)/ ./platform/desktop2

android: lib_install
	# Rayn rebrand (Android/Play de-Hiddify, audit C1): bound Java package
	# com.hiddify.core -> com.raynlabs.core, lib hiddify-core -> rayn-core
	# (-> librayn-core.so + rayn-core.aar). Scoped to the android target only so
	# the shared iOS/desktop outputs (which still use $(LIBNAME)) are unchanged.
	CGO_LDFLAGS="-O2 -g -s -w -Wl,-z,max-page-size=16384" gomobile bind -v -androidapi=21 -javapkg=com.raynlabs.core -libname=rayn-core -tags=$(ALL_TAGS) -trimpath -ldflags="$(LDFLAGS)" -target=android -gcflags "all=-N -l" -o $(BINDIR)/rayn-core.aar github.com/sagernet/sing-box/experimental/libbox ./platform/mobile

ios-full: lib_install
	gomobile bind -v  -target ios,iossimulator,tvos,tvossimulator,macos -libname=hiddify-core -tags=$(ALL_TAGS),$(IOS_ADD_TAGS) -trimpath -ldflags="$(LDFLAGS)" -o $(BINDIR)/$(PRODUCT_NAME).xcframework github.com/sagernet/sing-box/experimental/libbox ./platform/mobile 
	mv $(BINDIR)/$(PRODUCT_NAME).xcframework $(BINDIR)/$(LIBNAME).xcframework 
	cp HiddifyCore.podspec $(BINDIR)/$(LIBNAME).xcframework/

# Device arm64 only — that is what TestFlight and the App Store take, and the VPN
# Network Extension cannot run in the simulator anyway, so a simulator slice buys
# nothing for a release build.
#
# There used to be a `cp Info.plist $(BINDIR)/HiddifyCore.xcframework/` here. It
# overwrote the manifest gomobile had just written correctly with the checked-in
# Info.plist, which declares TWO libraries — `ios-arm64_x86_64-simulator` and
# `ios-arm64`. That file describes the output of `ios-full` (which is separately
# broken: it cp's a HiddifyCore.podspec that does not exist), not of this target.
# `-target ios` produces the device slice alone, so the copied manifest pointed at
# a simulator framework that was never in the bundle and Xcode refused to resolve
# it. gomobile's own manifest is correct; leave it alone.
#
# If you ever need a simulator slice for local debugging, build it as a separate
# invocation — do not add it here and do not restore the cp.
ios: lib_install
	gomobile bind -v  -target ios -libname=rayn-core -tags=$(ALL_TAGS),$(IOS_ADD_TAGS) -trimpath -ldflags="$(LDFLAGS)" -o $(BINDIR)/RaynCore.xcframework github.com/sagernet/sing-box/experimental/libbox ./platform/mobile


webui:
	curl -L -o webui.zip  https://github.com/hiddify/Yacd-meta/archive/gh-pages.zip 
	unzip -d ./ -q webui.zip
	rm webui.zip
	rm -rf bin/webui
	mv Yacd-meta-gh-pages bin/webui

.PHONY: build
# Rayn rebrand (Windows de-Hiddify): the bundled desktop core ships as
# rayn-core.dll (matching the Android rayn-core lib) and RaynVPNCli.exe. Scoped
# to this target only via target-specific vars so the shared iOS/macOS/Linux
# outputs keep the global $(LIBNAME)/$(CLINAME). The CLI links + dlopen-resolves
# the DLL by $(LIBNAME).dll, and the Dart FFI loader / CMake install use the same
# rayn-core.dll name — keep all three in sync if this ever changes.
windows-amd64: LIBNAME := rayn-core
windows-amd64: CLINAME := RaynVPNCli
windows-amd64: prepare
	# Extract cronet into a staging dir BEFORE clearing $(BINDIR), and retry: the
	# fetch is the one step here that fails intermittently (see CRONET_GO_REF
	# above). Clearing bin/ first meant a single transient failure deleted the
	# previously extracted libcronet.dll and put nothing back — and because the
	# failure happened inside `go run`, whose status was not checked, make still
	# exited 0 and the missing DLL only surfaced later in the Flutter/CMake build.
	rm -rf $(CRONET_STAGE)
	mkdir -p $(CRONET_STAGE)
	for i in 1 2 3; do \
		go run -v "github.com/sagernet/cronet-go/cmd/build-naive@$(CRONET_GO_REF)" extract-lib --target windows/amd64 -o $(CRONET_STAGE)/ && break; \
		if [ $$i -eq 3 ]; then \
			echo "Error: cronet extract-lib failed after 3 attempts ($(CRONET_GO_REF))"; \
			rm -rf $(CRONET_STAGE); \
			exit 1; \
		fi; \
		echo "cronet extract-lib attempt $$i failed, retrying in 10s..."; \
		sleep 10; \
	done
	if [ ! -f $(CRONET_STAGE)/libcronet.dll ]; then \
		echo "Error: cronet extract-lib reported success but produced no libcronet.dll"; \
		rm -rf $(CRONET_STAGE); \
		exit 1; \
	fi
	rm -rf $(BINDIR)/*
	mv $(CRONET_STAGE)/* $(BINDIR)/
	rm -rf $(CRONET_STAGE)
	env GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc  $(GOBUILDLIB) -tags $(ALL_TAGS),$(WINDOWS_ADD_TAGS)   -o $(BINDIR)/$(LIBNAME).dll ./platform/desktop
	echo "core built, now building cli" 
	ls -R $(BINDIR)/
	go install -mod=readonly github.com/akavel/rsrc@latest ||echo "rsrc error in installation"
	# A `go run ./cli tunnel exit` used to sit here, to stop a running tunnel service
	# so it could not hold rayn-core.dll open across the copy + link below. Removed:
	# `cli/` was deleted upstream in 0d94b2c ("refactor cmd") — the entrypoints are
	# `cmd/main` and `cmd/bydll` now — so the line had been failing with
	# "stat .../cli: directory not found" on every Windows build since, surviving
	# only because .ONESHELL without `set -e` ignores mid-recipe failures.
	#
	# Not repointed at ./cmd/main, because it would still be pointless: this target
	# only runs on Linux/WSL (the guard at the top of this file hard-errors on
	# Windows), and ExitTunnelService signals a Windows service that does not exist
	# on the build host. The DLL-lock problem it guarded against cannot occur here.
	cp $(BINDIR)/$(LIBNAME).dll ./$(LIBNAME).dll
	$$(go env GOPATH)/bin/rsrc -ico ./assets/rayn-cli.ico -o ./cmd/bydll/cli.syso ||echo "rsrc error in syso"
	env GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc CGO_LDFLAGS="$(LIBNAME).dll" $(GOBUILDSRV) -o $(BINDIR)/$(CLINAME).exe ./cmd/bydll
	rm ./*.dll
	# libcronet.dll is checked alongside the two build outputs because CMake
	# installs it into the Windows bundle (windows/CMakeLists.txt) — it is a shipped
	# artefact, not an intermediate, and its absence must fail the core build rather
	# than the Flutter build much later.
	if [ ! -f $(BINDIR)/$(LIBNAME).dll -o ! -f $(BINDIR)/$(CLINAME).exe -o ! -f $(BINDIR)/libcronet.dll ]; then \
		echo "Error: $(LIBNAME).dll, $(CLINAME).exe or libcronet.dll not built"; \
		exit 1; \
	fi

# 	make webui
	



cronet-%:
	$(MAKE) ARCH=$* build-cronet

build-cronet:
# 	rm -rf $(CRONET_DIR)
	git init $(CRONET_DIR) || echo "dir exist"
	cd $(CRONET_DIR) && \
	git remote add origin https://github.com/sagernet/cronet-go.git ||echo "remote exist"; \
	git fetch --depth=1 origin $(CRONET_GO_VERSION) && \
	git checkout FETCH_HEAD && \
	git submodule update --init --recursive --depth=1 && \
	if [ "$${VARIANT}" = "musl" ]; then \
		go run ./cmd/build-naive --target=linux/$(ARCH) --libc=musl download-toolchain && \
		go run ./cmd/build-naive --target=linux/$(ARCH) --libc=musl env > cronet.env; \
	else \
		go run ./cmd/build-naive --target=linux/$(ARCH) download-toolchain && \
		go run ./cmd/build-naive --target=linux/$(ARCH) env > cronet.env; \
	fi

################################
# Generic Linux Builder
################################
linux-%:
	$(MAKE) ARCH=$* build-linux

define load_cronet_env
set -a; \
while IFS= read -r line; do \
    key=$${line%%=*}; \
    value=$${line#*=}; \
    export "$$key=$$value"; \
	echo "$$key=$$value"; \
done < $(CRONET_DIR)/cronet.env; \
set +a;
endef

build-linux: prepare
	mkdir -p $(BINDIR)/lib

	$(load_cronet_env)
	FINAL_TAGS=$(ALL_TAGS); \
	if [ "$${VARIANT}" = "musl" ]; then \
		FINAL_TAGS=$${FINAL_TAGS},with_musl; \
	elif [ "$${VARIANT}" = "purego" ]; then \
		FINAL_TAGS="$${FINAL_TAGS},with_purego"; \
	fi; \
	echo "FinalTags: $$FINAL_TAGS"; \
	GOOS=linux GOARCH=$(ARCH) $(GOBUILDLIB) -tags $${FINAL_TAGS} -o $(BINDIR)/lib/$(LIBNAME).so ./platform/desktop ;\
	
	echo "Core library built, now building CLI with CGO linking to core library"
	mkdir lib
	cp $(BINDIR)/lib/$(LIBNAME).so ./lib/$(LIBNAME).so

	GOOS=linux GOARCH=$(ARCH) CGO_LDFLAGS="./lib/$(LIBNAME).so -Wl,-rpath,\$$ORIGIN/lib -fuse-ld=lld" $(GOBUILDSRV) -o $(BINDIR)/$(CLINAME) ./cmd/bydll
	
	rm -rf ./lib/*.so
	chmod +x $(BINDIR)/$(CLINAME)
	if [ ! -f $(BINDIR)/lib/$(LIBNAME).so -o ! -f $(BINDIR)/$(CLINAME) ]; then \
		echo "Error: $(LIBNAME).so or $(CLINAME) not built"; \
		ls -R $(BINDIR); \
		exit 1; \
	fi
# 	make webui


linux-custom: prepare  install_cronet
	mkdir -p $(BINDIR)/
	#env GOARCH=mips $(GOBUILDSRV) -o $(BINDIR)/$(CLINAME) ./cmd/
	$(load_cronet_env)
	go build -ldflags="$(LDFLAGS)" -trimpath -tags $(ALL_TAGS) -o $(BINDIR)/$(CLINAME) ./cmd/main
	chmod +x $(BINDIR)/$(CLINAME)
	make webui

macos-amd64:
	env GOOS=darwin GOARCH=amd64 CGO_CFLAGS="-mmacosx-version-min=10.11 -O2" CGO_LDFLAGS="-mmacosx-version-min=10.11 -O2 -lpthread" CGO_ENABLED=1 go build -trimpath -tags $(ALL_TAGS),$(MACOS_ADD_TAGS) -buildmode=c-shared -o $(BINDIR)/$(LIBNAME)-amd64.dylib ./platform/desktop
macos-arm64:
	env GOOS=darwin GOARCH=arm64 CGO_CFLAGS="-mmacosx-version-min=10.11 -O2" CGO_LDFLAGS="-mmacosx-version-min=10.11 -O2 -lpthread" CGO_ENABLED=1 go build -trimpath -tags $(ALL_TAGS),$(MACOS_ADD_TAGS) -buildmode=c-shared -o $(BINDIR)/$(LIBNAME)-arm64.dylib ./platform/desktop
	
macos: prepare macos-amd64 macos-arm64 
	
	lipo -create $(BINDIR)/$(LIBNAME)-amd64.dylib $(BINDIR)/$(LIBNAME)-arm64.dylib -output $(BINDIR)/$(LIBNAME).dylib
	cp $(BINDIR)/$(LIBNAME).dylib ./$(LIBNAME).dylib 
	mv $(BINDIR)/$(LIBNAME)-arm64.h $(BINDIR)/desktop.h 
	# env GOOS=darwin GOARCH=amd64 CGO_CFLAGS="-mmacosx-version-min=10.15" CGO_LDFLAGS="-mmacosx-version-min=10.15" CGO_LDFLAGS="bin/$(LIBNAME).dylib"  CGO_ENABLED=1 $(GOBUILDSRV)  -o $(BINDIR)/$(CLINAME) ./cmd/bydll
	# rm ./$(LIBNAME).dylib
	# chmod +x $(BINDIR)/$(CLINAME)

prepare: 
	go mod tidy

clean:
	rm $(BINDIR)/*




.PHONY: release
release: # Create a new tag for release.	
	@bash -c '.github/change_version.sh'
	


