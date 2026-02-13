# Use bash for recipes so env VAR=value and && work on all platforms (incl. Windows with Git Bash)
SHELL := bash
.SHELLFLAGS := -ec

TARGET=$(shell rustup target list | grep 'installed' | awk '$$1 != "" {print $$1; exit}')
EXE=pcrypt
VERSION=$(shell awk -F'"' '/^application_version = /{print $$2; exit}' Cargo.toml)
BUILD_DIR=$(CURDIR)/build
# Use = so TARGET override from command line is respected (e.g. Windows .exe)
RELEASE_FILENAME_POSTFIX = $(if $(findstring windows,$(TARGET)),.exe,)
BINARY = $(EXE)$(RELEASE_FILENAME_POSTFIX)
DOCKER_ALPINE_VERSION ?= 3.23

all: dev fmt clippy test release

dev:
	cargo build --features password-from-env --target ${TARGET}
	@ cp ./target/${TARGET}/debug/pcrypt$(RELEASE_FILENAME_POSTFIX) ./$(BINARY)
	@ echo "Built pcrypt dev"

fmt:
	cargo fmt --check
	@ echo "Checked format style"

clippy:
	cargo clippy --no-deps
	@ echo "Checked clippy issues"

test: dev
	@ rm -rf test && mkdir -p test/contents && mkdir -p test/decrypted
	openssl rand -base64 -out test/contents/file.txt 36700160 # 35MB
	openssl rand -base64 -out test/contents/txt.file 36700160
	mkdir -p test/contents/ignore && echo XYZ > test/contents/ignore/ignored.txt
	cd test && PCRYPT_PASSWORD="P" ../$(BINARY) archive -z=-7 contents
	mv test/contents*.pcrypt.zip test/archived.pcrypt.zip
	cd test/decrypted && PCRYPT_PASSWORD="P" ../../$(BINARY) extract ../archived.pcrypt.zip
	cmp test/contents/file.txt test/decrypted/file.txt
	cmp test/contents/txt.file test/decrypted/txt.file
	@ if [ -d "test/decrypted/ignore" ]; then echo "ignore directory exists"; exit 1; fi
	@ echo "Test successful"

release:
	@ rm -rf ${BUILD_DIR}/pcrypt-* || true
	cargo build --release --target ${TARGET}
	@ mkdir -p ${BUILD_DIR} && cp ./target/${TARGET}/release/pcrypt$(RELEASE_FILENAME_POSTFIX) ${BUILD_DIR}/pcrypt-${VERSION}-${TARGET}$(RELEASE_FILENAME_POSTFIX)
	@ ls -sh ${BUILD_DIR}/pcrypt-*

docker:
	docker build --build-arg DOCKER_ALPINE_VERSION=${DOCKER_ALPINE_VERSION} --build-arg PCRYPT_VERSION=${VERSION} -t pcrypt:${VERSION} -t pcrypt:latest .

.PHONY: all dev fmt clippy test release docker