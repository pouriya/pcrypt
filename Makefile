TARGET=$(shell rustup target list | grep 'installed' | awk '$$1 != "" {print $$1; exit}')

all: dev fmt clippy test prod

dev:
	cargo build --features password-from-env --target ${TARGET}
	@ cp ./target/${TARGET}/debug/pcrypt .
	@ echo "Built ./`./pcrypt -V` dev"

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
	cd test && PCRYPT_PASSWORD="P" ../pcrypt archive -z=-7 contents
	mv test/contents*.pcrypt.zip test/archived.pcrypt.zip
	cd test/decrypted && PCRYPT_PASSWORD="P" ../../pcrypt extract ../archived.pcrypt.zip
	cmp test/contents/file.txt test/decrypted/file.txt
	cmp test/contents/txt.file test/decrypted/txt.file
	@ if [ -d "test/decrypted/ignore" ]; then echo "ignore directory exists"; exit 1; fi
	@ echo "Test successful"

prod:
	cargo build --release --target ${TARGET}
	@ cp ./target/${TARGET}/release/pcrypt .
	@ echo "Built ./`./pcrypt -V` production" 

.PHONY: all dev fmt clippy test prod