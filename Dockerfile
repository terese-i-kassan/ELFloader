FROM ghcr.io/wiiu-env/devkitppc:20260225

COPY --from=ghcr.io/wiiu-env/wiiupluginsystem:latest /artifacts $DEVKITPRO
COPY --from=ghcr.io/wiiu-env/librpxloader:latest /artifacts $DEVKITPRO

# zlib for the ELF->RPX converter (usually already installed with wut)
RUN dkp-pacman -S --noconfirm --needed ppc-zlib || true

WORKDIR project
