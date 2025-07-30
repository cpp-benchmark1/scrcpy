# Documentation Build Guide

This guide explains how to build the project.

---

### 1 — Install dependency packages

```bash
sudo apt install -y meson ninja-build nasm ffmpeg libsdl2-2.0-0 \
    libsdl2-dev libavcodec-dev libavdevice-dev libavformat-dev \
    libavutil-dev libswresample-dev libusb-1.0-0 libusb-1.0-0-dev \
    libv4l-dev libmongoc-1.0-0 libmongoc-dev libbson-1.0-0 libbson-dev libcurl4-openssl-dev
```

---

### 2 — Normalise script line endings

```bash
sed -i 's/\r$//' install_release.sh
```

---

### 3 — Make the helper script executable

```bash
chmod +x install_release.sh
```

---

### 4 — Run the release-build installer

```bash
./install_release.sh
```

