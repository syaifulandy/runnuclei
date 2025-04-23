#!/bin/bash

# --- Cek apakah nuclei tersedia ---
if ! command -v nuclei &> /dev/null; then
    echo "[ERROR] Nuclei tidak ditemukan! Pastikan nuclei sudah di-install dan masuk PATH."
    exit 1
fi

# --- Template Options ---
TEMPLATE_BASE="/root/.local/nuclei-templates"
declare -A TEMPLATE_OPTIONS=(
    ["1"]="$TEMPLATE_BASE"
    ["2"]="$TEMPLATE_BASE/http/cves"
    ["3"]="$TEMPLATE_BASE/dast"
    ["4"]="$TEMPLATE_BASE/network"
)

# --- Output Directory ---
OUTPUT_DIR="hasil"
if [ -d "$OUTPUT_DIR" ]; then
    echo "[*] Direktori output '$OUTPUT_DIR' sudah ada, hasil akan ditimpa jika nama file sama."
else
    mkdir -p "$OUTPUT_DIR" || { echo "[ERROR] Gagal membuat direktori output '$OUTPUT_DIR'."; exit 1; }
fi

# --- Pilih Template ---
echo
echo "Pilih template scan:"
echo "1) Semua template"
echo "2) HTTP CVE (default)"
echo "3) DAST"
echo "4) Network"
read -p "Masukkan pilihan (default: 2): " template_choice
TEMPLATE_DIR="${TEMPLATE_OPTIONS[$template_choice]:-${TEMPLATE_OPTIONS[2]}}"

if [ ! -d "$TEMPLATE_DIR" ]; then
    echo "[ERROR] Direktori template '$TEMPLATE_DIR' tidak ditemukan!"
    exit 1
fi

echo "[*] Template yang digunakan: $TEMPLATE_DIR"

# --- Pilih Mode Target ---
echo
echo "Pilih mode scan:"
echo "1) Satu target"
echo "2) Banyak target dari file"
read mode

# --- Fungsi Normalisasi URL ---
normalize_url() {
    url="$1"
    if [[ "$url" =~ ^https?:// ]]; then
        echo "$url"
    else
        echo "http://$url"
    fi
}

if [[ "$mode" == "1" ]]; then
    echo "Masukkan URL target (contoh: example.com atau https://example.com):"
    read target_url
    if [[ -z "$target_url" ]]; then
        echo "[ERROR] URL tidak boleh kosong!"
        exit 1
    fi
    target_url=$(normalize_url "$target_url")
    hostname=$(echo "$target_url" | awk -F[/:] '{print $4}')
    output_file="${OUTPUT_DIR}/${hostname}.txt"

    echo "[+] Menjalankan Nuclei pada $target_url ..."
    nuclei -ss host-spray -es info -t "$TEMPLATE_DIR" -u "$target_url" -o "$output_file"

    echo "[+] Hasil disimpan di: $output_file"

elif [[ "$mode" == "2" ]]; then
    echo "Masukkan path file target (contoh: targets.txt):"
    read target_file
    if [[ ! -f "$target_file" ]]; then
        echo "[ERROR] File '$target_file' tidak ditemukan!"
        exit 1
    fi

    if [[ ! -s "$target_file" ]]; then
        echo "[ERROR] File '$target_file' kosong!"
        exit 1
    fi

    output_file="${OUTPUT_DIR}/results.txt"
    echo "[+] Menjalankan Nuclei untuk banyak target..."

    # Gunakan opsi -list untuk memproses banyak URL
    nuclei -ss host-spray -es info -t "$TEMPLATE_DIR" -list "$target_file" -o "$output_file"

    echo "[+] Hasil disimpan di: $output_file"

else
    echo "[ERROR] Pilihan tidak valid. Silakan pilih 1 atau 2."
    exit 1
fi

