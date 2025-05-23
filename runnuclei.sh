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
echo "1) Semua template (Termasuk scan file js)"
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

# --- Fungsi Flag Scan Berdasarkan Template ---
get_scan_flags() {
    if [[ "$template_choice" == "2" || -z "$template_choice" ]]; then
        echo "-es info"
    else
        read -p "Gunakan mode auto-scan (-as)? [Y/n]: " as_choice
        if [[ "$as_choice" =~ ^[Nn]$ ]]; then
            echo "-es info"
        else
            echo "-as"
        fi
    fi
}

# --- Pilih Mode Target ---
echo
echo "Pilih mode scan:"
echo "1) Satu target"
echo "2) Banyak target dari file"
echo "3) Scan Local File (JS static)"
read -p "Masukkan pilihan: " mode

# --- Fungsi Normalisasi URL ---
normalize_url() {
    url="$1"
    if [[ "$url" =~ ^https?:// ]]; then
        echo "$url"
    else
        echo "http://$url"
    fi
}

# --- Eksekusi berdasarkan mode ---
if [[ "$mode" == "1" ]]; then
    read -p "Masukkan URL target (contoh: example.com atau https://example.com): " target_url
    if [[ -z "$target_url" ]]; then
        echo "[ERROR] URL tidak boleh kosong!"
        exit 1
    fi
    target_url=$(normalize_url "$target_url")
    hostname=$(echo "$target_url" | awk -F[/:] '{print $4}')
    output_file="${OUTPUT_DIR}/${hostname}.txt"

    flags=$(get_scan_flags)

    echo "[+] Menjalankan Nuclei pada $target_url ..."
    nuclei -ni -ss host-spray $flags -t "$TEMPLATE_DIR" -u "$target_url" -o "$output_file" \
        -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

    echo "[+] Hasil disimpan di: $output_file"

elif [[ "$mode" == "2" ]]; then
    read -p "Masukkan path file target (contoh: targets.txt): " target_file
    if [[ ! -f "$target_file" ]]; then
        echo "[ERROR] File '$target_file' tidak ditemukan!"
        exit 1
    fi
    if [[ ! -s "$target_file" ]]; then
        echo "[ERROR] File '$target_file' kosong!"
        exit 1
    fi

    flags=$(get_scan_flags)
    output_file="${OUTPUT_DIR}/results.txt"
    echo "[+] Menjalankan Nuclei untuk banyak target..."

    nuclei -ni -ss host-spray $flags -t "$TEMPLATE_DIR" -list "$target_file" -o "$output_file" \
        -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

    echo "[+] Hasil disimpan di: $output_file"

elif [[ "$mode" == "3" ]]; then
    read -p "Masukkan target domain (contoh: https://example.com): " target
    domain=$(echo "$target" | sed 's|https\?://||' | sed 's|/.*||')

    rm -rf js-files/
    rm -f parsed_output.txt
    mkdir -p js-files

    echo "[*] Mencari semua link .js dari $target ..."
    js_links=$(curl -s -k -L "$target" | grep -oP '(?<=src=")[^"]+\.js' | sort -u)
    curl -s -k -L "$target" -o "js-files/index.html"

    if [[ -z "$js_links" ]]; then
        echo "[!] Tidak ditemukan file .js di halaman."
        exit 1
    fi

    for link in $js_links; do
        if [[ "$link" == http* ]]; then
            url="$link"
        else
            url="$target/${link#/}"
        fi
        filename=$(basename "$link")
        echo "[*] Downloading $url ..."
        wget -q "$url" -O "js-files/$filename"
    done

    echo "[*] Semua file JS sudah di-download ke folder js-files/"

    output_file="${OUTPUT_DIR}/${domain}-results.txt"
    echo "[*] Mulai scanning semua file dengan nuclei templates..."

    nuclei -ni -nh -file -target js-files -t "$TEMPLATE_DIR" -o "$output_file"

    echo "[*] Selesai scanning! Hasil disimpan di: $output_file"

    parsed_output_file="parsed_output.txt"
    if [ ! -f "$output_file" ]; then
        echo "File $output_file tidak ditemukan!"
        exit 1
    fi

    echo "[*] Memproses file $output_file..."
    > "$parsed_output_file"
    grep -oP "https?://[^\s'\",)]+|/[^'\s),]+" js-files/index.html | sort -u >> "$parsed_output_file"

    while IFS= read -r line; do
        cleaned=$(echo "$line" | sed 's/[][]//g' | tr -d '"')
        IFS=',' read -ra parts <<< "$cleaned"
        for part in "${parts[@]}"; do
            trimmed=$(echo "$part" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            if [ -n "$trimmed" ]; then
                echo "$trimmed" >> "$parsed_output_file"
            fi
        done
    done < "$output_file"

    echo "[*] Parsing selesai! Hasil disimpan di: $parsed_output_file"

else
    echo "[ERROR] Pilihan tidak valid. Silakan pilih 1, 2, atau 3."
    exit 1
fi

