if [ $# -ne 2 ]; then
    echo "Usage: $0 <ip> <port>"
    exit 1
fi
ufw delete deny from $1 to any port $2